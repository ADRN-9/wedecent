-- Replace direct device_access writes with authenticated, serialized RPCs.
--
-- Lock order is organization -> device -> actor membership -> device_access.
-- The helper derives the actor only from auth.uid(); callers cannot supply it.
-- Existing device-owner authority remains independent of organization membership.

begin;

drop function if exists wedecent_private.lock_device_access_authority(text);

create or replace function wedecent_private.lock_device_access_authority(
    p_device_id text,
    p_allow_revoked boolean
)
returns public.devices
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor_id uuid := auth.uid();
    initial_organization_id uuid;
    locked_organization_id uuid;
    actor_organization_role public.organization_role;
    device_row public.devices%rowtype;
begin
    if actor_id is null
       or (auth.jwt() ->> 'role') is distinct from 'authenticated'
       or coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) then
        raise exception 'authenticated identity required'
            using errcode = '42501';
    end if;

    if p_device_id is null
       or p_device_id !~ '^wd_[a-z2-7]{16}$' then
        raise exception 'invalid device_id'
            using errcode = '22023';
    end if;

    -- Read the association only to determine the first lock. It is revalidated
    -- after the device row lock, so a concurrent reassignment fails closed.
    select d.organization_id
      into initial_organization_id
      from public.devices as d
     where d.device_id = p_device_id;

    if not found then
        raise exception 'device not found'
            using errcode = '22023';
    end if;

    -- Lock 1: organization. FOR SHARE conflicts with deletion and updates.
    if initial_organization_id is not null then
        select o.id
          into locked_organization_id
          from public.organizations as o
         where o.id = initial_organization_id
         for share;

        if not found then
            raise exception 'device organization changed; retry authorization'
                using errcode = '40001';
        end if;
    end if;

    -- Lock 2: device. This serializes grant changes with revocation and
    -- organization reassignment.
    select d.*
      into device_row
      from public.devices as d
     where d.device_id = p_device_id
     for update;

    if not found then
        raise exception 'device changed during authorization; retry authorization'
            using errcode = '40001';
    end if;

    if device_row.organization_id is distinct from initial_organization_id then
        raise exception 'device organization changed; retry authorization'
            using errcode = '40001';
    end if;

    -- Only the explicit revoke RPC may manage stale grants on a revoked device.
    if p_allow_revoked is null then
        raise exception 'invalid device access operation'
            using errcode = '22023';
    end if;

    if device_row.revoked_at is not null and not p_allow_revoked then
        raise exception 'device is revoked'
            using errcode = '22023';
    end if;

    -- Lock 3: the caller's membership row, including member-role rows. A
    -- concurrent role downgrade or membership removal must finish before
    -- authorization is evaluated.
    if device_row.organization_id is not null then
        select m.role
          into actor_organization_role
          from public.organization_memberships as m
         where m.organization_id = device_row.organization_id
           and m.user_id = actor_id
         for share;
    end if;

    -- Preserve direct device-owner authority. Otherwise require a current
    -- owner/admin membership captured by the locked query above.
    if device_row.owner_user_id is distinct from actor_id
       and coalesce(
           actor_organization_role in ('owner', 'admin'),
           false
       ) is not true then
        raise exception 'device access grant is not authorized'
            using errcode = '42501';
    end if;

    return device_row;
end;
$$;

alter function wedecent_private.lock_device_access_authority(text, boolean)
    owner to postgres;

revoke all on function wedecent_private.lock_device_access_authority(text, boolean)
    from public, anon, authenticated, service_role;

create or replace function public.create_device_access_grant(
    p_device_id text,
    p_grantee_user_id uuid,
    p_permission public.device_permission,
    p_expires_at timestamptz
)
returns public.device_access
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor_id uuid := auth.uid();
    existing_grant public.device_access%rowtype;
    created_grant public.device_access%rowtype;
begin
    if actor_id is null
       or (auth.jwt() ->> 'role') is distinct from 'authenticated'
       or coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) then
        raise exception 'authenticated identity required'
            using errcode = '42501';
    end if;

    if p_grantee_user_id is null
       or (
            p_permission is distinct from 'terminal.connect'::public.device_permission
            and p_permission is distinct from 'mesh.forward'::public.device_permission
        ) then
        raise exception 'invalid device access grant parameters'
            using errcode = '22023';
    end if;

    perform wedecent_private.lock_device_access_authority(p_device_id, false);

    -- Lock 4: existing grant row. The device lock above also serializes
    -- concurrent inserts for this device before checking the unique key.
    select a.*
      into existing_grant
      from public.device_access as a
     where a.device_id = p_device_id
       and a.user_id = p_grantee_user_id
       and a.permission = p_permission
     for update;

    if found then
        raise exception 'device access grant already exists'
            using errcode = '23505';
    end if;

    -- PostgreSQL accepts timestamp infinities; grant expirations must be finite.
    if p_expires_at is not null and not pg_catalog.isfinite(p_expires_at) then
        raise exception 'grant expiration must be finite'
            using errcode = '22023';
    end if;

    -- Evaluate expiry after all authorization locks have been acquired.
    if p_expires_at is not null
       and p_expires_at <= pg_catalog.clock_timestamp() then
        raise exception 'grant expiration must be in the future'
            using errcode = '22023';
    end if;

    insert into public.device_access (
        device_id,
        user_id,
        permission,
        granted_by,
        expires_at
    )
    values (
        p_device_id,
        p_grantee_user_id,
        p_permission,
        actor_id,
        p_expires_at
    )
    returning * into created_grant;

    return created_grant;
end;
$$;

alter function public.create_device_access_grant(
    text, uuid, public.device_permission, timestamptz
) owner to postgres;

create or replace function public.update_device_access_grant_expiry(
    p_device_id text,
    p_grantee_user_id uuid,
    p_permission public.device_permission,
    p_expires_at timestamptz
)
returns public.device_access
language plpgsql
security definer
set search_path = ''
as $$
declare
    existing_grant public.device_access%rowtype;
    updated_grant public.device_access%rowtype;
    checked_at timestamptz;
begin
    if auth.uid() is null
       or (auth.jwt() ->> 'role') is distinct from 'authenticated'
       or coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) then
        raise exception 'authenticated identity required'
            using errcode = '42501';
    end if;

    if p_grantee_user_id is null
       or (
            p_permission is distinct from 'terminal.connect'::public.device_permission
            and p_permission is distinct from 'mesh.forward'::public.device_permission
        ) then
        raise exception 'invalid device access grant parameters'
            using errcode = '22023';
    end if;

    perform wedecent_private.lock_device_access_authority(p_device_id, false);

    -- Lock 4: the grant record. Its expiry is checked only after this lock.
    select a.*
      into existing_grant
      from public.device_access as a
     where a.device_id = p_device_id
       and a.user_id = p_grantee_user_id
       and a.permission = p_permission
     for update;

    if not found then
        raise exception 'device access grant does not exist'
            using errcode = 'P0002';
    end if;

    checked_at := pg_catalog.clock_timestamp();

    if existing_grant.expires_at is not null
       and existing_grant.expires_at <= checked_at then
        raise exception 'device access grant has expired'
            using errcode = '22023';
    end if;

    if p_expires_at is not null and not pg_catalog.isfinite(p_expires_at) then
        raise exception 'grant expiration must be finite'
            using errcode = '22023';
    end if;

    if p_expires_at is not null and p_expires_at <= checked_at then
        raise exception 'grant expiration must be in the future'
            using errcode = '22023';
    end if;

    -- NULL is the established permanent-grant representation. Keep it NULL
    -- unless an authorized caller explicitly supplies a finite future expiry.
    update public.device_access
       set expires_at = p_expires_at
     where device_id = p_device_id
       and user_id = p_grantee_user_id
       and permission = p_permission
     returning * into updated_grant;

    return updated_grant;
end;
$$;

alter function public.update_device_access_grant_expiry(
    text, uuid, public.device_permission, timestamptz
) owner to postgres;

create or replace function public.revoke_device_access_grant(
    p_device_id text,
    p_grantee_user_id uuid,
    p_permission public.device_permission
)
returns public.device_access
language plpgsql
security definer
set search_path = ''
as $$
declare
    existing_grant public.device_access%rowtype;
    revoked_grant public.device_access%rowtype;
begin
    if auth.uid() is null
       or (auth.jwt() ->> 'role') is distinct from 'authenticated'
       or coalesce((auth.jwt() ->> 'is_anonymous')::boolean, true) then
        raise exception 'authenticated identity required'
            using errcode = '42501';
    end if;

    if p_grantee_user_id is null
       or (
            p_permission is distinct from 'terminal.connect'::public.device_permission
            and p_permission is distinct from 'mesh.forward'::public.device_permission
        ) then
        raise exception 'invalid device access grant parameters'
            using errcode = '22023';
    end if;

    perform wedecent_private.lock_device_access_authority(p_device_id, true);

    -- Lock 4: the grant record. Expiry is deliberately re-read here; revoking
    -- an expired row is still allowed because revocation only removes authority.
    select a.*
      into existing_grant
      from public.device_access as a
     where a.device_id = p_device_id
       and a.user_id = p_grantee_user_id
       and a.permission = p_permission
     for update;

    if not found then
        raise exception 'device access grant does not exist'
            using errcode = 'P0002';
    end if;

    -- Expiry does not block revocation: this operation only removes authority.
    delete from public.device_access as a
     where a.device_id = p_device_id
       and a.user_id = p_grantee_user_id
       and a.permission = p_permission
     returning * into revoked_grant;

    return revoked_grant;
end;
$$;

alter function public.revoke_device_access_grant(
    text, uuid, public.device_permission
) owner to postgres;

revoke all on function public.create_device_access_grant(
    text, uuid, public.device_permission, timestamptz
) from public, anon, authenticated, service_role;
revoke all on function public.update_device_access_grant_expiry(
    text, uuid, public.device_permission, timestamptz
) from public, anon, authenticated, service_role;
revoke all on function public.revoke_device_access_grant(
    text, uuid, public.device_permission
) from public, anon, authenticated, service_role;

grant execute on function public.create_device_access_grant(
    text, uuid, public.device_permission, timestamptz
) to authenticated;
grant execute on function public.update_device_access_grant_expiry(
    text, uuid, public.device_permission, timestamptz
) to authenticated;
grant execute on function public.revoke_device_access_grant(
    text, uuid, public.device_permission
) to authenticated;

-- Remove table and column-level writes. service_role remains read-only for this
-- table: repository inspection found no trusted backend caller that mutates it
-- directly; existing Edge Functions call dedicated enrollment/connection RPCs.
revoke all on table public.device_access
    from public, anon, authenticated, service_role;
revoke insert (
    device_id, user_id, permission, granted_by, created_at, expires_at
), update (
    device_id, user_id, permission, granted_by, created_at, expires_at
), references (
    device_id, user_id, permission, granted_by, created_at, expires_at
) on table public.device_access
    from public, anon, authenticated, service_role;

grant select on table public.device_access to authenticated, service_role;

drop policy if exists device_access_insert_manager on public.device_access;
drop policy if exists device_access_update_manager on public.device_access;
drop policy if exists device_access_delete_manager on public.device_access;

comment on table public.device_access is
'Explicit per-user terminal grants. Authenticated writes use the create, expiry-update, and revoke RPCs; service_role has read-only table access.';

comment on function public.create_device_access_grant(
    text, uuid, public.device_permission, timestamptz
) is
'Creates an explicit terminal.connect or mesh.forward grant for the target user. The permissions are independent; actor and granted_by are derived from auth.uid().' ;

comment on function public.update_device_access_grant_expiry(
    text, uuid, public.device_permission, timestamptz
) is
'Updates an active grant expiry. NULL remains the permanent-grant representation; expired grants cannot be revived.';

comment on function public.revoke_device_access_grant(
    text, uuid, public.device_permission
) is
'Revokes an existing terminal.connect or mesh.forward grant. Current owners/admins may explicitly clean up grants on revoked devices; creation and expiry updates remain denied there.';

commit;
