-- Tenant-scoped append-only security audit foundation.
--
-- Events are written by trusted database triggers in the same transaction as
-- enrollment, membership, device-ownership, and device-access mutations. The
-- event table deliberately has no FK to organizations or auth.users: deleting
-- either parent must not erase historical evidence.

begin;

create table public.organization_audit_events (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null,
    actor_user_id uuid,
    actor_kind text not null,
    event_type text not null,
    target_type text not null,
    target_id text not null,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default clock_timestamp(),
    constraint organization_audit_actor_kind
        check (actor_kind in ('user', 'service', 'system')),
    constraint organization_audit_actor_identity
        check ((actor_kind = 'user') = (actor_user_id is not null)),
    constraint organization_audit_event_type
        check (event_type in (
            'organization.membership_added',
            'organization.membership_role_changed',
            'organization.membership_removed',
            'device.enrolled',
            'device.owner_changed',
            'device.organization_changed',
            'device.revocation_changed',
            'device.deleted',
            'device_access.granted',
            'device_access.updated',
            'device_access.revoked'
        )),
    constraint organization_audit_target_type
        check (target_type in ('membership', 'device', 'device_access')),
    constraint organization_audit_target_id
        check (char_length(target_id) between 1 and 128),
    constraint organization_audit_metadata_object
        check (jsonb_typeof(metadata) = 'object'),
    constraint organization_audit_metadata_size
        check (pg_column_size(metadata) <= 2048),
    constraint organization_audit_metadata_allowlist
        check (
            metadata - array[
                'target_user_id',
                'membership_role',
                'previous_membership_role',
                'owner_user_id',
                'previous_owner_user_id',
                'organization_id',
                'previous_organization_id',
                'device_kind',
                'revoked',
                'previous_revoked',
                'permission',
                'expires_at'
            ]::text[] = '{}'::jsonb
        )
);

create index organization_audit_events_tenant_time_idx
    on public.organization_audit_events (organization_id, created_at desc, id desc);

alter table public.organization_audit_events enable row level security;

revoke all on public.organization_audit_events
    from public, anon, authenticated, service_role;
grant select on public.organization_audit_events to authenticated;

create policy organization_audit_events_select_managers
on public.organization_audit_events
for select
to authenticated
using (
    (select wedecent_private.can_manage_organization(organization_id))
);

comment on table public.organization_audit_events is
'Tenant-scoped security audit events. Application roles cannot insert, update, delete, or truncate rows; reads require current organization owner/admin membership.';

create or replace function wedecent_private.audit_actor_user_id()
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    actor_id uuid := auth.uid();
    trusted_actor text;
begin
    if actor_id is not null then
        return actor_id;
    end if;

    -- Only service-role database functions may supply this transaction-local
    -- context. Authenticated callers always use the verified JWT subject above.
    if auth.role() = 'service_role' then
        trusted_actor := nullif(
            current_setting('wedecent.audit_actor_user_id', true),
            ''
        );
        if trusted_actor is not null then
            if trusted_actor !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
                raise exception 'invalid trusted audit actor context'
                    using errcode = '22023';
            end if;
            return trusted_actor::uuid;
        end if;
    end if;

    return null;
end;
$$;

create or replace function wedecent_private.append_tenant_audit_event(
    p_organization_id uuid,
    p_event_type text,
    p_target_type text,
    p_target_id text,
    p_metadata jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor_id uuid;
    actor_kind text;
begin
    if p_organization_id is null then
        return;
    end if;

    actor_id := wedecent_private.audit_actor_user_id();
    actor_kind := case
        when actor_id is not null then 'user'
        when auth.role() = 'service_role' then 'service'
        else 'system'
    end;

    if auth.role() = 'authenticated' and actor_id is null then
        raise exception 'authenticated audit event requires a verified actor'
            using errcode = '42501';
    end if;

    insert into public.organization_audit_events (
        organization_id,
        actor_user_id,
        actor_kind,
        event_type,
        target_type,
        target_id,
        metadata
    )
    values (
        p_organization_id,
        actor_id,
        actor_kind,
        p_event_type,
        p_target_type,
        p_target_id,
        coalesce(p_metadata, '{}'::jsonb)
    );
end;
$$;

create or replace function wedecent_private.audit_organization_membership_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if tg_op = 'INSERT' then
        perform wedecent_private.append_tenant_audit_event(
            new.organization_id,
            'organization.membership_added',
            'membership',
            new.user_id::text,
            jsonb_build_object(
                'target_user_id', new.user_id,
                'membership_role', new.role::text
            )
        );
        return new;
    elsif tg_op = 'DELETE' then
        perform wedecent_private.append_tenant_audit_event(
            old.organization_id,
            'organization.membership_removed',
            'membership',
            old.user_id::text,
            jsonb_build_object(
                'target_user_id', old.user_id,
                'membership_role', old.role::text
            )
        );
        return old;
    end if;

    if new.organization_id is distinct from old.organization_id
       or new.user_id is distinct from old.user_id then
        perform wedecent_private.append_tenant_audit_event(
            old.organization_id,
            'organization.membership_removed',
            'membership',
            old.user_id::text,
            jsonb_build_object(
                'target_user_id', old.user_id,
                'membership_role', old.role::text
            )
        );
        perform wedecent_private.append_tenant_audit_event(
            new.organization_id,
            'organization.membership_added',
            'membership',
            new.user_id::text,
            jsonb_build_object(
                'target_user_id', new.user_id,
                'membership_role', new.role::text
            )
        );
    elsif new.role is distinct from old.role then
        perform wedecent_private.append_tenant_audit_event(
            new.organization_id,
            'organization.membership_role_changed',
            'membership',
            new.user_id::text,
            jsonb_build_object(
                'target_user_id', new.user_id,
                'membership_role', new.role::text,
                'previous_membership_role', old.role::text
            )
        );
    end if;

    return new;
end;
$$;

create or replace function wedecent_private.audit_device_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    metadata jsonb;
begin
    if tg_op = 'INSERT' then
        perform wedecent_private.append_tenant_audit_event(
            new.organization_id,
            'device.enrolled',
            'device',
            new.device_id,
            jsonb_build_object(
                'owner_user_id', new.owner_user_id,
                'organization_id', new.organization_id,
                'device_kind', new.kind::text
            )
        );
        return new;
    elsif tg_op = 'DELETE' then
        perform wedecent_private.append_tenant_audit_event(
            old.organization_id,
            'device.deleted',
            'device',
            old.device_id,
            jsonb_build_object(
                'owner_user_id', old.owner_user_id,
                'organization_id', old.organization_id,
                'device_kind', old.kind::text
            )
        );
        return old;
    end if;

    if new.owner_user_id is distinct from old.owner_user_id then
        metadata := jsonb_build_object(
            'owner_user_id', new.owner_user_id,
            'previous_owner_user_id', old.owner_user_id
        );
        perform wedecent_private.append_tenant_audit_event(
            old.organization_id,
            'device.owner_changed',
            'device',
            new.device_id,
            metadata
        );
        if new.organization_id is distinct from old.organization_id then
            perform wedecent_private.append_tenant_audit_event(
                new.organization_id,
                'device.owner_changed',
                'device',
                new.device_id,
                metadata
            );
        end if;
    end if;

    if new.organization_id is distinct from old.organization_id then
        metadata := jsonb_build_object(
            'organization_id', new.organization_id,
            'previous_organization_id', old.organization_id
        );
        perform wedecent_private.append_tenant_audit_event(
            old.organization_id,
            'device.organization_changed',
            'device',
            new.device_id,
            metadata
        );
        perform wedecent_private.append_tenant_audit_event(
            new.organization_id,
            'device.organization_changed',
            'device',
            new.device_id,
            metadata
        );
    end if;

    if new.revoked_at is distinct from old.revoked_at then
        perform wedecent_private.append_tenant_audit_event(
            coalesce(new.organization_id, old.organization_id),
            'device.revocation_changed',
            'device',
            new.device_id,
            jsonb_build_object(
                'revoked', new.revoked_at is not null,
                'previous_revoked', old.revoked_at is not null
            )
        );
    end if;

    return new;
end;
$$;

create or replace function wedecent_private.audit_device_access_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    device_id text;
    organization_id uuid;
    target_user_id uuid;
    permission text;
    expires_at timestamptz;
    event_type text;
begin
    if tg_op = 'DELETE' then
        device_id := old.device_id;
        target_user_id := old.user_id;
        permission := old.permission::text;
        expires_at := old.expires_at;
        event_type := 'device_access.revoked';
    elsif tg_op = 'INSERT' then
        device_id := new.device_id;
        target_user_id := new.user_id;
        permission := new.permission::text;
        expires_at := new.expires_at;
        event_type := 'device_access.granted';
    else
        device_id := new.device_id;
        target_user_id := new.user_id;
        permission := new.permission::text;
        expires_at := new.expires_at;
        event_type := 'device_access.updated';
        if new.device_id is not distinct from old.device_id
           and new.user_id is not distinct from old.user_id
           and new.permission is not distinct from old.permission
           and new.expires_at is not distinct from old.expires_at then
            return new;
        end if;
    end if;

    select d.organization_id
      into organization_id
      from public.devices as d
     where d.device_id = device_id;

    if organization_id is not null then
        perform wedecent_private.append_tenant_audit_event(
            organization_id,
            event_type,
            'device_access',
            device_id || ':' || target_user_id::text || ':' || permission,
            jsonb_build_object(
                'target_user_id', target_user_id,
                'permission', permission,
                'expires_at', expires_at
            )
        );
    end if;

    if tg_op = 'DELETE' then
        return old;
    end if;
    return new;
end;
$$;

create trigger organization_memberships_audit_event
after insert or update or delete on public.organization_memberships
for each row
execute function wedecent_private.audit_organization_membership_change();

create trigger devices_audit_event
after insert or update or delete on public.devices
for each row
execute function wedecent_private.audit_device_change();

create trigger device_access_audit_event
after insert or update or delete on public.device_access
for each row
execute function wedecent_private.audit_device_access_change();

create or replace function wedecent_private.reject_tenant_audit_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    raise exception 'tenant audit events are append-only'
        using errcode = '55000';
end;
$$;

create trigger organization_audit_events_no_update_or_delete
before update or delete on public.organization_audit_events
for each row
execute function wedecent_private.reject_tenant_audit_mutation();

revoke all on function wedecent_private.audit_actor_user_id()
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.append_tenant_audit_event(uuid, text, text, text, jsonb)
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.audit_organization_membership_change()
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.audit_device_change()
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.audit_device_access_change()
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.reject_tenant_audit_mutation()
    from public, anon, authenticated, service_role;

-- The enrollment Edge Function verifies the bearer token with auth.getUser(),
-- derives p_user_id from that verified user, and is the only caller of this
-- service-role-only RPC. The transaction-local context is accepted only for
-- service_role and is cleared before the RPC returns.
create or replace function public.complete_device_enrollment(
    p_challenge_id uuid,
    p_user_id uuid,
    p_device_id text,
    p_public_key text,
    p_kind public.device_kind,
    p_name text,
    p_organization_id uuid,
    p_challenge_sha256_hex text
)
returns public.devices
language plpgsql
security definer
set search_path = ''
as $$
declare
    challenge public.device_enrollment_challenges%rowtype;
    device public.devices%rowtype;
    membership_row record;
    target_membership_role public.organization_role;
    source_membership_role public.organization_role;
    target_membership_found boolean := false;
    source_membership_found boolean := false;
    device_exists boolean := false;
begin
    if p_challenge_id is null
       or p_user_id is null
       or p_device_id is null
       or p_public_key is null
       or p_kind is null
       or p_name is null
       or p_device_id !~ '^wd_[a-z2-7]{16}$'
       or p_public_key !~ '^[A-Za-z0-9_-]{43}$'
       or char_length(btrim(p_name)) not between 1 and 128 then
        raise exception 'invalid enrollment parameters'
            using errcode = '22023';
    end if;

    if p_challenge_sha256_hex is null
       or p_challenge_sha256_hex !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid enrollment challenge digest'
            using errcode = '22023';
    end if;

    select c.*
      into challenge
      from public.device_enrollment_challenges as c
     where c.id = p_challenge_id
     for update;

    if not found then
        raise exception 'invalid enrollment challenge'
            using errcode = '22023';
    end if;

    if challenge.user_id <> p_user_id
       or challenge.device_id <> p_device_id then
        raise exception 'enrollment challenge context mismatch'
            using errcode = '22023';
    end if;

    if challenge.consumed_at is not null then
        raise exception 'enrollment challenge already consumed'
            using errcode = '22023';
    end if;

    if challenge.expires_at <= now() then
        raise exception 'enrollment challenge expired'
            using errcode = '22023';
    end if;

    if encode(challenge.challenge_sha256, 'hex')
       <> lower(p_challenge_sha256_hex) then
        raise exception 'enrollment challenge digest mismatch'
            using errcode = '22023';
    end if;

    select d.*
      into device
      from public.devices as d
     where d.device_id = p_device_id
     for update;

    device_exists := found;

    if device_exists then
        if device.revoked_at is not null then
            raise exception 'device is revoked'
                using errcode = '22023';
        end if;

        if device.owner_user_id is distinct from p_user_id then
            raise exception 'device belongs to another user'
                using errcode = '42501';
        end if;

        if device.public_key is distinct from p_public_key then
            raise exception 'device public key mismatch'
                using errcode = '22023';
        end if;

        if device.kind is distinct from p_kind then
            raise exception 'device kind mismatch'
                using errcode = '22023';
        end if;
    end if;

    -- Lock and capture every relevant membership row in deterministic order.
    -- These locks serialize enrollment with concurrent membership revocation.
    for membership_row in
        select m.organization_id, m.role
          from public.organization_memberships as m
         where m.user_id = p_user_id
           and (
               (p_organization_id is not null and m.organization_id = p_organization_id)
               or (
                   device_exists
                   and device.organization_id is not null
                   and device.organization_id is distinct from p_organization_id
                   and m.organization_id = device.organization_id
               )
           )
         order by m.organization_id
         for share
    loop
        if p_organization_id is not null
           and membership_row.organization_id = p_organization_id then
            target_membership_role := membership_row.role;
            target_membership_found := true;
        end if;

        if device_exists
           and device.organization_id is not null
           and device.organization_id is distinct from p_organization_id
           and membership_row.organization_id = device.organization_id then
            source_membership_role := membership_row.role;
            source_membership_found := true;
        end if;
    end loop;

    if p_organization_id is not null
       and (
           not target_membership_found
           or target_membership_role not in ('owner', 'admin')
       ) then
        raise exception 'target organization enrollment is not authorized'
            using errcode = '42501';
    end if;

    if device_exists
       and device.organization_id is not null
       and device.organization_id is distinct from p_organization_id
       and (
           not source_membership_found
           or source_membership_role not in ('owner', 'admin')
       ) then
        raise exception 'device organization reassignment is not authorized'
            using errcode = '42501';
    end if;

    perform set_config('wedecent.audit_actor_user_id', p_user_id::text, true);

    if device_exists then
        update public.devices
           set name = p_name,
               organization_id = p_organization_id
         where device_id = p_device_id
         returning * into device;
    else
        insert into public.devices (
            device_id,
            public_key,
            kind,
            name,
            owner_user_id,
            organization_id
        )
        values (
            p_device_id,
            p_public_key,
            p_kind,
            p_name,
            p_user_id,
            p_organization_id
        )
        returning * into device;
    end if;

    update public.device_enrollment_challenges
       set consumed_at = now()
     where id = p_challenge_id;

    perform set_config('wedecent.audit_actor_user_id', '', true);

    return device;
end;
$$;

revoke all on function public.complete_device_enrollment(
    uuid, uuid, text, text, public.device_kind, text, uuid, text
) from public, anon, authenticated;

grant execute on function public.complete_device_enrollment(
    uuid, uuid, text, text, public.device_kind, text, uuid, text
) to service_role;

comment on function public.complete_device_enrollment(
    uuid, uuid, text, text, public.device_kind, text, uuid, text
) is
'Service-role-only enrollment transaction. The trusted Edge Function derives p_user_id from a verified bearer token; this RPC sets a transaction-local audit actor only after matching the locked single-use challenge and revalidating organization membership.';

commit;
