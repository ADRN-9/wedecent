-- Tighten tenant ownership checks at the database authorization boundary.
--
-- created_by is provenance, not a substitute for current organization membership.
-- Device enrollment checks both the source and destination organization while
-- holding membership row locks through the enrollment transaction.

begin;

drop policy if exists organizations_select_member
on public.organizations;

create policy organizations_select_member
on public.organizations
for select
to authenticated
using (
    (select wedecent_private.is_organization_member(id))
);

drop policy if exists organizations_update_manager
on public.organizations;

create policy organizations_update_manager
on public.organizations
for update
to authenticated
using (
    (select wedecent_private.can_manage_organization(id))
)
with check (
    (select wedecent_private.can_manage_organization(id))
);

drop policy if exists organizations_delete_owner
on public.organizations;

create policy organizations_delete_owner
on public.organizations
for delete
to authenticated
using (
    (select wedecent_private.is_organization_owner(id))
);

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
    device_exists boolean := false;
begin
    if p_user_id is null then
        raise exception 'enrollment user is required'
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

    -- Lock every relevant owner/admin membership in deterministic order.
    -- A concurrent role change or membership deletion must wait until this
    -- transaction commits; a stale preflight check cannot authorize enrollment.
    perform m.organization_id
      from public.organization_memberships as m
     where m.user_id = p_user_id
       and m.role in ('owner', 'admin')
       and (
           m.organization_id = p_organization_id
           or (
               device_exists
               and device.organization_id is not null
               and device.organization_id is distinct from p_organization_id
               and m.organization_id = device.organization_id
           )
       )
     order by m.organization_id
     for share;

    if p_organization_id is not null
       and not exists (
           select 1
             from public.organization_memberships as m
            where m.organization_id = p_organization_id
              and m.user_id = p_user_id
              and m.role in ('owner', 'admin')
       ) then
        raise exception 'target organization enrollment is not authorized'
            using errcode = '42501';
    end if;

    if device_exists
       and device.organization_id is not null
       and device.organization_id is distinct from p_organization_id
       and not exists (
           select 1
             from public.organization_memberships as m
            where m.organization_id = device.organization_id
              and m.user_id = p_user_id
              and m.role in ('owner', 'admin')
       ) then
        raise exception 'device organization reassignment is not authorized'
            using errcode = '42501';
    end if;

    if device_exists then
        if device.revoked_at is not null then
            raise exception 'device is revoked'
                using errcode = '22023';
        end if;

        if device.owner_user_id <> p_user_id then
            raise exception 'device belongs to another user'
                using errcode = '42501';
        end if;

        if device.public_key <> p_public_key then
            raise exception 'device public key mismatch'
                using errcode = '22023';
        end if;

        if device.kind <> p_kind then
            raise exception 'device kind mismatch'
                using errcode = '22023';
        end if;

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
'Service-role-only enrollment transaction. It locks and revalidates current and destination organization owner/admin memberships before changing organization ownership.';

commit;
