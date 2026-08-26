-- Atomically consume a verified enrollment challenge and register the device.
--
-- Ed25519 verification happens in the trusted Edge Function. This RPC is callable
-- only by service_role and provides the database transaction boundary that makes
-- challenge consumption single-use under concurrent completion attempts.

begin;

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
begin
    if p_challenge_sha256_hex !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid enrollment challenge digest' using errcode = '22023';
    end if;

    select c.*
      into challenge
      from public.device_enrollment_challenges as c
     where c.id = p_challenge_id
     for update;

    if not found then
        raise exception 'invalid enrollment challenge' using errcode = '22023';
    end if;
    if challenge.user_id <> p_user_id or challenge.device_id <> p_device_id then
        raise exception 'enrollment challenge context mismatch' using errcode = '22023';
    end if;
    if challenge.consumed_at is not null then
        raise exception 'enrollment challenge already consumed' using errcode = '22023';
    end if;
    if challenge.expires_at <= now() then
        raise exception 'enrollment challenge expired' using errcode = '22023';
    end if;
    if encode(challenge.challenge_sha256, 'hex') <> lower(p_challenge_sha256_hex) then
        raise exception 'enrollment challenge digest mismatch' using errcode = '22023';
    end if;

    select d.*
      into device
      from public.devices as d
     where d.device_id = p_device_id
     for update;

    if found then
        if device.revoked_at is not null then
            raise exception 'device is revoked' using errcode = '22023';
        end if;
        if device.owner_user_id <> p_user_id then
            raise exception 'device belongs to another user' using errcode = '42501';
        end if;
        if device.public_key <> p_public_key then
            raise exception 'device public key mismatch' using errcode = '22023';
        end if;
        if device.kind <> p_kind then
            raise exception 'device kind mismatch' using errcode = '22023';
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
) is 'Service-role-only transaction boundary for a device enrollment whose Ed25519 proof was already verified by trusted server code.';

commit;
