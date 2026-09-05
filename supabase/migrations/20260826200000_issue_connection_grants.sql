-- Authorize and record short-lived terminal connection grants.
--
-- This RPC is service-role-only. It re-evaluates account/device authorization at
-- issuance time and returns an audit row that the Edge Function signs as a JWT.

begin;

create or replace function public.issue_connection_grant(
    p_user_id uuid,
    p_client_device_id text,
    p_target_device_id text
)
returns public.connection_grants
language plpgsql
security definer
set search_path = ''
as $$
declare
    client public.devices%rowtype;
    target public.devices%rowtype;
    grant_row public.connection_grants%rowtype;
    authorized boolean := false;
begin
    if p_user_id is null then
        raise exception 'user is required' using errcode = '22023';
    end if;
    if p_client_device_id is null or p_target_device_id is null then
        raise exception 'client and target devices are required' using errcode = '22023';
    end if;
    if p_client_device_id = p_target_device_id then
        raise exception 'client and target devices must differ' using errcode = '22023';
    end if;

    select d.*
      into client
      from public.devices as d
     where d.device_id = p_client_device_id
     for share;

    if not found then
        raise exception 'client device is not enrolled' using errcode = '22023';
    end if;
    if client.revoked_at is not null then
        raise exception 'client device is revoked' using errcode = '22023';
    end if;
    if client.owner_user_id <> p_user_id then
        raise exception 'client device belongs to another user' using errcode = '42501';
    end if;
    if client.kind not in ('client', 'hybrid') then
        raise exception 'client device kind cannot initiate terminal sessions' using errcode = '22023';
    end if;

    select d.*
      into target
      from public.devices as d
     where d.device_id = p_target_device_id
     for share;

    if not found then
        raise exception 'target device is not enrolled' using errcode = '22023';
    end if;
    if target.revoked_at is not null then
        raise exception 'target device is revoked' using errcode = '22023';
    end if;
    if target.kind not in ('agent', 'hybrid') then
        raise exception 'target device kind cannot accept terminal sessions' using errcode = '22023';
    end if;

    authorized := target.owner_user_id = p_user_id;

    if not authorized and target.organization_id is not null then
        authorized := exists (
            select 1
              from public.organization_memberships as m
             where m.organization_id = target.organization_id
               and m.user_id = p_user_id
               and m.role in ('owner', 'admin')
        );
    end if;

    if not authorized then
        authorized := exists (
            select 1
              from public.device_access as a
             where a.device_id = target.device_id
               and a.user_id = p_user_id
               and a.permission = 'terminal.connect'
               and (a.expires_at is null or a.expires_at > now())
        );
    end if;

    if not authorized then
        raise exception 'terminal connection is not authorized' using errcode = '42501';
    end if;

    insert into public.connection_grants (
        user_id,
        organization_id,
        client_device_id,
        target_device_id,
        permission,
        expires_at
    )
    values (
        p_user_id,
        target.organization_id,
        client.device_id,
        target.device_id,
        'terminal.connect',
        now() + interval '90 seconds'
    )
    returning * into grant_row;

    return grant_row;
end;
$$;

revoke all on function public.issue_connection_grant(uuid, text, text)
from public, anon, authenticated;

grant execute on function public.issue_connection_grant(uuid, text, text)
to service_role;

comment on function public.issue_connection_grant(uuid, text, text) is
'Service-role-only authorization boundary for short-lived terminal grants. The caller must sign the returned grant claims before presenting them to the relay.';

commit;
