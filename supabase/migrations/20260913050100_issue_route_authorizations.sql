-- Authorize and record short-lived one-hop routing capabilities.
--
-- The browser/authenticated client cannot insert these rows or execute the RPC.
-- A trusted Edge Function authenticates the Supabase user, invokes this
-- service-role-only authorization boundary, then signs the returned exact route
-- with the dedicated control-plane route-authorization Ed25519 key.

begin;

create table public.route_authorization_grants (
    id uuid primary key default gen_random_uuid(),
    jti text not null unique,
    user_id uuid not null
        references auth.users(id) on delete cascade,
    organization_id uuid
        references public.organizations(id) on delete set null,
    source_device_id text not null
        references public.devices(device_id) on delete cascade,
    router_device_id text not null
        references public.devices(device_id) on delete cascade,
    destination_device_id text not null
        references public.devices(device_id) on delete cascade,
    first_transport text not null,
    second_transport text not null,
    first_cost bigint not null,
    second_cost bigint not null,
    permission public.device_permission
        not null default 'mesh.forward',
    issued_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,

    constraint route_authorization_jti_format
        check (jti ~ '^[A-Za-z0-9_-]{22}$'),

    constraint route_authorization_distinct_devices
        check (
            source_device_id <> router_device_id
            and source_device_id <> destination_device_id
            and router_device_id <> destination_device_id
        ),

    constraint route_authorization_transport_profile
        check (
            first_transport in ('lan', 'internet')
            and second_transport in ('lan', 'internet')
        ),

    constraint route_authorization_cost_bounds
        check (
            first_cost between 0 and 1000000000
            and second_cost between 0 and 1000000000
        ),

    constraint route_authorization_permission
        check (permission = 'mesh.forward'),

    constraint route_authorization_short_lived
        check (
            expires_at > issued_at
            and expires_at <=
                issued_at + interval '120 seconds'
        )
);

create index route_authorization_user_issued_idx
    on public.route_authorization_grants
        (user_id, issued_at desc);

create index route_authorization_router_active_idx
    on public.route_authorization_grants
        (router_device_id, expires_at)
    where revoked_at is null;

alter table public.route_authorization_grants
enable row level security;

revoke all
on public.route_authorization_grants
from anon, authenticated;

create or replace function public.issue_route_authorization(
    p_user_id uuid,
    p_jti text,
    p_source_device_id text,
    p_router_device_id text,
    p_destination_device_id text,
    p_first_transport text,
    p_second_transport text,
    p_first_cost bigint,
    p_second_cost bigint
)
returns public.route_authorization_grants
language plpgsql
security definer
set search_path = ''
as $$
declare
    source_device public.devices%rowtype;
    router_device public.devices%rowtype;
    destination_device public.devices%rowtype;
    grant_row public.route_authorization_grants%rowtype;
    router_authorized boolean := false;
    destination_authorized boolean := false;
    issued timestamptz;
    expires timestamptz;
begin
    if p_user_id is null then
        raise exception 'user is required'
            using errcode = '22023';
    end if;

    if p_jti is null
       or p_jti !~ '^[A-Za-z0-9_-]{22}$' then
        raise exception 'invalid route authorization jti'
            using errcode = '22023';
    end if;

    if p_source_device_id is null
       or p_router_device_id is null
       or p_destination_device_id is null then
        raise exception 'route devices are required'
            using errcode = '22023';
    end if;

    if p_source_device_id = p_router_device_id
       or p_source_device_id = p_destination_device_id
       or p_router_device_id = p_destination_device_id then
        raise exception 'route devices must differ'
            using errcode = '22023';
    end if;

    if p_first_transport is null
       or p_second_transport is null
       or p_first_transport not in ('lan', 'internet')
       or p_second_transport not in ('lan', 'internet') then
        raise exception 'unsupported routing transport'
            using errcode = '22023';
    end if;

    if p_first_cost is null
       or p_second_cost is null
       or p_first_cost < 0
       or p_second_cost < 0
       or p_first_cost > 1000000000
       or p_second_cost > 1000000000 then
        raise exception 'invalid route cost'
            using errcode = '22023';
    end if;

    select d.*
      into source_device
      from public.devices as d
     where d.device_id = p_source_device_id
     for share;

    if not found then
        raise exception 'source device is not enrolled'
            using errcode = '22023';
    end if;

    if source_device.revoked_at is not null then
        raise exception 'source device is revoked'
            using errcode = '22023';
    end if;

    if source_device.owner_user_id <> p_user_id then
        raise exception 'source device belongs to another user'
            using errcode = '42501';
    end if;

    if source_device.kind not in ('client', 'hybrid') then
        raise exception 'source device cannot initiate routed sessions'
            using errcode = '22023';
    end if;

    select d.*
      into router_device
      from public.devices as d
     where d.device_id = p_router_device_id
     for share;

    if not found then
        raise exception 'router device is not enrolled'
            using errcode = '22023';
    end if;

    if router_device.revoked_at is not null then
        raise exception 'router device is revoked'
            using errcode = '22023';
    end if;

    if router_device.kind not in ('agent', 'hybrid') then
        raise exception 'router device cannot forward routed sessions'
            using errcode = '22023';
    end if;

    select d.*
      into destination_device
      from public.devices as d
     where d.device_id = p_destination_device_id
     for share;

    if not found then
        raise exception 'destination device is not enrolled'
            using errcode = '22023';
    end if;

    if destination_device.revoked_at is not null then
        raise exception 'destination device is revoked'
            using errcode = '22023';
    end if;

    if destination_device.kind not in ('agent', 'hybrid') then
        raise exception 'destination device cannot accept routed sessions'
            using errcode = '22023';
    end if;

    -- Router authorization is deliberately distinct from terminal access.
    router_authorized :=
        router_device.owner_user_id = p_user_id;

    if not router_authorized
       and router_device.organization_id is not null then
        router_authorized := exists (
            select 1
              from public.organization_memberships as m
             where m.organization_id =
                       router_device.organization_id
               and m.user_id = p_user_id
               and m.role in ('owner', 'admin')
        );
    end if;

    if not router_authorized then
        router_authorized := exists (
            select 1
              from public.device_access as a
             where a.device_id = router_device.device_id
               and a.user_id = p_user_id
               and a.permission = 'mesh.forward'
               and (
                   a.expires_at is null
                   or a.expires_at > now()
               )
        );
    end if;

    if not router_authorized then
        raise exception 'route forwarding is not authorized'
            using errcode = '42501';
    end if;

    -- Destination authorization preserves the existing terminal.connect
    -- boundary. Routing does not create terminal access.
    destination_authorized :=
        destination_device.owner_user_id = p_user_id;

    if not destination_authorized
       and destination_device.organization_id is not null then
        destination_authorized := exists (
            select 1
              from public.organization_memberships as m
             where m.organization_id =
                       destination_device.organization_id
               and m.user_id = p_user_id
               and m.role in ('owner', 'admin')
        );
    end if;

    if not destination_authorized then
        destination_authorized := exists (
            select 1
              from public.device_access as a
             where a.device_id =
                       destination_device.device_id
               and a.user_id = p_user_id
               and a.permission = 'terminal.connect'
               and (
                   a.expires_at is null
                   or a.expires_at > now()
               )
        );
    end if;

    if not destination_authorized then
        raise exception 'terminal destination is not authorized'
            using errcode = '42501';
    end if;

    -- Millisecond precision exactly matches the signed Go/JavaScript
    -- authorization profile.
    issued :=
        date_trunc('milliseconds', clock_timestamp());
    expires := issued + interval '60 seconds';

    insert into public.route_authorization_grants (
        jti,
        user_id,
        organization_id,
        source_device_id,
        router_device_id,
        destination_device_id,
        first_transport,
        second_transport,
        first_cost,
        second_cost,
        permission,
        issued_at,
        expires_at
    )
    values (
        p_jti,
        p_user_id,
        coalesce(
            destination_device.organization_id,
            router_device.organization_id
        ),
        source_device.device_id,
        router_device.device_id,
        destination_device.device_id,
        p_first_transport,
        p_second_transport,
        p_first_cost,
        p_second_cost,
        'mesh.forward',
        issued,
        expires
    )
    returning * into grant_row;

    return grant_row;
end;
$$;

revoke all
on function public.issue_route_authorization(
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    bigint,
    bigint
)
from public, anon, authenticated;

grant execute
on function public.issue_route_authorization(
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    bigint,
    bigint
)
to service_role;

comment on function public.issue_route_authorization(
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    bigint,
    bigint
) is
'Service-role-only boundary for short-lived signed mesh.forward capabilities. Routing permission and terminal destination permission are evaluated independently.';

commit;
