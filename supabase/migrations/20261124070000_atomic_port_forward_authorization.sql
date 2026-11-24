-- Atomic, database-enforced multi-participant port-forward authorization.
-- The SQL transaction is the Supabase primary's authorization/replay linearization
-- point. It is not an atomic commit with independently operated replay witnesses.

begin;

alter table public.devices
    add column if not exists revocation_epoch bigint not null default 0,
    add constraint devices_revocation_epoch_nonnegative
        check (revocation_epoch >= 0);

create table public.port_forward_authorization_transactions (
    forwarding_id uuid primary key,
    jti text not null unique,
    authorization_sha256 bytea not null,
    permission public.device_permission not null,
    direction text not null,
    initiating_device_id text not null references public.devices(device_id),
    destination_device_id text not null references public.devices(device_id),
    router_device_id text references public.devices(device_id),
    initiator_account_id uuid not null references auth.users(id),
    destination_account_id uuid not null references auth.users(id),
    router_account_id uuid references auth.users(id),
    initiator_organization_id uuid references public.organizations(id),
    destination_organization_id uuid references public.organizations(id),
    router_organization_id uuid references public.organizations(id),
    initiator_revocation_epoch bigint not null,
    destination_revocation_epoch bigint not null,
    router_revocation_epoch bigint,
    route_authorization_id uuid references public.route_authorization_grants(id),
    route_authorization_jti text,
    issued_at timestamptz not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default pg_catalog.clock_timestamp(),
    constraint port_forward_transaction_jti
        check (pg_catalog.char_length(jti) = 22 and jti !~ '[^A-Za-z0-9_-]'),
    constraint port_forward_transaction_route_jti_unique
        unique (route_authorization_id),
    constraint port_forward_transaction_digest
        check (pg_catalog.octet_length(authorization_sha256) = 32),
    constraint port_forward_transaction_permission
        check (
            (direction = 'local' and permission = 'port_forward.local')
            or (direction = 'remote' and permission = 'port_forward.remote')
        ),
    constraint port_forward_transaction_devices
        check (
            initiating_device_id <> destination_device_id
            and (
                router_device_id is null
                or (
                    router_device_id <> initiating_device_id
                    and router_device_id <> destination_device_id
                )
            )
        ),
    constraint port_forward_transaction_router_binding
        check (
            (router_device_id is null
                and router_account_id is null
                and router_organization_id is null
                and router_revocation_epoch is null
                and route_authorization_id is null
                and route_authorization_jti is null)
            or
            (router_device_id is not null
                and router_account_id is not null
                and router_revocation_epoch is not null
                and route_authorization_id is not null
                and route_authorization_jti is not null)
        ),
    constraint port_forward_transaction_epochs
        check (
            initiator_revocation_epoch >= 0
            and destination_revocation_epoch >= 0
            and (router_revocation_epoch is null or router_revocation_epoch >= 0)
        ),
    constraint port_forward_transaction_lifetime
        check (
            expires_at > issued_at
            and expires_at <= issued_at + interval '120 seconds'
        )
);

create index port_forward_authorization_transactions_expiry_idx
    on public.port_forward_authorization_transactions (expires_at);

alter table public.port_forward_replay_entries
    add column if not exists forwarding_id uuid
        references public.port_forward_authorization_transactions(forwarding_id);

alter table public.port_forward_authorization_transactions enable row level security;
revoke all on public.port_forward_authorization_transactions
    from public, anon, authenticated, service_role;

-- Every change to a device's cryptographic owner, organization or revocation
-- state advances the same monotonic fence read by authorization consumption.
create or replace function wedecent_private.advance_device_revocation_epoch()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if new.owner_user_id is distinct from old.owner_user_id
       or new.organization_id is distinct from old.organization_id
       or new.revoked_at is distinct from old.revoked_at
       or new.public_key is distinct from old.public_key
       or new.kind is distinct from old.kind then
        new.revocation_epoch := old.revocation_epoch + 1;
    elsif new.revocation_epoch < old.revocation_epoch then
        raise exception 'device revocation epoch cannot decrease'
            using errcode = '22023';
    end if;
    return new;
end;
$$;

revoke all on function wedecent_private.advance_device_revocation_epoch()
    from public, anon, authenticated;

drop trigger if exists devices_advance_revocation_epoch on public.devices;
create trigger devices_advance_revocation_epoch
before update on public.devices
for each row
execute function wedecent_private.advance_device_revocation_epoch();

-- Membership mutations and authorization consumption share this lock order:
-- organization rows, membership rows, device_access rows, then device rows.
-- Mutation triggers update affected device epochs only after the membership or
-- access row is locked, so an authorization cannot commit against stale rights.
create or replace function wedecent_private.bump_membership_device_epochs()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    affected_org_ids uuid[];
    target_device_id text;
begin
    affected_org_ids := array_remove(
        array[
            case when tg_op <> 'INSERT' then old.organization_id else null end,
            case when tg_op <> 'DELETE' then new.organization_id else null end
        ],
        null
    );

    for target_device_id in
        select d.device_id
          from public.devices as d
         where d.organization_id = any(affected_org_ids)
         order by d.device_id
    loop
        update public.devices
           set revocation_epoch = revocation_epoch + 1
         where device_id = target_device_id;
    end loop;

    return null;
end;
$$;

revoke all on function wedecent_private.bump_membership_device_epochs()
    from public, anon, authenticated;

drop trigger if exists organization_memberships_bump_device_epochs
    on public.organization_memberships;
create trigger organization_memberships_bump_device_epochs
after insert or update or delete on public.organization_memberships
for each row
execute function wedecent_private.bump_membership_device_epochs();

create or replace function wedecent_private.bump_device_access_epoch()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    affected_device_ids text[];
    target_device_id text;
begin
    affected_device_ids := array_remove(
        array[
            case when tg_op <> 'INSERT' then old.device_id else null end,
            case when tg_op <> 'DELETE' then new.device_id else null end
        ],
        null
    );

    for target_device_id in
        select distinct ids.device_id
          from unnest(affected_device_ids) as ids(device_id)
         order by ids.device_idevice_id
    loop
        update public.devices
           set revocation_epoch = revocation_epoch + 1
         where device_id = target_device_id;
    end loop;

    return null;
end;
$$;

revoke all on function wedecent_private.bump_device_access_epoch()
    from public, anon, authenticated;

drop trigger if exists device_access_bump_device_epoch on public.device_access;
create trigger device_access_bump_device_epoch
after insert or update or delete on public.device_access
for each row
execute function wedecent_private.bump_device_access_epoch();

create or replace function public.consume_port_forward_authorization(
    p_device_id text,
    p_device_public_key text,
    p_forwarding_id uuid,
    p_direction text,
    p_initiating_device_id text,
    p_destination_device_id text,
    p_router_device_id text,
    p_route_authorization_id uuid,
    p_route_authorization_jti text,
    p_route_source_device_id text,
    p_route_destination_device_id text,
    p_route_first_transport text,
    p_route_second_transport text,
    p_route_first_cost bigint,
    p_route_second_cost bigint,
    p_jti text,
    p_issued_at timestamptz,
    p_expires_at timestamptz,
    p_authorization_sha256 bytea
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_permission public.device_permission;
    v_device_ids text[];
    v_org_ids uuid[];
    v_target_device_id text;
    v_pre_initiator public.devices%rowtype;
    v_pre_destination public.devices%rowtype;
    v_pre_router public.devices%rowtype;
    v_initiator public.devices%rowtype;
    v_destination public.devices%rowtype;
    v_router public.devices%rowtype;
    v_locked_device public.devices%rowtype;
    v_route_grant public.route_authorization_grants%rowtype;
    v_transaction public.port_forward_authorization_transactions%rowtype;
    v_membership_role public.organization_role;
    v_destination_authorized boolean := false;
    v_router_authorized boolean := false;
    v_rows integer;
    v_authority public.port_forward_replay_authority%rowtype;
    v_prior_entry public.port_forward_replay_entries%rowtype;
    v_duplicate_entry public.port_forward_replay_entries%rowtype;
    v_initial_hash bytea;
    v_expected_latest_hash bytea;
    v_next_generation bigint;
    v_next_hash bytea;
begin
    if p_device_id is null
       or p_device_id !~ '^wd_[a-z2-7]{16}
       or p_direction not in ('local', 'remote')
       or p_initiating_device_id is null
       or p_initiating_device_id !~ '^wd_[a-z2-7]{16}$'
       or p_destination_device_id is null
       or p_destination_device_id !~ '^wd_[a-z2-7]{16}$'
       or p_jti is null
       or p_jti !~ '^[A-Za-z0-9_-]{22}$'
       or p_issued_at is null
       or p_expires_at is null
       or p_authorization_sha256 is null
       or pg_catalog.octet_length(p_authorization_sha256) <> 32 then
        raise exception 'invalid port-forward authorization context'
            using errcode = '22023';
    end if;

    if p_initiating_device_id = p_destination_device_id
       or p_device_id not in (p_initiating_device_id, p_destination_device_id) then
        raise exception 'port-forward participant mismatch'
            using errcode = '42501';
    end if;

    if p_expires_at <= v_now
       or p_issued_at > v_now
       or p_expires_at <= p_issued_at
       or p_expires_at > p_issued_at + interval '120 seconds' then
        raise exception 'port-forward authorization is expired or invalid'
            using errcode = '22023';
    end if;

    v_permission := case p_direction
        when 'local' then 'port_forward.local'::public.device_permission
        else 'port_forward.remote'::public.device_permission
    end;

    if p_router_device_id is null then
        if p_route_authorization_id is not null
           or p_route_authorization_jti is not null
           or p_route_source_device_id is not null
           or p_route_destination_device_id is not null
           or p_route_first_transport is not null
           or p_route_second_transport is not null
           or p_route_first_cost is not null
           or p_route_second_cost is not null then
            raise exception 'direct route contains router authorization fields'
                using errcode = '22023';
        end if;
        v_device_ids := array[p_initiating_device_id, p_destination_device_id];
    else
        if p_router_device_id !~ '^wd_[a-z2-7]{16}$'
           or p_router_device_id in (p_initiating_device_id, p_destination_device_id)
           or p_route_authorization_id is null
           or p_route_authorization_jti is null
           or p_route_authorization_jti !~ '^[A-Za-z0-9_-]{22}$'
           or p_route_source_device_id is null
           or p_route_destination_device_id is null
           or p_route_first_transport not in ('lan', 'internet')
           or p_route_second_transport not in ('lan', 'internet')
           or p_route_first_cost is null or p_route_first_cost < 0 or p_route_first_cost > 1000000000
           or p_route_second_cost is null or p_route_second_cost < 0 or p_route_second_cost > 1000000000
           or (p_direction = 'local' and (
               p_route_source_device_id <> p_initiating_device_id
               or p_route_destination_device_id <> p_destination_device_id
           ))
           or (p_direction = 'remote' and (
               p_route_source_device_id <> p_destination_device_id
               or p_route_destination_device_id <> p_initiating_device_id
           )) then
            raise exception 'routed authorization binding is incomplete'
                using errcode = '22023';
        end if;
        v_device_ids := array[
            p_initiating_device_id,
            p_destination_device_id,
            p_router_device_id
        ];
    end if;

    -- Unlocked discovery is only used to determine lock targets. All fields are
    -- re-read under row locks and compared before authorization can proceed.
    select d.* into v_pre_initiator
      from public.devices as d
     where d.device_id = p_initiating_device_id;
    if not found then
        raise exception 'initiating device is not enrolled'
            using errcode = '42501';
    end if;

    select d.* into v_pre_destination
      from public.devices as d
     where d.device_id = p_destination_device_id;
    if not found then
        raise exception 'destination device is not enrolled'
            using errcode = '42501';
    end if;

    if p_router_device_id is not null then
        select d.* into v_pre_router
          from public.devices as d
         where d.device_id = p_router_device_id;
        if not found then
            raise exception 'router device is not enrolled'
                using errcode = '42501';
        end if;
    end if;

    if v_pre_initiator.revoked_at is not null
       or v_pre_destination.revoked_at is not null
       or (p_router_device_id is not null and v_pre_router.revoked_at is not null) then
        raise exception 'port-forward participant is revoked'
            using errcode = '42501';
    end if;

    if v_pre_initiator.kind not in ('client', 'hybrid')
       or v_pre_destination.kind not in ('agent', 'hybrid')
       or (p_router_device_id is not null and v_pre_router.kind not in ('agent', 'hybrid')) then
        raise exception 'port-forward participant kind is invalid'
            using errcode = '42501';
    end if;

    v_org_ids := array(
        select distinct org_id
          from unnest(array[
              v_pre_initiator.organization_id,
              v_pre_destination.organization_id,
              case when p_router_device_id is not null
                   then v_pre_router.organization_id else null end
          ]) as ids(org_id)
         where org_id is not null
         order by org_id
    );

    -- Lock organizations first (organization deletion cascades membership and
    -- device organization updates), then the subject's membership and access
    -- records, then participant devices in canonical device-ID order.
    perform o.id
      from public.organizations as o
     where o.id = any(v_org_ids)
     order by o.id
     for share;

    perform m.organization_id
      from public.organization_memberships as m
     where m.organization_id = any(v_org_ids)
       and m.user_id = v_pre_initiator.owner_user_id
     order by m.organization_id, m.user_id
     for share;

    perform a.device_id
      from public.device_access as a
     where a.device_id = any(v_device_ids)
       and a.user_id = v_pre_initiator.owner_user_id
     order by a.device_id, a.permission
     for share;

    if p_router_device_id is not null then
        select g.* into v_route_grant
          from public.route_authorization_grants as g
         where g.id = p_route_authorization_id
           and g.jti = p_route_authorization_jti
         for share;

        if not found
           or v_route_grant.revoked_at is not null
           or v_route_grant.expires_at < p_expires_at
           or v_route_grant.expires_at <= v_now
           or v_route_grant.user_id <> v_pre_initiator.owner_user_id
           or v_route_grant.source_device_id <> p_route_source_device_id
           or v_route_grant.destination_device_id <> p_route_destination_device_id
           or v_route_grant.router_device_id <> p_router_device_id
           or v_route_grant.permission <> 'mesh.forward'
           or v_route_grant.first_transport <> p_route_first_transport
           or v_route_grant.second_transport <> p_route_second_transport
           or v_route_grant.first_cost <> p_route_first_cost
           or v_route_grant.second_cost <> p_route_second_cost then
            raise exception 'router authorization is missing, revoked or mismatched'
                using errcode = '42501';
        end if;
    end if;

    for v_target_device_id in
        select ids.device_id
          from unnest(v_device_ids) as ids(device_id)
         order by ids.device_id
    loop
        select d.* into v_locked_device
          from public.devices as d
         where d.device_id = v_target_device_id
         for share;

        if not found then
            raise exception 'port-forward participant disappeared'
                using errcode = '42501';
        end if;

        if v_target_device_id = p_initiating_device_id then
            if row(v_locked_device.owner_user_id, v_locked_device.organization_id, v_locked_device.revocation_epoch, v_locked_device.revoked_at, v_locked_device.public_key, v_locked_device.kind)
               is distinct from
               row(v_pre_initiator.owner_user_id, v_pre_initiator.organization_id, v_pre_initiator.revocation_epoch, v_pre_initiator.revoked_at, v_pre_initiator.public_key, v_pre_initiator.kind) then
                raise exception 'initiating device authorization snapshot changed'
                    using errcode = '40001';
            end if;
            v_initiator := v_locked_device;
        elsif v_target_device_id = p_destination_device_id then
            if row(v_router.owner_user_id, v_router.organization_id, v_router.revocation_epoch, v_router.revoked_at, v_router.public_key, v_router.kind)
               is distinct from
               row(v_pre_destination.owner_user_id, v_pre_destination.organization_id, v_pre_destination.revocation_epoch, v_pre_destination.revoked_at, v_pre_destination.public_key, v_pre_destination.kind) then
                raise exception 'destination device authorization snapshot changed'
                    using errcode = '40001';
            end if;
            v_destination := v_locked_device;
        else
            if row(v_router.owner_user_id, v_router.organization_id, v_router.revocation_epoch, v_router.revoked_at, v_router.public_key, v_router.kind)
               is distinct from
               row(v_pre_router.owner_user_id, v_pre_router.organization_id, v_pre_router.revocation_epoch, v_pre_router.revoked_at, v_pre_router.public_key, v_pre_router.kind) then
                raise exception 'router device authorization snapshot changed'
                    using errcode = '40001';
            end if;
            v_router := v_locked_device;
        end if;
    end loop;

    if (p_device_id = v_initiator.device_id and v_initiator.public_key <> p_device_public_key)
       or (p_device_id = v_destination.device_id and v_destination.public_key <> p_device_public_key) then
        raise exception 'replay proof key no longer matches enrolled device identity'
            using errcode = '42501';
    end if;

    if v_initiator.revoked_at is not null
       or v_destination.revoked_at is not null
       or (p_router_device_id is not null and v_router.revoked_at is not null) then
        raise exception 'port-forward participant is revoked'
            using errcode = '42501';
    end if;

    if v_initiator.owner_user_id is null
       or v_initiator.owner_user_id <> v_pre_initiator.owner_user_id then
        raise exception 'initiating account identity mismatch'
            using errcode = '42501';
    end if;

    if v_initiator.organization_id is not null
       and not exists (
           select 1 from public.organization_memberships as m
            where m.organization_id = v_initiator.organization_id
              and m.user_id = v_initiator.owner_user_id
       ) then
        raise exception 'initiating organization membership is missing'
            using errcode = '42501';
    end if;

    v_destination_authorized := v_destination.owner_user_id = v_initiator.owner_user_id;

    if not v_destination_authorized and v_destination.organization_id is not null then
        select m.role into v_membership_role
          from public.organization_memberships as m
         where m.organization_id = v_destination.organization_id
           and m.user_id = v_initiator.owner_user_id;
        v_destination_authorized := found and v_membership_role in ('owner', 'admin');
    end if;

    if not v_destination_authorized then
        v_destination_authorized := exists (
            select 1
              from public.device_access as a
             where a.device_id = v_destination.device_id
               and a.user_id = v_initiator.owner_user_id
               and a.permission = v_permission
               and (a.expires_at is null or a.expires_at > v_now)
        );
    end if;

    if not v_destination_authorized then
        raise exception 'port-forward destination permission is not granted'
            using errcode = '42501';
    end if;

    if p_router_device_id is not null then
        v_router_authorized := v_router.owner_user_id = v_initiator.owner_user_id;

        if not v_router_authorized and v_router.organization_id is not null then
            select m.role into v_membership_role
              from public.organization_memberships as m
             where m.organization_id = v_router.organization_id
               and m.user_id = v_initiator.owner_user_id;
            v_router_authorized := found and v_membership_role in ('owner', 'admin');
        end if;

        if not v_router_authorized then
            v_router_authorized := exists (
                select 1
                  from public.device_access as a
                 where a.device_id = v_router.device_id
                   and a.user_id = v_initiator.owner_user_id
                   and a.permission = 'mesh.forward'
                   and (a.expires_at is null or a.expires_at > v_now)
            );
        end if;

        if not v_router_authorized then
            raise exception 'router mesh.forward permission is not granted'
                using errcode = '42501';
        end if;
    end if;

    -- The transaction row binds the exact signed capability digest and the
    -- current account, organization and revocation snapshots for all participants.
    insert into public.port_forward_authorization_transactions (
        forwarding_id, jti, authorization_sha256, permission, direction,
        initiating_device_id, destination_device_id, router_device_id,
        initiator_account_id, destination_account_id, router_account_id,
        initiator_organization_id, destination_organization_id, router_organization_id,
        initiator_revocation_epoch, destination_revocation_epoch, router_revocation_epoch,
        route_authorization_id, route_authorization_jti, issued_at, expires_at
    )
    values (
        p_forwarding_id, p_jti, p_authorization_sha256, v_permission, p_direction,
        v_initiator.device_id, v_destination.device_id, p_router_device_id,
        v_initiator.owner_user_id, v_destination.owner_user_id,
        case when p_router_device_id is not null then v_router.owner_user_id else null end,
        v_initiator.organization_id, v_destination.organization_id,
        case when p_router_device_id is not null then v_router.organization_id else null end,
        v_initiator.revocation_epoch, v_destination.revocation_epoch,
        case when p_router_device_id is not null then v_router.revocation_epoch else null end,
        p_route_authorization_id, p_route_authorization_jti, p_issued_at, p_expires_at
    )
    on conflict do nothing;

    get diagnostics v_rows = row_count;

    if v_rows = 0 then
        select t.* into v_transaction
          from public.port_forward_authorization_transactions as t
         where t.forwarding_id = p_forwarding_id
         for update;

        if not found then
            return pg_catalog.jsonb_build_object(
                'accepted', false,
                'reason', 'jti-conflict'
            );
        end if;

        if v_transaction.jti <> p_jti
           or v_transaction.authorization_sha256 <> p_authorization_sha256
           or v_transaction.permission <> v_permission
           or v_transaction.direction <> p_direction
           or v_transaction.initiating_device_id <> v_initiator.device_id
           or v_transaction.destination_device_id <> v_destination.device_id
           or v_transaction.router_device_id is distinct from p_router_device_id
           or v_transaction.initiator_account_id <> v_initiator.owner_user_id
           or v_transaction.destination_account_id <> v_destination.owner_user_id
           or v_transaction.router_account_id is distinct from
                case when p_router_device_id is not null then v_router.owner_user_id else null end
           or v_transaction.initiator_organization_id is distinct from v_initiator.organization_id
           or v_transaction.destination_organization_id is distinct from v_destination.organization_id
           or v_transaction.router_organization_id is distinct from
                case when p_router_device_id is not null then v_router.organization_id else null end
           or v_transaction.initiator_revocation_epoch <> v_initiator.revocation_epoch
           or v_transaction.destination_revocation_epoch <> v_destination.revocation_epoch
           or v_transaction.router_revocation_epoch is distinct from
                case when p_router_device_id is not null then v_router.revocation_epoch else null end
           or v_transaction.route_authorization_id is distinct from p_route_authorization_id
           or v_transaction.route_authorization_jti is distinct from p_route_authorization_jti
           or v_transaction.issued_at <> p_issued_at
           or v_transaction.expires_at <> p_expires_at then
            return pg_catalog.jsonb_build_object(
                'accepted', false,
                'reason', 'idempotency-conflict'
            );
        end if;
    end if;

    -- Replay state remains per endpoint device. The shared forwarding transaction
    -- makes the participant snapshot identical when both endpoints consume it.
    v_initial_hash := extensions.digest(
        pg_catalog.convert_to(
            'wedecent-port-forward-replay-authority-v1'
            || E'\n' || p_device_id || E'\n0\n',
            'UTF8'
        ),
        'sha256'
    );

    insert into public.port_forward_replay_authority (
        device_id, generation, state_hash
    )
    values (p_device_id, 0, v_initial_hash)
    on conflict (device_id) do nothing;

    select a.* into v_authority
      from public.port_forward_replay_authority as a
     where a.device_id = p_device_id
     for update;

    if not found then
        raise exception 'port-forward replay authority state is unavailable'
            using errcode = '55000';
    end if;

    if exists (
        select 1 from public.port_forward_replay_entries as e
         where e.device_id = p_device_id
           and e.generation > v_authority.generation
    ) then
        raise exception 'port-forward replay authority state integrity mismatch'
            using errcode = '55000';
    end if;

    if v_authority.generation = 0 then
        if v_authority.state_hash <> v_initial_hash
           or exists (
               select 1 from public.port_forward_replay_entries as e
                where e.device_id = p_device_id
           ) then
            raise exception 'port-forward replay authority state integrity mismatch'
                using errcode = '55000';
        end if;
    else
        select e.* into v_prior_entry
          from public.port_forward_replay_entries as e
         where e.device_id = p_device_id
           and e.generation = v_authority.generation;

        if not found then
            raise exception 'port-forward replay authority state integrity mismatch'
                using errcode = '55000';
        end if;

        v_expected_latest_hash := extensions.digest(
            v_prior_entry.previous_state_hash
            || pg_catalog.int8send(v_prior_entry.generation)
            || pg_catalog.convert_to(v_prior_entry.jti, 'UTF8')
            || v_prior_entry.authorization_sha256,
            'sha256'
        );

        if v_prior_entry.state_hash <> v_authority.state_hash
           or v_prior_entry.state_hash <> v_expected_latest_hash then
            raise exception 'port-forward replay authority state integrity mismatch'
                using errcode = '55000';
        end if;

        if v_authority.generation = 1 then
            if v_prior_entry.previous_state_hash <> v_initial_hash then
                raise exception 'port-forward replay authority chain mismatch'
                    using errcode = '55000';
            end if;
        else
            select e.* into v_duplicate_entry
              from public.port_forward_replay_entries as e
             where e.device_id = p_device_id
               and e.generation = v_authority.generation - 1;

            if not found
               or v_prior_entry.previous_state_hash <> v_duplicate_entry.state_hash then
                raise exception 'port-forward replay authority chain mismatch'
                    using errcode = '55000';
            end if;
        end if;
    end if;

    select e.* into v_duplicate_entry
      from public.port_forward_replay_entries as e
     where e.device_id = p_device_id
       and e.jti = p_jti;

    if found then
        if v_duplicate_entry.forwarding_id = p_forwarding_id
           and v_duplicate_entry.authorization_sha256 = p_authorization_sha256 then
            return pg_catalog.jsonb_build_object(
                'accepted', true,
                'replayed', true,
                'generation', v_authority.generation::text,
                'state_hash', pg_catalog.encode(v_authority.state_hash, 'hex')
            );
        end if;

        return pg_catalog.jsonb_build_object(
            'accepted', false,
            'reason', case
                when v_duplicate_entry.authorization_sha256 = p_authorization_sha256
                    then 'replay'
                else 'authorization-conflict'
            end,
            'generation', v_authority.generation::text,
            'state_hash', pg_catalog.encode(v_authority.state_hash, 'hex')
        );
    end if;

    if v_authority.generation = 9223372036854775807 then
        raise exception 'port-forward replay authority generation exhausted'
            using errcode = '55000';
    end if;

    v_next_generation := v_authority.generation + 1;
    v_next_hash := extensions.digest(
        v_authority.state_hash
        || pg_catalog.int8send(v_next_generation)
        || pg_catalog.convert_to(p_jti, 'UTF8')
        || p_authorization_sha256,
        'sha256'
    );

    insert into public.port_forward_replay_entries (
        device_id, jti, generation, authorization_sha256,
        previous_state_hash, state_hash, expires_at, forwarding_id
    )
    values (
        p_device_id, p_jti, v_next_generation, p_authorization_sha256,
        v_authority.state_hash, v_next_hash, p_expires_at, p_forwarding_id
    );

    update public.port_forward_replay_authority
       set generation = v_next_generation,
           state_hash = v_next_hash,
           updated_at = pg_catalog.clock_timestamp()
     where device_id = p_device_id;

    return pg_catalog.jsonb_build_object(
        'accepted', true,
        'replayed', false,
        'generation', v_next_generation::text,
        'state_hash', pg_catalog.encode(v_next_hash, 'hex')
    );
end;
$$;

revoke all on function public.consume_port_forward_authorization(
    text, text, uuid, text, text, text, text, uuid, text, text, text,
    text, text, text, bigint, bigint, text, timestamptz, timestamptz, bytea
) from public, anon, authenticated;
grant execute on function public.consume_port_forward_authorization(
    text, text, uuid, text, text, text, text, uuid, text, text, text,
    text, text, text, bigint, bigint, text, timestamptz, timestamptz, bytea
) to service_role;

comment on column public.devices.revocation_epoch is
    'Monotonic authorization fence advanced by device revocation/identity changes and organization membership or device-access mutations.';
comment on table public.port_forward_authorization_transactions is
    'Immutable idempotency record binding one signed forwarding capability to authoritative account, organization, participant and revocation snapshots.';
comment on function public.consume_port_forward_authorization(
    text, text, uuid, text, text, text, text, uuid, text, text, text,
    text, text, text, bigint, bigint, text, timestamptz, timestamptz, bytea
) is
    'Atomically validates initiator, destination, optional router, organization membership, distinct port-forward and mesh.forward permissions, route grant, revocation epochs, idempotency and per-device JTI replay. Linearization point is transaction commit.';

commit;
