-- Atomic multi-participant checkpoint reservations and commits.
-- The existing port_forward_replay_authority row remains the only mutable
-- participant-head authority. Reservation and event tables are not head stores.

begin;

alter table public.port_forward_replay_authority
    add column checkpoint_head_generation bigint not null default 0,
    add column checkpoint_head_hash bytea not null default pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
    add constraint port_forward_checkpoint_generation_nonnegative
        check (checkpoint_head_generation >= 0),
    add constraint port_forward_checkpoint_hash_size
        check (pg_catalog.octet_length(checkpoint_head_hash) = 32);

create table public.checkpoint_operations (
    operation_id text primary key check (operation_id ~ '^[0-9a-f]{64}$'),
    action text not null check (action in ('finalize', 'revoke')),
    organization_id uuid not null references public.organizations(id) on delete restrict,
    actor_id uuid not null references auth.users(id) on delete restrict,
    request_sha256 bytea not null check (pg_catalog.octet_length(request_sha256) = 32),
    participant_sha256 bytea not null check (pg_catalog.octet_length(participant_sha256) = 32),
    fingerprint bytea not null check (pg_catalog.octet_length(fingerprint) = 32),
    created_at timestamptz not null default pg_catalog.clock_timestamp()
);

create table public.checkpoint_operation_participants (
    operation_id text not null references public.checkpoint_operations(operation_id) on delete restrict,
    device_id text not null references public.devices(device_id) on delete restrict,
    account_id uuid not null references auth.users(id) on delete restrict,
    organization_id uuid not null references public.organizations(id) on delete restrict,
    revocation_epoch bigint not null check (revocation_epoch >= 0),
    expected_generation bigint not null check (expected_generation >= 0),
    expected_hash bytea not null check (pg_catalog.octet_length(expected_hash) = 32),
    next_generation bigint not null check (next_generation > expected_generation),
    next_hash bytea not null check (pg_catalog.octet_length(next_hash) = 32),
    primary key (operation_id, device_id),
    unique (operation_id, next_generation, device_id)
);

create table public.checkpoint_operation_events (
    event_id bigint generated always as identity primary key,
    operation_id text not null references public.checkpoint_operations(operation_id) on delete restrict,
    event_type text not null check (event_type in (
        'reserved', 'reservation_expired', 'committed'
    )),
    event_payload jsonb not null,
    event_sha256 bytea not null check (pg_catalog.octet_length(event_sha256) = 32),
    created_at timestamptz not null default pg_catalog.clock_timestamp()
);

create unique index checkpoint_operation_one_commit
    on public.checkpoint_operation_events(operation_id)
    where event_type = 'committed';

create index checkpoint_operation_events_operation_idx
    on public.checkpoint_operation_events(operation_id, event_id);

-- This is a lease/coordination table only. It never stores participant heads.
create table public.checkpoint_active_reservations (
    device_id text primary key references public.devices(device_id) on delete restrict,
    operation_id text not null references public.checkpoint_operations(operation_id) on delete restrict,
    fingerprint bytea not null check (pg_catalog.octet_length(fingerprint) = 32),
    expires_at timestamptz not null,
    reserved_at timestamptz not null default pg_catalog.clock_timestamp(),
    unique (operation_id, device_id)
);

alter table public.checkpoint_operations enable row level security;
alter table public.checkpoint_operation_participants enable row level security;
alter table public.checkpoint_operation_events enable row level security;
alter table public.checkpoint_active_reservations enable row level security;

revoke all on public.checkpoint_operations,
    public.checkpoint_operation_participants,
    public.checkpoint_operation_events,
    public.checkpoint_active_reservations
    from public, anon, authenticated, service_role;

create or replace function wedecent_private.reject_checkpoint_ledger_mutation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    raise exception 'checkpoint operation evidence is append-only'
        using errcode = '55000';
end;
$$;

revoke all on function wedecent_private.reject_checkpoint_ledger_mutation()
    from public, anon, authenticated, service_role;

create trigger checkpoint_operations_immutable
before update or delete on public.checkpoint_operations
for each row execute function wedecent_private.reject_checkpoint_ledger_mutation();

create trigger checkpoint_operation_participants_immutable
before update or delete on public.checkpoint_operation_participants
for each row execute function wedecent_private.reject_checkpoint_ledger_mutation();

create trigger checkpoint_operation_events_append_only
before update or delete on public.checkpoint_operation_events
for each row execute function wedecent_private.reject_checkpoint_ledger_mutation();

create or replace function public.reserve_checkpoint_operation(
    p_operation_id text,
    p_action text,
    p_organization_id uuid,
    p_actor_id uuid,
    p_request_sha256 bytea,
    p_participants jsonb,
    p_lease_seconds integer default 60
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_participants jsonb;
    v_participant jsonb;
    v_authoritative jsonb := '[]'::jsonb;
    v_payload jsonb;
    v_fingerprint bytea;
    v_participant_sha256 bytea;
    v_initial_replay_hash bytea;
    v_event_encoding bytea;
    v_next_hash bytea;
    v_operation public.checkpoint_operations%rowtype;
    v_device public.devices%rowtype;
    v_authority public.port_forward_replay_authority%rowtype;
    v_actor_role public.organization_role;
    v_reservation public.checkpoint_active_reservations%rowtype;
    v_committed public.checkpoint_operation_events%rowtype;
    v_expired_operation text;
    v_expected_count integer;
    v_existing_count integer;
    v_active_count integer;
    v_new_operation boolean := false;
begin
    if p_operation_id is null or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_action is null or p_action not in ('finalize', 'revoke')
       or p_organization_id is null or p_actor_id is null
       or p_request_sha256 is null or pg_catalog.octet_length(p_request_sha256) <> 32
       or p_participants is null or pg_catalog.jsonb_typeof(p_participants) <> 'array'
       or pg_catalog.jsonb_array_length(p_participants) < 1
       or pg_catalog.jsonb_array_length(p_participants) > 32
       or p_lease_seconds is null or p_lease_seconds < 5 or p_lease_seconds > 120 then
        raise exception 'invalid checkpoint reservation request'
            using errcode = '22023';
    end if;

    v_participant_sha256 := wedecent_private.checkpoint_participant_vector_hash(p_participants);
    select pg_catalog.jsonb_agg(item.value order by item.value ->> 'device_id')
      into v_participants
      from pg_catalog.jsonb_array_elements(p_participants) as item(value);

    if exists (
        select 1
          from pg_catalog.jsonb_array_elements(v_participants) as item(value)
         where item.value ->> 'organization_id' <> p_organization_id::text
            or pg_catalog.jsonb_object_length(item.value) <> 7
            or not (item.value ?& array[
                'device_id', 'account_id', 'organization_id',
                'revocation_epoch', 'head_generation', 'head_hash'
            ])
    ) then
        raise exception 'checkpoint participants must share the operation organization and exact schema'
            using errcode = '22023';
    end if;

    v_expected_count := pg_catalog.jsonb_array_length(v_participants);
    v_payload := pg_catalog.jsonb_build_object(
        'version', 1,
        'operation_id', p_operation_id,
        'action', p_action,
        'organization_id', p_organization_id,
        'actor_id', p_actor_id,
        'request_sha256', pg_catalog.encode(p_request_sha256, 'hex'),
        'participant_sha256', pg_catalog.encode(v_participant_sha256, 'hex'),
        'participants', v_participants
    );
    v_fingerprint := extensions.digest(
        pg_catalog.convert_to(wedecent_private.canonical_jsonb(v_payload), 'UTF8'),
        'sha256'
    );

    -- This key matches record_checkpoint_finalization's operation lock.
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_operation_id, 0));

    insert into public.checkpoint_operations (
        operation_id, action, organization_id, actor_id,
        request_sha256, participant_sha256, fingerprint
    )
    values (
        p_operation_id, p_action, p_organization_id, p_actor_id,
        p_request_sha256, v_participant_sha256, v_fingerprint
    )
    on conflict (operation_id) do nothing;
    v_new_operation := found;

    select operation_row.*
      into v_operation
      from public.checkpoint_operations as operation_row
     where operation_row.operation_id = p_operation_id
     for update;

    if not found
       or v_operation.action <> p_action
       or v_operation.organization_id <> p_organization_id
       or v_operation.actor_id <> p_actor_id
       or v_operation.request_sha256 <> p_request_sha256
       or v_operation.participant_sha256 <> v_participant_sha256
       or v_operation.fingerprint <> v_fingerprint then
        raise exception 'checkpoint operation fingerprint conflict'
            using errcode = '23505';
    end if;

    select event_row.*
      into v_committed
      from public.checkpoint_operation_events as event_row
     where event_row.operation_id = p_operation_id
       and event_row.event_type = 'committed';

    if found then
        return v_committed.event_payload -> 'result';
    end if;

    perform organization_row.id
      from public.organizations as organization_row
     where organization_row.id = p_organization_id
     for share;
    if not found then
        raise exception 'checkpoint organization is unavailable'
            using errcode = '42501';
    end if;

    select membership.role
      into v_actor_role
      from public.organization_memberships as membership
     where membership.organization_id = p_organization_id
       and membership.user_id = p_actor_id
     for share;

    if not found
       or (p_action = 'revoke' and v_actor_role not in ('owner', 'admin')) then
        raise exception 'checkpoint actor is not authorized for this operation'
            using errcode = '42501';
    end if;

    perform membership.user_id
      from public.organization_memberships as membership
     where membership.organization_id = p_organization_id
       and membership.user_id in (
           select (item.value ->> 'account_id')::uuid
             from pg_catalog.jsonb_array_elements(v_participants) as item(value)
       )
     order by membership.user_id
     for share;

    if (
        select pg_catalog.count(distinct membership.user_id)
          from public.organization_memberships as membership
         where membership.organization_id = p_organization_id
           and membership.user_id in (
               select (item.value ->> 'account_id')::uuid
                 from pg_catalog.jsonb_array_elements(v_participants) as item(value)
           )
    ) <> (
        select pg_catalog.count(distinct (item.value ->> 'account_id')::uuid)
          from pg_catalog.jsonb_array_elements(v_participants) as item(value)
    ) then
        raise exception 'checkpoint participant membership is unavailable'
            using errcode = '42501';
    end if;

    for v_device in
        select device_row.*
          from public.devices as device_row
          join pg_catalog.jsonb_array_elements(v_participants) as item(value)
            on item.value ->> 'device_id' = device_row.device_id
         order by device_row.device_id
         for share
    loop
        select item.value
          into v_participant
          from pg_catalog.jsonb_array_elements(v_participants) as item(value)
         where item.value ->> 'device_id' = v_device.device_id;

        if v_device.owner_user_id::text <> (v_participant ->> 'account_id')
           or v_device.organization_id <> p_organization_id
           or v_device.revocation_epoch <> (v_participant ->> 'revocation_epoch')::bigint
           or v_device.revoked_at is not null then
            raise exception 'checkpoint participant identity or revocation changed'
                using errcode = '42501';
        end if;
    end loop;

    if (
        select pg_catalog.count(*)
          from public.devices as device_row
         where device_row.device_id in (
             select item.value ->> 'device_id'
               from pg_catalog.jsonb_array_elements(v_participants) as item(value)
         )
    ) <> v_expected_count then
        raise exception 'checkpoint participant device is unavailable'
            using errcode = '42501';
    end if;

    -- Preserve the original replay-chain initialization and never rewrite its
    -- generation/hash. Checkpoint heads live on these same authority rows.
    for v_participant in
        select item.value
          from pg_catalog.jsonb_array_elements(v_participants) as item(value)
         order by item.value ->> 'device_id'
    loop
        v_initial_replay_hash := extensions.digest(
            pg_catalog.convert_to(
                'wedecent-port-forward-replay-authority-v1'
                || E'\n' || (v_participant ->> 'device_id') || E'\n0\n',
                'UTF8'
            ),
            'sha256'
        );

        insert into public.port_forward_replay_authority (
            device_id, generation, state_hash
        )
        values (v_participant ->> 'device_id', 0, v_initial_replay_hash)
        on conflict (device_id) do nothing;

        select authority_row.*
          into v_authority
          from public.port_forward_replay_authority as authority_row
         where authority_row.device_id = v_participant ->> 'device_id'
         for update;

        if not found then
            raise exception 'checkpoint participant authority is unavailable'
                using errcode = '55000';
        end if;

        select device_row.*
          into v_device
          from public.devices as device_row
         where device_row.device_id = v_participant ->> 'device_id';

        if not found then
            raise exception 'checkpoint participant device is unavailable'
                using errcode = '42501';
        end if;

        v_authoritative := v_authoritative || pg_catalog.jsonb_build_array(
            pg_catalog.jsonb_build_object(
                'device_id', v_participant ->> 'device_id',
                'account_id', v_device.owner_user_id,
                'organization_id', v_device.organization_id,
                'revocation_epoch', v_device.revocation_epoch,
                'head_generation', v_authority.checkpoint_head_generation,
                'head_hash', pg_catalog.encode(v_authority.checkpoint_head_hash, 'hex')
            )
        );

        if v_authority.checkpoint_head_generation <> (v_participant ->> 'head_generation')::bigint
           or v_authority.checkpoint_head_hash <> pg_catalog.decode(v_participant ->> 'head_hash', 'hex') then
            raise exception 'checkpoint participant head is stale'
                using errcode = '40001';
        end if;
    end loop;

    if not wedecent_private.checkpoint_v1_transition_matches(v_participants, v_authoritative) then
        raise exception 'checkpoint participant v1 transition is stale'
            using errcode = '40001';
    end if;

    if v_new_operation then
        for v_participant in
            select item.value
              from pg_catalog.jsonb_array_elements(v_participants) as item(value)
             order by item.value ->> 'device_id'
        loop
            select authority_row.*
              into v_authority
              from public.port_forward_replay_authority as authority_row
             where authority_row.device_id = v_participant ->> 'device_id';

            v_event_encoding := wedecent_private.checkpoint_event_v2_encoding_from_participants(
                p_action,
                'device',
                v_participant ->> 'device_id',
                v_participant ->> 'account_id',
                p_organization_id::text,
                p_operation_id,
                p_request_sha256,
                v_participants,
                v_authority.checkpoint_head_hash,
                v_authority.checkpoint_head_generation + 1,
                (v_participant ->> 'revocation_epoch')::bigint
            );
            v_next_hash := extensions.digest(v_event_encoding, 'sha256');

            insert into public.checkpoint_operation_participants (
                operation_id, device_id, account_id, organization_id,
                revocation_epoch, expected_generation, expected_hash,
                next_generation, next_hash
            )
            values (
                p_operation_id,
                v_participant ->> 'device_id',
                (v_participant ->> 'account_id')::uuid,
                p_organization_id,
                (v_participant ->> 'revocation_epoch')::bigint,
                v_authority.checkpoint_head_generation,
                v_authority.checkpoint_head_hash,
                v_authority.checkpoint_head_generation + 1,
                v_next_hash
            );
        end loop;
    else
        select pg_catalog.count(*)
          into v_existing_count
          from public.checkpoint_operation_participants
         where operation_id = p_operation_id;
        if v_existing_count <> v_expected_count then
            raise exception 'checkpoint operation participant ledger is incomplete'
                using errcode = '55000';
        end if;
    end if;

    select pg_catalog.count(*)
      into v_active_count
      from public.checkpoint_active_reservations
     where operation_id = p_operation_id
       and fingerprint = v_fingerprint
       and expires_at > v_now;

    if v_active_count = v_expected_count then
        return pg_catalog.jsonb_build_object(
            'status', 'reserved',
            'operation_id', p_operation_id,
            'fingerprint', pg_catalog.encode(v_fingerprint, 'hex'),
            'participant_sha256', pg_catalog.encode(v_participant_sha256, 'hex'),
            'expires_at', (
                select pg_catalog.min(expires_at)
                  from public.checkpoint_active_reservations
                 where operation_id = p_operation_id
            )
        );
    elsif v_active_count <> 0 then
        raise exception 'checkpoint reservation set is incomplete'
            using errcode = '55000';
    end if;

    for v_participant in
        select item.value
          from pg_catalog.jsonb_array_elements(v_participants) as item(value)
         order by item.value ->> 'device_id'
    loop
        select reservation_row.*
          into v_reservation
          from public.checkpoint_active_reservations as reservation_row
         where reservation_row.device_id = v_participant ->> 'device_id'
         for update;

        if found then
            if v_reservation.expires_at > v_now then
                raise exception 'checkpoint participant is reserved by another operation'
                    using errcode = '55P03';
            end if;

            v_expired_operation := v_reservation.operation_id;
            insert into public.checkpoint_operation_events (
                operation_id, event_type, event_payload, event_sha256
            )
            values (
                v_expired_operation,
                'reservation_expired',
                pg_catalog.jsonb_build_object(
                    'device_id', v_reservation.device_id,
                    'operation_id', v_expired_operation,
                    'expired_at', v_reservation.expires_at
                ),
                extensions.digest(
                    pg_catalog.convert_to(
                        wedecent_private.canonical_jsonb(pg_catalog.jsonb_build_object(
                            'device_id', v_reservation.device_id,
                            'operation_id', v_expired_operation,
                            'expired_at', v_reservation.expires_at
                        )),
                        'UTF8'
                    ),
                    'sha256'
                )
            );
            delete from public.checkpoint_active_reservations
             where device_id = v_reservation.device_id;
        end if;
    end loop;

    insert into public.checkpoint_active_reservations (
        device_id, operation_id, fingerprint, expires_at
    )
    select participant_row.device_id, p_operation_id, v_fingerprint,
           v_now + pg_catalog.make_interval(secs => p_lease_seconds)
      from public.checkpoint_operation_participants as participant_row
     where participant_row.operation_id = p_operation_id
     order by participant_row.device_id;

    v_payload := pg_catalog.jsonb_build_object(
        'operation_id', p_operation_id,
        'fingerprint', pg_catalog.encode(v_fingerprint, 'hex'),
        'participant_sha256', pg_catalog.encode(v_participant_sha256, 'hex'),
        'expires_at', v_now + pg_catalog.make_interval(secs => p_lease_seconds),
        'participant_count', v_expected_count
    );

    insert into public.checkpoint_operation_events (
        operation_id, event_type, event_payload, event_sha256
    )
    values (
        p_operation_id,
        'reserved',
        v_payload,
        extensions.digest(
            pg_catalog.convert_to(wedecent_private.canonical_jsonb(v_payload), 'UTF8'),
            'sha256'
        )
    );

    return pg_catalog.jsonb_build_object(
        'status', 'reserved',
        'operation_id', p_operation_id,
        'fingerprint', pg_catalog.encode(v_fingerprint, 'hex'),
        'participant_sha256', pg_catalog.encode(v_participant_sha256, 'hex'),
        'expires_at', v_now + pg_catalog.make_interval(secs => p_lease_seconds)
    );
end;
$$;

create or replace function public.commit_checkpoint_operation(
    p_operation_id text,
    p_fingerprint bytea,
    p_witness_acknowledgements jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_operation public.checkpoint_operations%rowtype;
    v_participant public.checkpoint_operation_participants%rowtype;
    v_actor_role public.organization_role;
    v_actor_role public.organization_role;
    v_device public.devices%rowtype;
    v_authority public.port_forward_replay_authority%rowtype;
    v_event public.checkpoint_operation_events%rowtype;
    v_authoritative jsonb := '[]'::jsonb;
    v_result jsonb;
    v_token_sha256 text;
    v_ack_generation numeric;
    v_ack_count integer;
    v_count integer;
    v_locked integer := 0;
begin
    if p_operation_id is null or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_fingerprint is null or pg_catalog.octet_length(p_fingerprint) <> 32 then
        raise exception 'invalid checkpoint commit request'
            using errcode = '22023';
    end if;

    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_operation_id, 0));

    select operation_row.*
      into v_operation
      from public.checkpoint_operations as operation_row
     where operation_row.operation_id = p_operation_id
     for update;

    if not found or v_operation.fingerprint <> p_fingerprint then
        raise exception 'checkpoint operation fingerprint conflict'
            using errcode = '23505';
    end if;

    select event_row.*
      into v_event
      from public.checkpoint_operation_events as event_row
     where event_row.operation_id = p_operation_id
       and event_row.event_type = 'committed';

    if found then
        return v_event.event_payload -> 'result';
    end if;

    if p_witness_acknowledgements is null
       or pg_catalog.jsonb_typeof(p_witness_acknowledgements) <> 'array'
       or pg_catalog.jsonb_array_length(p_witness_acknowledgements) < 2
       or pg_catalog.jsonb_array_length(p_witness_acknowledgements) > 31 then
        raise exception 'checkpoint witness acknowledgements are malformed or insufficient'
            using errcode = '22023';
    end if;

    v_ack_count := pg_catalog.jsonb_array_length(p_witness_acknowledgements);
    if exists (
        select 1
          from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
         where pg_catalog.jsonb_typeof(item.value) <> 'object'
            or pg_catalog.jsonb_object_length(item.value) <> 8
            or not (item.value ?& array[
                'witness_id', 'token_sha256', 'generation', 'action',
                'operation_id', 'witness_key_id', 'committed_at_unix_ms', 'signature'
            ])
            or coalesce(item.value ->> 'witness_id', '') !~ '^[A-Za-z0-9._-]{1,64}$'
            or coalesce(item.value ->> 'token_sha256', '') !~ '^[0-9a-f]{64}$'
            or coalesce(item.value ->> 'generation', '') !~ '^[1-9][0-9]{0,18}$'
            or (item.value ->> 'generation')::numeric > 9223372036854775807::numeric
            or item.value ->> 'action' <> v_operation.action
            or item.value ->> 'operation_id' <> p_operation_id
            or coalesce(item.value ->> 'witness_key_id', '') !~ '^[A-Za-z0-9._:-]{1,128}$'
            or coalesce(item.value ->> 'committed_at_unix_ms', '') !~ '^[1-9][0-9]{0,18}$'
            or (item.value ->> 'committed_at_unix_ms')::numeric > 9223372036854775807::numeric
            or coalesce(item.value ->> 'signature', '') !~ '^[A-Za-z0-9+/]{86}==$'
    ) then
        raise exception 'checkpoint witness acknowledgement fields are malformed'
            using errcode = '22023';
    end if;

    if (
        select pg_catalog.count(distinct item.value ->> 'witness_id')
          from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
    ) <> v_ack_count
       or (
           select pg_catalog.count(distinct item.value ->> 'token_sha256')
             from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
       ) <> 1
       or (
           select pg_catalog.count(distinct item.value ->> 'generation')
             from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
       ) <> 1 then
        raise exception 'checkpoint witness acknowledgement set conflicts'
            using errcode = '22023';
    end if;

    select item.value ->> 'token_sha256',
           (item.value ->> 'generation')::numeric
      into v_token_sha256, v_ack_generation
      from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
     limit 1;

    select pg_catalog.count(*)
      into v_count
      from public.checkpoint_operation_participants
     where operation_id = p_operation_id;

    if v_count < 1 or v_count > 32 then
        raise exception 'checkpoint operation participant ledger is unavailable'
            using errcode = '55000';
    end if;

    perform organization_row.id
      from public.organizations as organization_row
     where organization_row.id = v_operation.organization_id
     for share;
    if not found then
        raise exception 'checkpoint organization is unavailable'
            using errcode = '42501';
    end if;

    select membership.role
      into v_actor_role
      from public.organization_memberships as membership
     where membership.organization_id = v_operation.organization_id
       and membership.user_id = v_operation.actor_id
     for share;

    if not found
       or (v_operation.action = 'revoke' and v_actor_role not in ('owner', 'admin')) then
        raise exception 'checkpoint actor authorization was revoked'
            using errcode = '42501';
    end if;

    perform membership.user_id
      from public.organization_memberships as membership
     where membership.organization_id = v_operation.organization_id
       and membership.user_id in (
           select participant_row.account_id
             from public.checkpoint_operation_participants as participant_row
            where participant_row.operation_id = p_operation_id
       )
     order by membership.user_id
     for share;

    if (
        select pg_catalog.count(distinct membership.user_id)
          from public.organization_memberships as membership
         where membership.organization_id = v_operation.organization_id
           and membership.user_id in (
               select participant_row.account_id
                 from public.checkpoint_operation_participants as participant_row
                where participant_row.operation_id = p_operation_id
           )
    ) <> (
        select pg_catalog.count(distinct participant_row.account_id)
          from public.checkpoint_operation_participants as participant_row
         where participant_row.operation_id = p_operation_id
    ) then
        raise exception 'checkpoint participant membership is unavailable'
            using errcode = '42501';
    end if;

    for v_device in
        select device_row.*
          from public.devices as device_row
          join public.checkpoint_operation_participants as participant_row
            on participant_row.device_id = device_row.device_id
         where participant_row.operation_id = p_operation_id
         order by device_row.device_id
         for share
    loop
        select participant_row.*
          into v_participant
          from public.checkpoint_operation_participants as participant_row
         where participant_row.operation_id = p_operation_id
           and participant_row.device_id = v_device.device_id;

        if v_device.owner_user_id <> v_participant.account_id
           or v_device.organization_id <> v_participant.organization_id
           or v_device.revocation_epoch <> v_participant.revocation_epoch
           or v_device.revoked_at is not null then
            raise exception 'checkpoint participant identity or revocation changed'
                using errcode = '42501';
        end if;
    end loop;

    if (
        select pg_catalog.count(*)
          from public.devices as device_row
          join public.checkpoint_operation_participants as participant_row
            on participant_row.device_id = device_row.device_id
         where participant_row.operation_id = p_operation_id
    ) <> v_count then
        raise exception 'checkpoint participant device is unavailable'
            using errcode = '42501';
    end if;

    for v_participant in
        select participant_row.*
          from public.checkpoint_operation_participants as participant_row
         where participant_row.operation_id = p_operation_id
         order by participant_row.device_id
    loop
        select authority_row.*
          into v_authority
          from public.port_forward_replay_authority as authority_row
         where authority_row.device_id = v_participant.device_id
         for update;

        if not found
           or v_authority.checkpoint_head_generation <> v_participant.expected_generation
           or v_authority.checkpoint_head_hash <> v_participant.expected_hash then
            raise exception 'checkpoint participant head changed before commit'
                using errcode = '40001';
        end if;

        if not exists (
            select 1
              from public.checkpoint_active_reservations as reservation_row
             where reservation_row.device_id = v_participant.device_id
               and reservation_row.operation_id = p_operation_id
               and reservation_row.fingerprint = p_fingerprint
               and reservation_row.expires_at > v_now
        ) then
            raise exception 'checkpoint reservation is missing or expired'
                using errcode = '55P03';
        end if;

        v_authoritative := v_authoritative || pg_catalog.jsonb_build_array(
            pg_catalog.jsonb_build_object(
                'device_id', v_participant.device_id,
                'account_id', v_participant.account_id,
                'organization_id', v_participant.organization_id,
                'revocation_epoch', v_participant.revocation_epoch,
                'head_generation', v_authority.checkpoint_head_generation,
                'head_hash', pg_catalog.encode(v_authority.checkpoint_head_hash, 'hex')
            )
        );
        v_locked := v_locked + 1;
    end loop;

    if v_locked <> v_count then
        raise exception 'checkpoint participant authority set is incomplete'
            using errcode = '55000';
    end if;

    if not wedecent_private.checkpoint_v1_transition_matches(
        (
            select pg_catalog.jsonb_agg(
                pg_catalog.jsonb_build_object(
                    'device_id', participant_row.device_id,
                    'account_id', participant_row.account_id,
                    'organization_id', participant_row.organization_id,
                    'revocation_epoch', participant_row.revocation_epoch,
                    'head_generation', participant_row.expected_generation,
                    'head_hash', pg_catalog.encode(participant_row.expected_hash, 'hex')
                )
                order by participant_row.device_id
            )
              from public.checkpoint_operation_participants as participant_row
             where participant_row.operation_id = p_operation_id
        ),
        v_authoritative
    ) then
        raise exception 'checkpoint commit participant revalidation failed'
            using errcode = '40001';
    end if;

    update public.port_forward_replay_authority as authority_row
       set checkpoint_head_generation = participant_row.next_generation,
           checkpoint_head_hash = participant_row.next_hash,
           updated_at = pg_catalog.clock_timestamp()
      from public.checkpoint_operation_participants as participant_row
     where participant_row.operation_id = p_operation_id
       and authority_row.device_id = participant_row.device_id
       and authority_row.checkpoint_head_generation = participant_row.expected_generation
       and authority_row.checkpoint_head_hash = participant_row.expected_hash;

    get diagnostics v_locked = row_count;
    if v_locked <> v_count then
        raise exception 'checkpoint atomic head advancement was incomplete'
            using errcode = '40001';
    end if;

    select pg_catalog.jsonb_build_object(
        'status', 'committed',
        'operation_id', p_operation_id,
        'fingerprint', pg_catalog.encode(v_operation.fingerprint, 'hex'),
        'participant_sha256', pg_catalog.encode(v_operation.participant_sha256, 'hex'),
        'participants', pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
                'device_id', participant_row.device_id,
                'generation', participant_row.next_generation,
                'head_hash', pg_catalog.encode(participant_row.next_hash, 'hex')
            )
            order by participant_row.device_id
        ),
        'witness_token_sha256', v_token_sha256,
        'witness_generation', v_ack_generation,
        'witness_acknowledgements', p_witness_acknowledgements
    )
      into v_result
      from public.checkpoint_operation_participants as participant_row
     where participant_row.operation_id = p_operation_id;

    v_result := pg_catalog.jsonb_build_object('result', v_result);

    insert into public.checkpoint_operation_events (
        operation_id, event_type, event_payload, event_sha256
    )
    values (
        p_operation_id,
        'committed',
        v_result,
        extensions.digest(
            pg_catalog.convert_to(wedecent_private.canonical_jsonb(v_result), 'UTF8'),
            'sha256'
        )
    );

    delete from public.checkpoint_active_reservations
     where operation_id = p_operation_id;

    return v_result -> 'result';
end;
$$;

revoke all on function public.reserve_checkpoint_operation(text, text, uuid, uuid, bytea, jsonb, integer)
    from public, anon, authenticated;
revoke all on function public.commit_checkpoint_operation(text, bytea, jsonb)
    from public, anon, authenticated;

grant execute on function public.reserve_checkpoint_operation(text, text, uuid, uuid, bytea, jsonb, integer)
    to service_role;
grant execute on function public.commit_checkpoint_operation(text, bytea, jsonb)
    to service_role;

comment on table public.port_forward_replay_authority is
    'Sole mutable per-device authority row for port-forward replay chain state and PostgreSQL checkpoint participant heads. Checkpoint reservations and events are coordination/evidence only.';
comment on table public.checkpoint_operations is
    'Immutable operation identity and fingerprint for atomic multi-participant checkpoint reservations and commits.';
comment on table public.checkpoint_operation_participants is
    'Immutable expected and next participant snapshots; never authoritative for current heads.';
comment on table public.checkpoint_operation_events is
    'Append-only reservation, expiry and commit evidence. SQL validates acknowledgement structure and binding only; the trusted Go primary must verify Ed25519 signatures and independent quorum membership.';
comment on table public.checkpoint_active_reservations is
    'Expiring per-device reservation leases. This table contains no participant head and is not an authority.';

commit;
