-- PostgreSQL-backed organization fence ordering, signed-token receipts and recovery.
-- Participant heads remain exclusively in port_forward_replay_authority.
begin;

create table public.checkpoint_fence_authority (
    organization_id uuid primary key references public.organizations(id) on delete restrict,
    generation bigint not null default 0 check (generation >= 0),
    revocation_epoch bigint not null default 0 check (revocation_epoch >= 0),
    fence_hash bytea not null default pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        check (pg_catalog.octet_length(fence_hash) = 32),
    primary_head_generation bigint not null default 0 check (primary_head_generation >= 0),
    primary_head_hash bytea not null default pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        check (pg_catalog.octet_length(primary_head_hash) = 32),
    pending_operation_id text references public.checkpoint_operations(operation_id) on delete restrict,
    pending_fingerprint bytea check (pending_fingerprint is null or pg_catalog.octet_length(pending_fingerprint) = 32),
    pending_expires_at timestamptz,
    pending_primary_head_generation bigint,
    pending_primary_head_hash bytea,
    updated_at timestamptz not null default pg_catalog.clock_timestamp(),
    constraint checkpoint_fence_pending_consistency check (
        (pending_operation_id is null and pending_fingerprint is null and pending_expires_at is null
            and pending_primary_head_generation is null and pending_primary_head_hash is null)
        or
        (pending_operation_id is not null and pending_fingerprint is not null and pending_expires_at is not null
            and pending_primary_head_generation is not null and pending_primary_head_generation > 0
            and pending_primary_head_hash is not null and pg_catalog.octet_length(pending_primary_head_hash) = 32)
    ),
    constraint checkpoint_fence_head_consistency check (
        (generation = 0 and fence_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'))
        or (generation > 0 and fence_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'))
    )
);

alter table public.checkpoint_operation_events
    drop constraint checkpoint_operation_events_event_type_check;
alter table public.checkpoint_operation_events
    add constraint checkpoint_operation_events_event_type_check
    check (event_type in (
        'reserved', 'reservation_expired', 'committed',
        'fence_reserved', 'fence_committed'
    ));

alter table public.checkpoint_fence_authority enable row level security;
revoke all on public.checkpoint_fence_authority from public, anon, authenticated, service_role;

create or replace function public.reserve_checkpoint_fence_operation(
    p_operation_id text,
    p_action text,
    p_organization_id uuid,
    p_actor_id uuid,
    p_request_sha256 bytea,
    p_participants jsonb,
    p_primary_head_generation bigint,
    p_primary_head_sha256 bytea,
    p_lease_seconds integer default 60
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_fence public.checkpoint_fence_authority%rowtype;
    v_reservation jsonb;
    v_fingerprint bytea;
begin
    if p_primary_head_generation is null or p_primary_head_generation < 1
       or p_primary_head_sha256 is null or pg_catalog.octet_length(p_primary_head_sha256) <> 32
       or p_primary_head_sha256 = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') then
        raise exception 'invalid checkpoint fence primary head'
            using errcode = '22023';
    end if;

    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_operation_id, 0));

    insert into public.checkpoint_fence_authority(organization_id)
    values (p_organization_id)
    on conflict (organization_id) do nothing;

    select authority.*
      into v_fence
      from public.checkpoint_fence_authority as authority
     where authority.organization_id = p_organization_id
     for update;

    if not found then
        raise exception 'checkpoint fence authority unavailable'
            using errcode = '55000';
    end if;

    if v_fence.pending_operation_id is not null
       and v_fence.pending_expires_at > v_now
       and v_fence.pending_operation_id <> p_operation_id then
        raise exception 'organization checkpoint fence is reserved by another operation'
            using errcode = '55P03';
    end if;

    if v_fence.pending_operation_id is not null
       and v_fence.pending_expires_at <= v_now then
        update public.checkpoint_fence_authority
           set pending_operation_id = null,
               pending_fingerprint = null,
               pending_expires_at = null,
               pending_primary_head_generation = null,
               pending_primary_head_hash = null,
               updated_at = pg_catalog.clock_timestamp()
         where organization_id = p_organization_id;
        v_fence.pending_operation_id := null;
        v_fence.pending_fingerprint := null;
        v_fence.pending_expires_at := null;
        v_fence.pending_primary_head_generation := null;
        v_fence.pending_primary_head_hash := null;
    end if;

    if p_primary_head_generation <> v_fence.generation + 1
       or (p_primary_head_generation = v_fence.primary_head_generation
           and p_primary_head_sha256 <> v_fence.primary_head_hash)
       or p_primary_head_generation < v_fence.primary_head_generation then
        raise exception 'checkpoint fence primary head is stale'
            using errcode = '40001';
    end if;

    v_reservation := public.reserve_checkpoint_operation(
        p_operation_id, p_action, p_organization_id, p_actor_id,
        p_request_sha256, p_participants, p_lease_seconds
    );

    if v_reservation ->> 'status' = 'committed' then
        return v_reservation;
    end if;

    v_fingerprint := pg_catalog.decode(v_reservation ->> 'fingerprint', 'hex');

    if v_fence.pending_operation_id = p_operation_id then
        if v_fence.pending_fingerprint <> v_fingerprint then
            raise exception 'checkpoint fence operation fingerprint conflict'
                using errcode = '23505';
        end if;
        return v_reservation || pg_catalog.jsonb_build_object(
            'fence_generation', v_fence.generation,
            'fence_hash', pg_catalog.encode(v_fence.fence_hash, 'hex'),
            'revocation_epoch', v_fence.revocation_epoch,
            'primary_head_generation', p_primary_head_generation,
            'primary_head_sha256', pg_catalog.encode(v_fence.pending_primary_head_hash, 'hex'),
            'fence_expires_at', v_fence.pending_expires_at
        );
    end if;

    update public.checkpoint_fence_authority
       set pending_operation_id = p_operation_id,
           pending_fingerprint = v_fingerprint,
           pending_expires_at = (v_reservation ->> 'expires_at')::timestamptz,
           pending_primary_head_generation = p_primary_head_generation,
           pending_primary_head_hash = p_primary_head_sha256,
           updated_at = pg_catalog.clock_timestamp()
     where organization_id = p_organization_id;

    return v_reservation || pg_catalog.jsonb_build_object(
        'fence_generation', v_fence.generation,
        'fence_hash', pg_catalog.encode(v_fence.fence_hash, 'hex'),
        'revocation_epoch', v_fence.revocation_epoch,
        'primary_head_generation', p_primary_head_generation,
        'primary_head_sha256', pg_catalog.encode(p_primary_head_sha256, 'hex'),
        'fence_expires_at', (v_reservation ->> 'expires_at')::timestamptz
    );
end;
$$;

create or replace function public.record_checkpoint_fence_token(
    p_operation_id text,
    p_fingerprint bytea,
    p_token_sha256 bytea,
    p_token jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_operation public.checkpoint_operations%rowtype;
    v_fence public.checkpoint_fence_authority%rowtype;
    v_existing public.checkpoint_operation_events%rowtype;
    v_payload jsonb;
begin
    if p_operation_id is null or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_fingerprint is null or pg_catalog.octet_length(p_fingerprint) <> 32
       or p_token_sha256 is null or pg_catalog.octet_length(p_token_sha256) <> 32
       or p_token is null or pg_catalog.jsonb_typeof(p_token) <> 'object' then
        raise exception 'invalid checkpoint fence token receipt'
            using errcode = '22023';
    end if;

    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_operation_id, 0));

    select operation_row.* into v_operation
      from public.checkpoint_operations as operation_row
     where operation_row.operation_id = p_operation_id
     for share;
    if not found or v_operation.fingerprint <> p_fingerprint
       or p_token ->> 'operation_id' <> p_operation_id
       or p_token ->> 'action' <> v_operation.action
       or p_token -> 'scope' ->> 'organization_id' <> v_operation.organization_id::text
       or p_token ->> 'request_sha256' <> pg_catalog.encode(v_operation.request_sha256, 'hex') then
        raise exception 'checkpoint fence token does not match reserved operation'
            using errcode = '23505';
    end if;

    select authority.* into v_fence
      from public.checkpoint_fence_authority as authority
     where authority.organization_id = v_operation.organization_id
     for update;
    if not found or v_fence.pending_operation_id <> p_operation_id
       or v_fence.pending_fingerprint <> p_fingerprint
       or v_fence.pending_expires_at <= pg_catalog.clock_timestamp()
       or (p_token ->> 'expected_fence_generation')::bigint <> v_fence.generation
       or (p_token ->> 'generation')::bigint <> v_fence.generation + 1
       or p_token ->> 'previous_fence_sha256' <> pg_catalog.encode(v_fence.fence_hash, 'hex')
       or (p_token ->> 'expected_revocation_epoch')::bigint <> v_fence.revocation_epoch
       or (p_token ->> 'primary_head_generation')::bigint <> v_fence.pending_primary_head_generation
       or p_token ->> 'primary_head_sha256' <> pg_catalog.encode(v_fence.pending_primary_head_hash, 'hex')
       or (p_token ->> 'expires_at_unix_ms')::bigint > (extract(epoch from v_fence.pending_expires_at) * 1000)::bigint
       or (p_token ->> 'expires_at_unix_ms')::bigint <= (extract(epoch from pg_catalog.clock_timestamp()) * 1000)::bigint then
        raise exception 'checkpoint fence token is stale or expired'
            using errcode = '40001';
    end if;

    select event_row.* into v_existing
      from public.checkpoint_operation_events as event_row
     where event_row.operation_id = p_operation_id
       and event_row.event_type = 'fence_reserved'
     order by event_row.event_id desc
     limit 1;

    if found and v_existing.event_payload ->> 'token_sha256' = pg_catalog.encode(p_token_sha256, 'hex')
       and v_existing.event_payload -> 'token' = p_token then
        return v_existing.event_payload;
    end if;
    if found and (v_existing.event_payload -> 'token' ->> 'expires_at_unix_ms')::bigint
        > (extract(epoch from pg_catalog.clock_timestamp()) * 1000)::bigint then
        raise exception 'checkpoint fence token retry conflicts'
            using errcode = '23505';
    end if;

    if (
        select pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
                'device_id', participant_row.device_id,
                'account_id', participant_row.account_id,
                'organization_id', participant_row.organization_id,
                'revocation_epoch', participant_row.revocation_epoch
            ) order by participant_row.device_id
        )
        from public.checkpoint_operation_participants as participant_row
        where participant_row.operation_id = p_operation_id
    ) <> (
        select pg_catalog.jsonb_agg(item.value order by item.value ->> 'device_id')
        from pg_catalog.jsonb_array_elements(p_token -> 'participants') as item(value)
    ) then
        raise exception 'checkpoint fence token participant vector conflicts'
            using errcode = '23505';
    end if;

    v_payload := pg_catalog.jsonb_build_object(
        'token_sha256', pg_catalog.encode(p_token_sha256, 'hex'),
        'token', p_token
    );
    insert into public.checkpoint_operation_events(
        operation_id, event_type, event_payload, event_sha256
    ) values (
        p_operation_id, 'fence_reserved', v_payload,
        extensions.digest(pg_catalog.convert_to(wedecent_private.canonical_jsonb(v_payload), 'UTF8'), 'sha256')
    );
    return v_payload;
end;
$$;

create or replace function public.commit_checkpoint_fence_operation(
    p_operation_id text,
    p_fingerprint bytea,
    p_token_sha256 bytea,
    p_witness_acknowledgements jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_operation public.checkpoint_operations%rowtype;
    v_fence public.checkpoint_fence_authority%rowtype;
    v_token_event public.checkpoint_operation_events%rowtype;
    v_commit_event public.checkpoint_operation_events%rowtype;
    v_token jsonb;
    v_result jsonb;
    v_ack_count integer;
begin
    if p_operation_id is null or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_fingerprint is null or pg_catalog.octet_length(p_fingerprint) <> 32
       or p_token_sha256 is null or pg_catalog.octet_length(p_token_sha256) <> 32 then
        raise exception 'invalid checkpoint fence commit'
            using errcode = '22023';
    end if;

    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_operation_id, 0));

    select operation_row.* into v_operation
      from public.checkpoint_operations as operation_row
     where operation_row.operation_id = p_operation_id
     for update;
    if not found or v_operation.fingerprint <> p_fingerprint then
        raise exception 'checkpoint operation fingerprint conflict'
            using errcode = '23505';
    end if;

    select event_row.* into v_commit_event
      from public.checkpoint_operation_events as event_row
     where event_row.operation_id = p_operation_id
       and event_row.event_type = 'fence_committed';
    if found then
        if v_commit_event.event_payload ->> 'token_sha256' <> pg_catalog.encode(p_token_sha256, 'hex') then
            raise exception 'checkpoint committed token digest conflicts'
                using errcode = '23505';
        end if;
        return v_commit_event.event_payload -> 'result';
    end if;

    select event_row.* into v_token_event
      from public.checkpoint_operation_events as event_row
     where event_row.operation_id = p_operation_id
       and event_row.event_type = 'fence_reserved'
     order by event_row.event_id desc
     limit 1;
    if not found or v_token_event.event_payload ->> 'token_sha256' <> pg_catalog.encode(p_token_sha256, 'hex') then
        raise exception 'checkpoint signed reservation token is unavailable'
            using errcode = '55000';
    end if;
    v_token := v_token_event.event_payload -> 'token';

    if p_witness_acknowledgements is null
       or pg_catalog.jsonb_typeof(p_witness_acknowledgements) <> 'array'
       or pg_catalog.jsonb_array_length(p_witness_acknowledgements) < 2
       or pg_catalog.jsonb_array_length(p_witness_acknowledgements) > 31 then
        raise exception 'checkpoint witness acknowledgements are malformed'
            using errcode = '22023';
    end if;

    v_ack_count := pg_catalog.jsonb_array_length(p_witness_acknowledgements);
    if exists (
        select 1 from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
        where item.value ->> 'token_sha256' <> pg_catalog.encode(p_token_sha256, 'hex')
           or (item.value ->> 'generation')::bigint <> (v_token ->> 'generation')::bigint
           or item.value ->> 'operation_id' <> p_operation_id
           or item.value ->> 'action' <> v_operation.action
    ) or (
        select pg_catalog.count(distinct item.value ->> 'witness_id')
          from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value)
    ) <> v_ack_count then
        raise exception 'checkpoint witness acknowledgements do not bind to signed token'
            using errcode = '22023';
    end if;

    select authority.* into v_fence
      from public.checkpoint_fence_authority as authority
     where authority.organization_id = v_operation.organization_id
     for update;
    if not found or v_fence.pending_operation_id <> p_operation_id
       or v_fence.pending_fingerprint <> p_fingerprint
       or v_fence.pending_expires_at <= pg_catalog.clock_timestamp()
       or (v_token ->> 'expected_fence_generation')::bigint <> v_fence.generation
       or (v_token ->> 'generation')::bigint <> v_fence.generation + 1
       or v_token ->> 'previous_fence_sha256' <> pg_catalog.encode(v_fence.fence_hash, 'hex')
       or (v_token ->> 'expected_revocation_epoch')::bigint <> v_fence.revocation_epoch then
        raise exception 'checkpoint fence reservation is stale or expired'
            using errcode = '40001';
    end if;

    v_result := public.commit_checkpoint_operation(
        p_operation_id, p_fingerprint, p_witness_acknowledgements
    );

    update public.checkpoint_fence_authority
       set generation = (v_token ->> 'generation')::bigint,
           revocation_epoch = (v_token ->> 'resulting_revocation_epoch')::bigint,
           fence_hash = p_token_sha256,
           primary_head_generation = (v_token ->> 'primary_head_generation')::bigint,
           primary_head_hash = pg_catalog.decode(v_token ->> 'primary_head_sha256', 'hex'),
           pending_operation_id = null,
           pending_fingerprint = null,
           pending_expires_at = null,
           pending_primary_head_generation = null,
           pending_primary_head_hash = null,
           updated_at = pg_catalog.clock_timestamp()
     where organization_id = v_operation.organization_id
       and pending_operation_id = p_operation_id
       and generation = (v_token ->> 'expected_fence_generation')::bigint
       and fence_hash = pg_catalog.decode(v_token ->> 'previous_fence_sha256', 'hex');

    if not found then
        raise exception 'checkpoint fence authority advancement was incomplete'
            using errcode = '40001';
    end if;

    v_result := pg_catalog.jsonb_build_object(
        'token_sha256', pg_catalog.encode(p_token_sha256, 'hex'),
        'token', v_token,
        'result', v_result
    );
    insert into public.checkpoint_operation_events(
        operation_id, event_type, event_payload, event_sha256
    ) values (
        p_operation_id, 'fence_committed', v_result,
        extensions.digest(pg_catalog.convert_to(wedecent_private.canonical_jsonb(v_result), 'UTF8'), 'sha256')
    );
    return v_result -> 'result';
end;
$$;

create or replace function public.load_checkpoint_fence_operation(
    p_organization_id uuid,
    p_operation_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_token jsonb;
    v_token_sha256 text;
    v_commit jsonb;
begin
    select event_row.event_payload -> 'token',
           event_row.event_payload ->> 'token_sha256'
      into v_token, v_token_sha256
      from public.checkpoint_operation_events as event_row
      join public.checkpoint_operations as operation_row using (operation_id)
     where event_row.operation_id = p_operation_id
       and operation_row.organization_id = p_organization_id
       and event_row.event_type = 'fence_reserved'
     order by event_row.event_id desc
     limit 1;

    if v_token is null then
        return pg_catalog.jsonb_build_object('found', false);
    end if;

    select event_row.event_payload
      into v_commit
      from public.checkpoint_operation_events as event_row
     where event_row.operation_id = p_operation_id
       and event_row.event_type = 'fence_committed';

    return pg_catalog.jsonb_build_object(
        'found', true,
        'token', v_token,
        'token_sha256', v_token_sha256,
        'committed', v_commit is not null,
        'fingerprint', (
            select pg_catalog.encode(operation_row.fingerprint, 'hex')
            from public.checkpoint_operations as operation_row
            where operation_row.operation_id = p_operation_id
        ),
        'acknowledgements', coalesce(v_commit -> 'result' -> 'witness_acknowledgements', '[]'::jsonb)
    );
end;
$$;

create or replace function public.load_checkpoint_fence_head(p_organization_id uuid)
returns jsonb
language sql
security definer
set search_path = ''
as $$
 select pg_catalog.jsonb_build_object(
    'generation', authority.generation,
    'revocation_epoch', authority.revocation_epoch,
    'fence_hash', pg_catalog.encode(authority.fence_hash, 'hex'),
    'primary_head_generation', authority.primary_head_generation,
    'primary_head_sha256', pg_catalog.encode(authority.primary_head_hash, 'hex'),
    'pending_operation_id', coalesce(authority.pending_operation_id, '')
 )
 from public.checkpoint_fence_authority as authority
 where authority.organization_id = p_organization_id;
$$;

revoke all on function public.reserve_checkpoint_operation(text,text,uuid,uuid,bytea,jsonb,integer) from service_role;
revoke all on function public.commit_checkpoint_operation(text,bytea,jsonb) from service_role;

revoke all on function public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)
    from public, anon, authenticated;
revoke all on function public.record_checkpoint_fence_token(text,bytea,bytea,jsonb)
    from public, anon, authenticated;
revoke all on function public.commit_checkpoint_fence_operation(text,bytea,bytea,jsonb)
    from public, anon, authenticated;
revoke all on function public.load_checkpoint_fence_operation(uuid,text)
    from public, anon, authenticated;
revoke all on function public.load_checkpoint_fence_head(uuid)
    from public, anon, authenticated;

grant execute on function public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer) to service_role;
grant execute on function public.record_checkpoint_fence_token(text,bytea,bytea,jsonb) to service_role;
grant execute on function public.commit_checkpoint_fence_operation(text,bytea,bytea,jsonb) to service_role;
grant execute on function public.load_checkpoint_fence_operation(uuid,text) to service_role;
grant execute on function public.load_checkpoint_fence_head(uuid) to service_role;

comment on table public.checkpoint_fence_authority is
    'Organization-scoped fence ordering metadata only. Participant generations and hashes remain solely authoritative in port_forward_replay_authority.';
commit;
