begin;

create or replace function wedecent_private.checkpoint_participant_vector_encoding(p_participants jsonb)
returns bytea
language plpgsql
immutable
parallel safe
security invoker
set search_path = ''
as $$
declare
    v_result bytea := pg_catalog.convert_to('wedecent-checkpoint-participant-vector-v1', 'UTF8') || pg_catalog.decode('00', 'hex');
    v_participant jsonb;
    v_device_id text;
    v_account_id text;
    v_organization_id text;
    v_epoch bigint;
    v_generation bigint;
    v_head_hash bytea;
    v_count integer;
begin
    if p_participants is null or pg_catalog.jsonb_typeof(p_participants) <> 'array' then
        raise exception 'participant vector must be an array' using errcode = '22023';
    end if;

    v_count := pg_catalog.jsonb_array_length(p_participants);
    if v_count < 1 then
        raise exception 'participant vector must not be empty' using errcode = '22023';
    end if;

    if exists (
        select 1
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
        where pg_catalog.jsonb_typeof(item.value) <> 'object'
           or (
               select pg_catalog.count(*)
               from pg_catalog.jsonb_object_keys(
                   case when pg_catalog.jsonb_typeof(item.value) = 'object'
                        then item.value else '{}'::jsonb end
               )
           ) <> 6
           or not (item.value ?& array[
               'device_id', 'account_id', 'organization_id',
               'revocation_epoch', 'head_generation', 'head_hash'
           ])
    ) then
        raise exception 'participant vector contains malformed records' using errcode = '22023';
    end if;

    if exists (
        select 1
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
        group by (item.value->>'device_id') collate "C"
        having pg_catalog.count(*) > 1
    ) then
        raise exception 'participant vector contains duplicate devices' using errcode = '22023';
    end if;

    if exists (
        select 1
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
        where item.value->>'device_id' is null
           or item.value->>'account_id' is null
           or item.value->>'organization_id' is null
           or item.value->>'revocation_epoch' is null
           or item.value->>'head_generation' is null
           or item.value->>'head_hash' is null
           or item.value->>'device_id' !~ '^wd_[a-z2-7]{16}$'
           or item.value->>'account_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           or item.value->>'organization_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           or item.value->>'revocation_epoch' !~ '^(0|[1-9][0-9]*)$'
           or item.value->>'head_generation' !~ '^(0|[1-9][0-9]*)$'
           or item.value->>'head_hash' !~ '^[0-9a-f]{64}$'
    ) then
        raise exception 'participant vector contains invalid identities or counters' using errcode = '22023';
    end if;

    if (
        select pg_catalog.count(distinct item.value->>'organization_id')
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
    ) <> 1 then
        raise exception 'participants must belong to one organization' using errcode = '22023';
    end if;

    v_result := v_result || pg_catalog.int4send(v_count);
    for v_participant in
        select item.value
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
        order by (item.value->>'device_id') collate "C"
    loop
        v_device_id := v_participant->>'device_id';
        v_account_id := v_participant->>'account_id';
        v_organization_id := v_participant->>'organization_id';
        v_epoch := (v_participant->>'revocation_epoch')::bigint;
        v_generation := (v_participant->>'head_generation')::bigint;
        v_head_hash := pg_catalog.decode(v_participant->>'head_hash', 'hex');

        if (v_generation = 0 and v_head_hash <> pg_catalog.decode(repeat('00', 32), 'hex'))
           or (v_generation > 0 and v_head_hash = pg_catalog.decode(repeat('00', 32), 'hex')) then
            raise exception 'participant head generation/hash mismatch' using errcode = '22023';
        end if;

        v_result := v_result
            || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(v_device_id, 'UTF8')))
            || pg_catalog.convert_to(v_device_id, 'UTF8')
            || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(v_account_id, 'UTF8')))
            || pg_catalog.convert_to(v_account_id, 'UTF8')
            || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(v_organization_id, 'UTF8')))
            || pg_catalog.convert_to(v_organization_id, 'UTF8')
            || pg_catalog.int8send(v_epoch)
            || pg_catalog.int8send(v_generation)
            || v_head_hash;
    end loop;

    return v_result;
exception
    when numeric_value_out_of_range then
        raise exception 'participant counter exceeds PostgreSQL bigint range' using errcode = '22003';
end $$;

create or replace function wedecent_private.checkpoint_participant_vector_hash(p_participants jsonb)
returns bytea
language sql
immutable
parallel safe
security invoker
set search_path = ''
as $$
    select extensions.digest(
        wedecent_private.checkpoint_participant_vector_encoding(p_participants),
        'sha256'
    );
$$;

-- Pure comparator only. The authoritative argument must come from rows locked by the calling transaction.
create or replace function wedecent_private.checkpoint_v1_transition_matches(
    p_claimed jsonb,
    p_authoritative_locked_heads jsonb
)
returns boolean
language plpgsql
immutable
parallel safe
security invoker
set search_path = ''
as $$
begin
    if p_claimed is null or p_authoritative_locked_heads is null then
        raise exception 'historical participant vectors are required' using errcode = '22023';
    end if;

    return wedecent_private.checkpoint_participant_vector_encoding(p_claimed)
        = wedecent_private.checkpoint_participant_vector_encoding(p_authoritative_locked_heads);
end $$;

create or replace function wedecent_private.checkpoint_event_v2_encoding_from_participants(
    p_action text,
    p_scope_kind text,
    p_device_id text,
    p_account_id text,
    p_organization_id text,
    p_operation_id text,
    p_request_sha256 bytea,
    p_participants jsonb,
    p_previous_hash bytea,
    p_generation bigint,
    p_revocation_epoch bigint
)
returns bytea
language plpgsql
immutable
parallel safe
security invoker
set search_path = ''
as $$
declare
    v_participant_digest bytea;
begin
    if p_participants is null or p_action is null or p_scope_kind is null
       or p_device_id is null or p_account_id is null or p_organization_id is null
       or p_operation_id is null or p_request_sha256 is null or p_previous_hash is null
       or p_generation is null or p_revocation_epoch is null then
        raise exception 'checkpoint event fields and participant vector are required' using errcode = '22023';
    end if;

    v_participant_digest := wedecent_private.checkpoint_participant_vector_hash(p_participants);

    if exists (
        select 1
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
        where item.value->>'organization_id' <> p_organization_id
    ) then
        raise exception 'participant organization does not match event scope' using errcode = '22023';
    end if;

    if p_scope_kind = 'device' and not exists (
        select 1
        from pg_catalog.jsonb_array_elements(p_participants) as item(value)
        where item.value->>'device_id' = p_device_id
          and item.value->>'account_id' = p_account_id
          and item.value->>'organization_id' = p_organization_id
          and (item.value->>'revocation_epoch')::bigint = p_revocation_epoch
    ) then
        raise exception 'device event scope or epoch is absent from participant vector' using errcode = '22023';
    end if;

    return wedecent_private.checkpoint_event_v2_encoding(
        p_action, p_scope_kind, p_device_id, p_account_id, p_organization_id,
        p_operation_id, p_request_sha256, v_participant_digest, p_previous_hash,
        p_generation, p_revocation_epoch
    );
end $$;

revoke all on function wedecent_private.checkpoint_participant_vector_encoding(jsonb)
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.checkpoint_participant_vector_hash(jsonb)
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.checkpoint_v1_transition_matches(jsonb, jsonb)
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.checkpoint_event_v2_encoding_from_participants(text, text, text, text, text, text, bytea, jsonb, bytea, bigint, bigint)
    from public, anon, authenticated, service_role;

commit;
