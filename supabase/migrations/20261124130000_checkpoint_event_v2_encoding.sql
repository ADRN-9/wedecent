-- Versioned canonical event encoding shared with Go CheckpointEventV2Encoding.
-- Historical replay-entry hashes are deliberately not rewritten or reinterpreted.
begin;

create or replace function wedecent_private.checkpoint_event_v2_encoding(
    p_action text,
    p_scope_kind text,
    p_device_id text,
    p_account_id text,
    p_organization_id text,
    p_operation_id text,
    p_request_sha256 bytea,
    p_participant_sha256 bytea,
    p_previous_hash bytea,
    p_generation bigint,
    p_revocation_epoch bigint
)
returns bytea
language plpgsql
immutable
strict
parallel safe
security invoker
set search_path = ''
as $$
declare
    v_result bytea := pg_catalog.convert_to('wedecent-checkpoint-event-v2', 'UTF8') || pg_catalog.decode('00', 'hex');
begin
    if p_action not in ('finalize', 'revoke')
       or p_scope_kind not in ('device', 'organization')
       or p_operation_id !~ '^[0-9a-f]{64}$'
       or pg_catalog.octet_length(p_request_sha256) <> 32
       or pg_catalog.octet_length(p_participant_sha256) <> 32
       or pg_catalog.octet_length(p_previous_hash) <> 32
       or p_generation <= 0
       or p_revocation_epoch < 0 then
        raise exception 'invalid canonical checkpoint event v2'
            using errcode = '22023';
    end if;

    if p_scope_kind = 'device' then
        if p_device_id !~ '^wd_[a-z2-7]{16}$'
           or p_account_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           or p_organization_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
            raise exception 'invalid device checkpoint event scope'
                using errcode = '22023';
        end if;
    elsif p_device_id <> '' or p_account_id <> ''
       or p_organization_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
        raise exception 'invalid organization checkpoint event scope'
            using errcode = '22023';
    end if;

    v_result := v_result
        || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(p_action, 'UTF8')))
        || pg_catalog.convert_to(p_action, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(p_scope_kind, 'UTF8')))
        || pg_catalog.convert_to(p_scope_kind, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(p_device_id, 'UTF8')))
        || pg_catalog.convert_to(p_device_id, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(p_account_id, 'UTF8')))
        || pg_catalog.convert_to(p_account_id, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(p_organization_id, 'UTF8')))
        || pg_catalog.convert_to(p_organization_id, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(p_operation_id, 'UTF8')))
        || pg_catalog.convert_to(p_operation_id, 'UTF8')
        || p_request_sha256
        || p_participant_sha256
        || p_previous_hash
        || pg_catalog.int8send(p_generation)
        || pg_catalog.int8send(p_revocation_epoch);

    return v_result;
end;
$$;

create or replace function wedecent_private.checkpoint_event_v2_hash(
    p_action text,
    p_scope_kind text,
    p_device_id text,
    p_account_id text,
    p_organization_id text,
    p_operation_id text,
    p_request_sha256 bytea,
    p_participant_sha256 bytea,
    p_previous_hash bytea,
    p_generation bigint,
    p_revocation_epoch bigint
)
returns bytea
language sql
immutable
strict
parallel safe
security invoker
set search_path = ''
as $$
    select extensions.digest(
        wedecent_private.checkpoint_event_v2_encoding(
            p_action, p_scope_kind, p_device_id, p_account_id,
            p_organization_id, p_operation_id, p_request_sha256,
            p_participant_sha256, p_previous_hash, p_generation,
            p_revocation_epoch
        ),
        'sha256'
    );
$$;

revoke all on function wedecent_private.checkpoint_event_v2_encoding(text,text,text,text,text,text,bytea,bytea,bytea,bigint,bigint)
    from public, anon, authenticated, service_role;
revoke all on function wedecent_private.checkpoint_event_v2_hash(text,text,text,text,text,text,bytea,bytea,bytea,bigint,bigint)
    from public, anon, authenticated, service_role;

commit;
