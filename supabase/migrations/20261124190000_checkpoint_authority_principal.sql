begin;

-- The fencing API is callable only through a separately provisioned JWT role.
do $$
begin
    if not exists (select 1 from pg_catalog.pg_roles where rolname = 'wedecent_checkpoint_authority') then
        create role wedecent_checkpoint_authority nologin noinherit;
    end if;
end
$$;
grant wedecent_checkpoint_authority to authenticator;

create extension if not exists pgsodium;
grant usage on schema public, auth, pgsodium to wedecent_checkpoint_authority;

create table public.checkpoint_fence_primary_trust (
    key_id text primary key check (key_id ~ '^ed25519-[A-Za-z0-9_-]{43}$'),
    public_key bytea not null check (pg_catalog.octet_length(public_key) = 32),
    created_at timestamptz not null default pg_catalog.clock_timestamp(),
    check (key_id = 'ed25519-' || pg_catalog.translate(
        pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(extensions.digest(public_key,'sha256'),'base64'),'=',''),'+/','-_'
    ))
);

create table public.checkpoint_fence_witness_trust (
    witness_set_version text not null check (witness_set_version ~ '^[A-Za-z0-9._:-]{1,128}$'),
    witness_id text not null check (witness_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    key_id text not null check (key_id ~ '^ed25519-[A-Za-z0-9_-]{43}$'),
    public_key bytea not null check (pg_catalog.octet_length(public_key) = 32),
    created_at timestamptz not null default pg_catalog.clock_timestamp(),
    check (key_id = 'ed25519-' || pg_catalog.translate(
        pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(extensions.digest(public_key,'sha256'),'base64'),'=',''),'+/','-_'
    )),
    primary key (witness_set_version, witness_id),
    unique (witness_set_version, key_id),
    unique (witness_set_version, public_key)
);

alter table public.checkpoint_fence_primary_trust enable row level security;
alter table public.checkpoint_fence_witness_trust enable row level security;
revoke all on public.checkpoint_fence_primary_trust, public.checkpoint_fence_witness_trust
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;

-- The byte-oriented message builder mirrors checkpointFenceAcknowledgementMessage.
create or replace function wedecent_private.checkpoint_fence_ack_signing_bytes(p_ack jsonb)
returns bytea
language plpgsql
immutable
security definer
set search_path = ''
as $$
declare
    v_message bytea;
    v_tail text;
begin
    v_message := pg_catalog.convert_to(
        'wedecent-checkpoint-fence-ack-v1' || E'\n' ||
        pg_catalog.to_json(p_ack ->> 'witness_id')::text || E'\n',
        'UTF8'
    ) || pg_catalog.decode(p_ack ->> 'token_sha256', 'hex');

    v_tail :=
        '{"Generation":' || (p_ack ->> 'generation') ||
        ',"Action":' || pg_catalog.to_json(p_ack ->> 'action')::text ||
        ',"OperationID":' || pg_catalog.to_json(p_ack ->> 'operation_id')::text ||
        ',"WitnessKeyID":' || pg_catalog.to_json(p_ack ->> 'witness_key_id')::text ||
        ',"CommittedAtUnixMS":' || (p_ack ->> 'committed_at_unix_ms') || '}' || E'\n';

    return v_message || pg_catalog.convert_to(v_tail, 'UTF8');
end;
$$;

create or replace function wedecent_private.checkpoint_fence_commit_signing_bytes(
    p_operation_id text,
    p_fingerprint bytea,
    p_token_sha256 bytea,
    p_token jsonb,
    p_acknowledgements jsonb,
    p_actor_id uuid
)
returns bytea
language sql
immutable
security definer
set search_path = ''
as $$
    select pg_catalog.convert_to(
        'wedecent-checkpoint-fence-commit-v1' || E'\n' ||
        p_operation_id || E'\n' ||
        pg_catalog.encode(p_fingerprint, 'hex') || E'\n' ||
        pg_catalog.encode(p_token_sha256, 'hex') || E'\n' ||
        pg_catalog.encode(extensions.digest(
            pg_catalog.convert_to(wedecent_private.canonical_jsonb(p_token), 'UTF8'), 'sha256'
        ), 'hex') || E'\n' ||
        pg_catalog.encode(extensions.digest(
            pg_catalog.convert_to(wedecent_private.canonical_jsonb(p_acknowledgements), 'UTF8'), 'sha256'
        ), 'hex') || E'\n' ||
        p_actor_id::text || E'\n',
        'UTF8'
    );
$$;

-- Keep the original transactional implementations as private callees.
alter function public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)
    rename to reserve_checkpoint_fence_operation_internal;
alter function public.record_checkpoint_fence_token(text,bytea,bytea,jsonb)
    rename to record_checkpoint_fence_token_internal;
alter function public.commit_checkpoint_fence_operation(text,bytea,bytea,jsonb)
    rename to commit_checkpoint_fence_operation_internal;
alter function public.load_checkpoint_fence_operation(uuid,text)
    rename to load_checkpoint_fence_operation_internal;
alter function public.load_checkpoint_fence_head(uuid)
    rename to load_checkpoint_fence_head_internal;

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
as $fn$
declare
    v_pending_operation_id text;
    v_pending_expires_at timestamptz;
begin
    if auth.uid() is null or auth.uid() is distinct from p_actor_id then
        raise exception 'checkpoint actor authentication failed' using errcode = '42501';
    end if;
    select pending_operation_id, pending_expires_at
      into v_pending_operation_id, v_pending_expires_at
      from public.checkpoint_fence_authority
     where organization_id = p_organization_id
     for update;
    if v_pending_operation_id is not null
       and v_pending_operation_id <> p_operation_id
       and (v_pending_expires_at is null or v_pending_expires_at <= pg_catalog.clock_timestamp()) then
        raise exception 'expired checkpoint operation requires exact-operation quorum recovery'
            using errcode = '55P03';
    end if;
    return public.reserve_checkpoint_fence_operation_internal(
        p_operation_id, p_action, p_organization_id, p_actor_id, p_request_sha256,
        p_participants, p_primary_head_generation, p_primary_head_sha256, p_lease_seconds
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
    v_actor_id uuid;
    v_existing public.checkpoint_operation_events%rowtype;
begin
    select actor_id into v_actor_id from public.checkpoint_operations
     where operation_id = p_operation_id;
    if auth.uid() is null or v_actor_id is null or auth.uid() is distinct from v_actor_id then
        raise exception 'checkpoint actor authentication failed' using errcode = '42501';
    end if;
    select * into v_existing from public.checkpoint_operation_events
     where operation_id = p_operation_id and event_type = 'fence_reserved'
     order by event_id desc limit 1;
    if found and (
        v_existing.event_payload ->> 'token_sha256' is distinct from pg_catalog.encode(p_token_sha256, 'hex')
        or v_existing.event_payload -> 'token' is distinct from p_token
    ) then
        raise exception 'a persisted checkpoint reservation token cannot be replaced'
            using errcode = '23505';
    end if;
    return public.record_checkpoint_fence_token_internal(
        p_operation_id, p_fingerprint, p_token_sha256, p_token
    );
end;
$$;

create or replace function public.commit_checkpoint_fence_operation(
    p_operation_id text,
    p_fingerprint bytea,
    p_token_sha256 bytea,
    p_witness_acknowledgements jsonb,
    p_authority_signature bytea
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_operation public.checkpoint_operations%rowtype;
    v_token_event public.checkpoint_operation_events%rowtype;
    v_token jsonb;
    v_primary_key bytea;
    v_set_count integer;
    v_ack_count integer;
    v_quorum integer;
    v_distinct_count integer;
    v_signature bytea;
    v_ack jsonb;
    v_key bytea;
    v_message bytea;
begin
    if p_operation_id is null or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_fingerprint is null or pg_catalog.octet_length(p_fingerprint) <> 32
       or p_token_sha256 is null or pg_catalog.octet_length(p_token_sha256) <> 32
       or p_authority_signature is null or pg_catalog.octet_length(p_authority_signature) <> 64
       or p_witness_acknowledgements is null
       or pg_catalog.jsonb_typeof(p_witness_acknowledgements) is distinct from 'array' then
        raise exception 'invalid checkpoint authority commit' using errcode = '22023';
    end if;

    select * into v_operation from public.checkpoint_operations
     where operation_id = p_operation_id for update;
    if not found or auth.uid() is null or auth.uid() is distinct from v_operation.actor_id
       or v_operation.fingerprint is distinct from p_fingerprint then
        raise exception 'checkpoint actor or operation binding failed' using errcode = '42501';
    end if;

    select * into v_token_event from public.checkpoint_operation_events
     where operation_id = p_operation_id and event_type = 'fence_reserved'
     order by event_id desc limit 1;
    if not found
       or v_token_event.event_payload ->> 'token_sha256' is distinct from pg_catalog.encode(p_token_sha256, 'hex') then
        raise exception 'exact signed checkpoint token is unavailable' using errcode = '55000';
    end if;
    v_token := v_token_event.event_payload -> 'token';

    select public_key into v_primary_key
      from public.checkpoint_fence_primary_trust
     where key_id = v_token ->> 'primary_key_id';
    if not found then
        raise exception 'checkpoint primary trust anchor is unavailable' using errcode = '42501';
    end if;

    select pg_catalog.count(*) into v_set_count
      from public.checkpoint_fence_witness_trust
     where witness_set_version = v_token ->> 'witness_set_version';
    if v_set_count < 3 or v_set_count > 31
       or pg_catalog.jsonb_typeof(v_token -> 'witness_ids') is distinct from 'array'
       or pg_catalog.jsonb_array_length(v_token -> 'witness_ids') <> v_set_count
       or (select pg_catalog.count(distinct value #>> '{}')
             from pg_catalog.jsonb_array_elements(v_token -> 'witness_ids')) <> v_set_count
       or exists (
           select 1 from pg_catalog.jsonb_array_elements(v_token -> 'witness_ids') as item(value)
            where not exists (
                select 1 from public.checkpoint_fence_witness_trust trust
                 where trust.witness_set_version = v_token ->> 'witness_set_version'
                   and trust.witness_id = item.value #>> '{}'
            )
       ) then
        raise exception 'checkpoint token witness set does not match database trust anchors'
            using errcode = '42501';
    end if;

    v_quorum := (v_set_count / 2) + 1;
    v_ack_count := pg_catalog.jsonb_array_length(p_witness_acknowledgements);
    if v_ack_count < v_quorum or v_ack_count > v_set_count then
        raise exception 'checkpoint witness quorum is insufficient' using errcode = '22023';
    end if;

    for v_ack in select value from pg_catalog.jsonb_array_elements(p_witness_acknowledgements)
    loop
        if pg_catalog.jsonb_typeof(v_ack) is distinct from 'object'
           or (select pg_catalog.count(*) from pg_catalog.jsonb_object_keys(v_ack)) <> 8
           or v_ack ->> 'operation_id' is distinct from p_operation_id
           or v_ack ->> 'action' is distinct from v_operation.action
           or v_ack ->> 'token_sha256' is distinct from pg_catalog.encode(p_token_sha256, 'hex')
           or v_ack ->> 'generation' is distinct from v_token ->> 'generation'
           or coalesce(v_ack ->> 'committed_at_unix_ms', '') !~ '^[1-9][0-9]{0,18}$'
           or (v_ack ->> 'committed_at_unix_ms')::numeric > 9223372036854775807::numeric
           or (v_ack ->> 'committed_at_unix_ms')::bigint >
                (v_token ->> 'expires_at_unix_ms')::bigint
           or (v_ack ->> 'committed_at_unix_ms')::bigint <
                (extract(epoch from v_token_event.created_at) * 1000)::bigint
           or coalesce(v_ack ->> 'signature', '') !~ '^[A-Za-z0-9+/]{86}==$' then
            raise exception 'checkpoint acknowledgement is not bound to the original pre-expiry token'
                using errcode = '22023';
        end if;

        select public_key into v_key
          from public.checkpoint_fence_witness_trust
         where witness_set_version = v_token ->> 'witness_set_version'
           and witness_id = v_ack ->> 'witness_id'
           and key_id = v_ack ->> 'witness_key_id';
        if not found then
            raise exception 'checkpoint acknowledgement witness is not in the configured trust set'
                using errcode = '42501';
        end if;

        v_signature := pg_catalog.decode(v_ack ->> 'signature', 'base64');
        v_message := wedecent_private.checkpoint_fence_ack_signing_bytes(v_ack);
        if not pgsodium.crypto_sign_verify_detached(v_signature, v_message, v_key) then
            raise exception 'checkpoint witness signature verification failed'
                using errcode = '42501';
        end if;
    end loop;

    select pg_catalog.count(distinct item.value ->> 'witness_id')
      into v_distinct_count
      from pg_catalog.jsonb_array_elements(p_witness_acknowledgements) as item(value);
    if v_distinct_count < v_quorum or v_distinct_count <> v_ack_count then
        raise exception 'checkpoint witness quorum contains duplicates or is insufficient'
            using errcode = '22023';
    end if;

    v_message := wedecent_private.checkpoint_fence_commit_signing_bytes(
        p_operation_id, p_fingerprint, p_token_sha256, v_token,
        p_witness_acknowledgements, v_operation.actor_id
    );
    if not pgsodium.crypto_sign_verify_detached(p_authority_signature, v_message, v_primary_key) then
        raise exception 'checkpoint primary commit attestation is invalid'
            using errcode = '42501';
    end if;

    if exists (
        select 1 from public.checkpoint_operation_events
         where operation_id = p_operation_id and event_type = 'fence_committed'
    ) then
        return public.commit_checkpoint_fence_operation_internal(
            p_operation_id, p_fingerprint, p_token_sha256, p_witness_acknowledgements
        );
    end if;

    update public.checkpoint_fence_authority
       set pending_expires_at = pg_catalog.clock_timestamp() + interval '30 seconds',
           updated_at = pg_catalog.clock_timestamp()
     where organization_id = v_operation.organization_id
       and pending_operation_id = p_operation_id
       and pending_fingerprint = p_fingerprint;
    if not found then
        raise exception 'exact checkpoint operation is no longer pending'
            using errcode = '40001';
    end if;
    perform pg_catalog.set_config('wedecent.checkpoint_fence_verified', p_operation_id, true);

    return public.commit_checkpoint_fence_operation_internal(
        p_operation_id, p_fingerprint, p_token_sha256, p_witness_acknowledgements
    );
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
    v_actor_id uuid;
begin
    select actor_id into v_actor_id from public.checkpoint_operations
     where operation_id = p_operation_id and organization_id = p_organization_id;
    if auth.uid() is null or v_actor_id is null or auth.uid() is distinct from v_actor_id then
        raise exception 'checkpoint actor authentication failed' using errcode = '42501';
    end if;
    return public.load_checkpoint_fence_operation_internal(p_organization_id, p_operation_id);
end;
$$;

create or replace function public.load_checkpoint_fence_head(p_organization_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
    if auth.uid() is null or not exists (
        select 1 from public.organization_memberships membership
         where membership.organization_id = p_organization_id
           and membership.user_id = auth.uid()
    ) then
        raise exception 'checkpoint actor authentication failed' using errcode = '42501';
    end if;
    return public.load_checkpoint_fence_head_internal(p_organization_id);
end;
$$;

-- No shared service-role, anonymous, authenticated or PUBLIC entry point remains.
revoke all on function public.reserve_checkpoint_fence_operation_internal(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function public.record_checkpoint_fence_token_internal(text,bytea,bytea,jsonb)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function public.commit_checkpoint_fence_operation_internal(text,bytea,bytea,jsonb)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function public.load_checkpoint_fence_operation_internal(uuid,text)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function public.load_checkpoint_fence_head_internal(uuid)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;

revoke all on function public.reserve_checkpoint_operation(text,text,uuid,uuid,bytea,jsonb,integer)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function public.commit_checkpoint_operation(text,bytea,jsonb)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;

revoke all on function public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)
    from public, anon, authenticated, service_role;
revoke all on function public.record_checkpoint_fence_token(text,bytea,bytea,jsonb)
    from public, anon, authenticated, service_role;
revoke all on function public.commit_checkpoint_fence_operation(text,bytea,bytea,jsonb,bytea)
    from public, anon, authenticated, service_role;
revoke all on function public.load_checkpoint_fence_operation(uuid,text)
    from public, anon, authenticated, service_role;
revoke all on function public.load_checkpoint_fence_head(uuid)
    from public, anon, authenticated, service_role;

grant execute on function public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)
    to wedecent_checkpoint_authority;
grant execute on function public.record_checkpoint_fence_token(text,bytea,bytea,jsonb)
    to wedecent_checkpoint_authority;
grant execute on function public.commit_checkpoint_fence_operation(text,bytea,bytea,jsonb,bytea)
    to wedecent_checkpoint_authority;
grant execute on function public.load_checkpoint_fence_operation(uuid,text)
    to wedecent_checkpoint_authority;
grant execute on function public.load_checkpoint_fence_head(uuid)
    to wedecent_checkpoint_authority;

    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function wedecent_private.checkpoint_fence_ack_signing_bytes(jsonb)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;
revoke all on function wedecent_private.checkpoint_fence_commit_signing_bytes(text,bytea,bytea,jsonb,jsonb,uuid)
    from public, anon, authenticated, service_role, wedecent_checkpoint_authority;

comment on table public.checkpoint_fence_primary_trust is
    'Postgres-operator-provisioned Ed25519 primary trust anchors for signed checkpoint commit attestations.';
comment on table public.checkpoint_fence_witness_trust is
    'Immutable-by-privilege Ed25519 witness key registry. Each token must name the exact configured set; commit requires a cryptographically verified strict majority.';
comment on role wedecent_checkpoint_authority is
    'Dedicated PostgREST JWT role. Only the trusted server-side checkpoint authority may mint short-lived JWTs with this role and an authenticated actor sub claim.';

commit;
