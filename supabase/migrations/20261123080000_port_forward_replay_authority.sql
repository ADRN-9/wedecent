-- Independent, append-only replay authority for port-forward capabilities.
-- The endpoint service account never receives direct table or reset privileges.

begin;

create extension if not exists pgcrypto with schema extensions;

create table public.port_forward_replay_authority (
    device_id text primary key,
    generation bigint not null,
    state_hash bytea not null,
    updated_at timestamptz not null default pg_catalog.clock_timestamp(),
    constraint port_forward_replay_authority_device_id
        check (device_id ~ '^wd_[a-z2-7]{16}$'),
    constraint port_forward_replay_authority_generation
        check (generation >= 0),
    constraint port_forward_replay_authority_hash
        check (pg_catalog.octet_length(state_hash) = 32)
);

create table public.port_forward_replay_entries (
    device_id text not null,
    jti text not null,
    generation bigint not null,
    authorization_sha256 bytea not null,
    previous_state_hash bytea not null,
    state_hash bytea not null,
    expires_at timestamptz not null,
    consumed_at timestamptz not null default pg_catalog.clock_timestamp(),
    primary key (device_id, jti),
    unique (device_id, generation),
    constraint port_forward_replay_entry_device_id
        check (device_id ~ '^wd_[a-z2-7]{16}$'),
    constraint port_forward_replay_entry_jti
        check (jti ~ '^[A-Za-z0-9_-]{22}$'),
    constraint port_forward_replay_entry_generation
        check (generation > 0),
    constraint port_forward_replay_entry_digests
        check (
            pg_catalog.octet_length(authorization_sha256) = 32
            and pg_catalog.octet_length(previous_state_hash) = 32
            and pg_catalog.octet_length(state_hash) = 32
        )
);

create index port_forward_replay_entries_expiry_idx
    on public.port_forward_replay_entries (expires_at);

alter table public.port_forward_replay_authority enable row level security;
alter table public.port_forward_replay_entries enable row level security;

-- Even service_role may only append through the SECURITY DEFINER transaction.
-- No Data API role receives direct SELECT, INSERT, UPDATE, or DELETE access.
revoke all on public.port_forward_replay_authority
    from public, anon, authenticated, service_role;
revoke all on public.port_forward_replay_entries
    from public, anon, authenticated, service_role;

create or replace function public.consume_port_forward_authorization(
    p_device_id text,
    p_jti text,
    p_expires_at timestamptz,
    p_authorization_sha256 bytea
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    device public.devices%rowtype;
    authority public.port_forward_replay_authority%rowtype;
    prior_entry public.port_forward_replay_entries%rowtype;
    duplicate_entry public.port_forward_replay_entries%rowtype;
    now_at timestamptz := pg_catalog.clock_timestamp();
    initial_hash bytea;
    expected_latest_hash bytea;
    next_generation bigint;
    next_hash bytea;
begin
    if p_device_id is null
       or p_device_id !~ '^wd_[a-z2-7]{16}$'
       or p_jti is null
       or p_jti !~ '^[A-Za-z0-9_-]{22}$'
       or p_expires_at is null
       or p_authorization_sha256 is null
       or pg_catalog.octet_length(p_authorization_sha256) <> 32 then
        raise exception 'invalid port-forward replay request'
            using errcode = '22023';
    end if;

    if p_expires_at <= now_at
       or p_expires_at > now_at + interval '120 seconds' then
        raise exception 'port-forward authorization is expired or too long-lived'
            using errcode = '22023';
    end if;

    select d.*
      into device
      from public.devices as d
     where d.device_id = p_device_id
     for share;

    if not found or device.revoked_at is not null then
        raise exception 'port-forward replay device is not active'
            using errcode = '42501';
    end if;

    initial_hash := extensions.digest(
        pg_catalog.convert_to(
            'wedecent-port-forward-replay-authority-v1'
            || E'\n' || p_device_id || E'\n0\n',
            'UTF8'
        ),
        'sha256'
    );

    insert into public.port_forward_replay_authority (
        device_id,
        generation,
        state_hash
    )
    values (p_device_id, 0, initial_hash)
    on conflict (device_id) do nothing;

    select a.*
      into authority
      from public.port_forward_replay_authority as a
     where a.device_id = p_device_id
     for update;

    if not found then
        raise exception 'port-forward replay authority state is unavailable'
            using errcode = '55000';
    end if;

    if authority.generation = 0 then
        if authority.state_hash <> initial_hash
           or exists (
               select 1
                 from public.port_forward_replay_entries as e
                where e.device_id = p_device_id
           ) then
            raise exception 'port-forward replay authority state integrity mismatch'
                using errcode = '55000';
        end if;
    else
        select e.*
          into prior_entry
          from public.port_forward_replay_entries as e
         where e.device_id = p_device_id
           and e.generation = authority.generation;

        if not found then
            raise exception 'port-forward replay authority state integrity mismatch'
                using errcode = '55000';
        end if;

        expected_latest_hash := extensions.digest(
            prior_entry.previous_state_hash
            || pg_catalog.int8send(prior_entry.generation)
            || pg_catalog.convert_to(prior_entry.jti, 'UTF8')
            || prior_entry.authorization_sha256,
            'sha256'
        );

        if prior_entry.state_hash <> authority.state_hash
           or prior_entry.state_hash <> expected_latest_hash then
            raise exception 'port-forward replay authority state integrity mismatch'
                using errcode = '55000';
        end if;

        if authority.generation = 1 then
            if prior_entry.previous_state_hash <> initial_hash then
                raise exception 'port-forward replay authority chain mismatch'
                    using errcode = '55000';
            end if;
        else
            select e.*
              into duplicate_entry
              from public.port_forward_replay_entries as e
             where e.device_id = p_device_id
               and e.generation = authority.generation - 1;

            if not found
               or prior_entry.previous_state_hash <> duplicate_entry.state_hash then
                raise exception 'port-forward replay authority chain mismatch'
                    using errcode = '55000';
            end if;
        end if;
    end if;

    select e.*
      into duplicate_entry
      from public.port_forward_replay_entries as e
     where e.device_id = p_device_id
       and e.jti = p_jti;

    if found then
        return pg_catalog.jsonb_build_object(
            'accepted', false,
            'reason', case
                when duplicate_entry.authorization_sha256 = p_authorization_sha256
                    then 'replay'
                else 'authorization-conflict'
            end,
            'generation', authority.generation::text,
            'state_hash', pg_catalog.encode(authority.state_hash, 'hex')
        );
    end if;

    if authority.generation = 9223372036854775807 then
        raise exception 'port-forward replay authority generation exhausted'
            using errcode = '55000';
    end if;

    next_generation := authority.generation + 1;
    next_hash := extensions.digest(
        authority.state_hash
        || pg_catalog.int8send(next_generation)
        || pg_catalog.convert_to(p_jti, 'UTF8')
        || p_authorization_sha256,
        'sha256'
    );

    insert into public.port_forward_replay_entries (
        device_id,
        jti,
        generation,
        authorization_sha256,
        previous_state_hash,
        state_hash,
        expires_at
    )
    values (
        p_device_id,
        p_jti,
        next_generation,
        p_authorization_sha256,
        authority.state_hash,
        next_hash,
        p_expires_at
    );

    update public.port_forward_replay_authority
       set generation = next_generation,
           state_hash = next_hash,
           updated_at = pg_catalog.clock_timestamp()
     where device_id = p_device_id;

    return pg_catalog.jsonb_build_object(
        'accepted', true,
        'generation', next_generation::text,
        'state_hash', pg_catalog.encode(next_hash, 'hex')
    );
end;
$$;

revoke all on function public.consume_port_forward_authorization(text, text, timestamptz, bytea)
    from public, anon, authenticated;
grant execute on function public.consume_port_forward_authorization(text, text, timestamptz, bytea)
    to service_role;

comment on table public.port_forward_replay_authority is
    'Service-role-inaccessible monotonic per-device replay generation and SHA-256 chain head. Updated only by consume_port_forward_authorization.';
comment on table public.port_forward_replay_entries is
    'Append-only per-device consumed capability ledger. Unique (device_id,jti) prevents replay after local filesystem rollback.';
comment on function public.consume_port_forward_authorization(text, text, timestamptz, bytea) is
    'Atomically consumes a control-plane-verified port-forward JTI, appends a device-scoped generation/hash-chain record, and rejects duplicate JTIs. No reset or delete operation is exposed.';

commit;
