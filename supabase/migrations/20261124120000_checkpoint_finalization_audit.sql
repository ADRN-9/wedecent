begin;

create or replace function wedecent_private.canonical_jsonb(p jsonb)
returns text
language plpgsql
immutable
strict
set search_path = ''
as $$
declare
    result text;
begin
    case pg_catalog.jsonb_typeof(p)
        when 'object' then
            select '{' || coalesce(pg_catalog.string_agg(
                pg_catalog.to_json(entry.key)::text || ':' ||
                wedecent_private.canonical_jsonb(entry.value),
                ',' order by entry.key
            ), '') || '}'
              into result
              from pg_catalog.jsonb_each(p) as entry;
            return result;
        when 'array' then
            select '[' || coalesce(pg_catalog.string_agg(
                wedecent_private.canonical_jsonb(entry.value),
                ',' order by entry.ordinality
            ), '') || ']'
              into result
              from pg_catalog.jsonb_array_elements(p) with ordinality as entry(value, ordinality);
            return result;
        else
            return p::text;
    end case;
end;
$$;

revoke all on function wedecent_private.canonical_jsonb(jsonb)
    from public, anon, authenticated, service_role;

create table public.checkpoint_finalization_operations (
    operation_id text primary key
        check (operation_id ~ '^[0-9a-f]{64}$'),
    payload_version integer not null check (payload_version = 1),
    payload jsonb not null,
    payload_sha256 bytea not null check (pg_catalog.octet_length(payload_sha256) = 32),
    actor_id uuid not null references auth.users(id) on delete restrict,
    created_at timestamptz not null default pg_catalog.clock_timestamp()
);

create table public.checkpoint_finalization_audit (
    id uuid primary key default gen_random_uuid(),
    operation_id text not null references public.checkpoint_finalization_operations(operation_id),
    outcome text not null check (outcome in (
        'finalization_started',
        'membership_unavailable',
        'finalization_failed',
        'finalized',
        'rejected_revocation'
    )),
    payload_version integer not null check (payload_version = 1),
    payload_sha256 bytea not null check (pg_catalog.octet_length(payload_sha256) = 32),
    actor_id uuid not null references auth.users(id) on delete restrict,
    created_at timestamptz not null default pg_catalog.clock_timestamp(),
    unique (operation_id, outcome)
);

create index checkpoint_finalization_audit_created_idx
    on public.checkpoint_finalization_audit (created_at);

alter table public.checkpoint_finalization_operations enable row level security;
alter table public.checkpoint_finalization_audit enable row level security;

revoke all on public.checkpoint_finalization_operations
    from public, anon, authenticated, service_role;
revoke all on public.checkpoint_finalization_audit
    from public, anon, authenticated, service_role;

create or replace function public.record_checkpoint_finalization(
    p_operation_id text,
    p_outcome text,
    p_payload_version integer,
    p_payload jsonb,
    p_payload_sha256 bytea,
    p_actor_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_operation public.checkpoint_finalization_operations%rowtype;
    v_event public.checkpoint_finalization_audit%rowtype;
    v_transaction public.port_forward_authorization_transactions%rowtype;
    v_terminal_outcome text;
    v_jti text;
    v_initiator text;
    v_destination text;
    v_actor_organization uuid;
    v_replayed boolean := false;
begin
    if p_operation_id is null
       or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_outcome not in (
           'finalization_started',
           'membership_unavailable',
           'finalization_failed',
           'finalized',
           'rejected_revocation'
       )
       or p_payload_version <> 1
       or p_payload is null
       or pg_catalog.jsonb_typeof(p_payload) <> 'object'
       or p_actor_id is null
       or p_payload_sha256 is null
       or pg_catalog.octet_length(p_payload_sha256) <> 32 then
        raise exception 'invalid audit request' using errcode = '22023';
    end if;

    if extensions.digest(
        pg_catalog.convert_to(wedecent_private.canonical_jsonb(p_payload), 'UTF8'),
        'sha256'
    ) <> p_payload_sha256 then
        raise exception 'audit digest mismatch' using errcode = '22023';
    end if;

    v_jti := p_payload ->> 'jti';
    v_initiator := p_payload #>> '{initiator,device_id}';
    v_destination := p_payload #>> '{destination,device_id}';

    if v_jti is null or v_jti !~ '^[A-Za-z0-9_-]{22}$'
       or v_initiator is null or v_initiator !~ '^wd_[a-z2-7]{16}$'
       or v_destination is null or v_destination !~ '^wd_[a-z2-7]{16}$'
       or coalesce(p_payload ->> 'consuming_device_id', '') not in (v_initiator, v_destination)
       or p_payload #>> '{initiator,account_id}' !~ '^[0-9a-f-]{36}$'
       or p_payload #>> '{destination,account_id}' !~ '^[0-9a-f-]{36}$'
       or p_payload #>> '{initiator,organization_id}' !~ '^[0-9a-f-]{36}$'
       or p_payload #>> '{destination,organization_id}' !~ '^[0-9a-f-]{36}$' then
        raise exception 'invalid audit participant scope' using errcode = '22023';
    end if;

    if p_actor_id::text = p_payload #>> '{initiator,account_id}' then
        v_actor_organization := (p_payload #>> '{initiator,organization_id}')::uuid;
    elsif p_actor_id::text = p_payload #>> '{destination,account_id}' then
        v_actor_organization := (p_payload #>> '{destination,organization_id}')::uuid;
    else
        raise exception 'unauthorized audit actor' using errcode = '42501';
    end if;

    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_operation_id, 0));

    -- Keep the organization -> membership -> authorization-transaction lock order.
    perform 1
      from public.organizations as organization_row
     where organization_row.id = v_actor_organization
     for share;
    if not found then
        raise exception 'audit organization is unavailable' using errcode = '42501';
    end if;

    perform 1
      from public.organization_memberships as membership
     where membership.user_id = p_actor_id
       and membership.organization_id = v_actor_organization
     for share;
    if not found then
        raise exception 'audit actor membership is unavailable' using errcode = '42501';
    end if;

    select transaction_row.*
      into v_transaction
      from public.port_forward_authorization_transactions as transaction_row
     where transaction_row.jti = v_jti
     for share;

    if not found
       or v_transaction.initiating_device_id <> v_initiator
       or v_transaction.destination_device_id <> v_destination
       or v_transaction.router_device_id is distinct from (p_payload #>> '{router,device_id}')
       or (
           v_transaction.router_device_id is not null
           and (
               v_transaction.router_account_id::text <> p_payload #>> '{router,account_id}'
               or v_transaction.router_organization_id::text <> p_payload #>> '{router,organization_id}'
           )
       )
       or pg_catalog.encode(v_transaction.authorization_sha256, 'hex') <> p_payload ->> 'authorization_sha256'
       or v_transaction.initiator_account_id::text <> p_payload #>> '{initiator,account_id}'
       or v_transaction.destination_account_id::text <> p_payload #>> '{destination,account_id}'
       or v_transaction.initiator_organization_id::text <> p_payload #>> '{initiator,organization_id}'
       or v_transaction.destination_organization_id::text <> p_payload #>> '{destination,organization_id}' then
        raise exception 'unauthorized audit actor or operation scope' using errcode = '42501';
    end if;

    insert into public.checkpoint_finalization_operations (
        operation_id, payload_version, payload, payload_sha256, actor_id
    )
    values (p_operation_id, p_payload_version, p_payload, p_payload_sha256, p_actor_id)
    on conflict (operation_id) do nothing;

    select operation_row.*
      into v_operation
      from public.checkpoint_finalization_operations as operation_row
     where operation_row.operation_id = p_operation_id
     for update;

    if v_operation.payload_version <> p_payload_version
       or v_operation.payload_sha256 <> p_payload_sha256
       or v_operation.payload <> p_payload
       or v_operation.actor_id <> p_actor_id then
        raise exception 'operation payload conflict' using errcode = '23505';
    end if;

    select event_row.*
      into v_event
      from public.checkpoint_finalization_audit as event_row
     where event_row.operation_id = p_operation_id
       and event_row.outcome = p_outcome;

    if found then
        if v_event.payload_sha256 <> p_payload_sha256
           or v_event.payload_version <> p_payload_version
           or v_event.actor_id <> p_actor_id then
            raise exception 'outcome conflict' using errcode = '23505';
        end if;
        v_replayed := true;
    else
        select event_row.outcome
          into v_terminal_outcome
          from public.checkpoint_finalization_audit as event_row
         where event_row.operation_id = p_operation_id
           and event_row.outcome in ('finalized', 'rejected_revocation')
         limit 1;

        if v_terminal_outcome is not null then
            raise exception 'contradictory terminal outcome' using errcode = '23505';
        end if;

        insert into public.checkpoint_finalization_audit (
            operation_id, outcome, payload_version, payload_sha256, actor_id
        )
        values (p_operation_id, p_outcome, p_payload_version, p_payload_sha256, p_actor_id)
        returning * into v_event;
    end if;

    return pg_catalog.jsonb_build_object(
        'record_id', v_event.id::text,
        'operation_id', v_event.operation_id,
        'outcome', v_event.outcome,
        'created_at', v_event.created_at,
        'replayed', v_replayed
    );
end;
$$;

revoke all on function public.record_checkpoint_finalization(text, text, integer, jsonb, bytea, uuid)
    from public, anon, authenticated;
grant execute on function public.record_checkpoint_finalization(text, text, integer, jsonb, bytea, uuid)
    to service_role;

comment on table public.checkpoint_finalization_operations is
    'Immutable canonical checkpoint-finalization request and authenticated actor binding.';
comment on table public.checkpoint_finalization_audit is
    'Append-only durable checkpoint-finalization outcome events with mutually exclusive terminal states.';

commit;
