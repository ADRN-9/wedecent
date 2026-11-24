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
                ',' order by entry.key collate "C"
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
        when 'number' then
            if p::numeric <> pg_catalog.trunc(p::numeric)
               or p::numeric > 9007199254740991::numeric
               or p::numeric < -9007199254740991::numeric then
                raise exception 'unsafe canonical JSON number' using errcode = '22023';
            end if;
            return pg_catalog.trunc(p::numeric)::text;
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
        'finalized'
    )),
    payload_version integer not null check (payload_version = 1),
    payload_sha256 bytea not null check (pg_catalog.octet_length(payload_sha256) = 32),
    actor_id uuid not null references auth.users(id) on delete restrict,
    evidence jsonb not null,
    evidence_sha256 bytea not null check (pg_catalog.octet_length(evidence_sha256) = 32),
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
    p_evidence jsonb,
    p_evidence_sha256 bytea,
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
    v_initial_transaction public.port_forward_authorization_transactions%rowtype;
    v_terminal_outcome text;
    v_jti text;
    v_initiator text;
    v_destination text;
    v_actor_organization uuid;
    v_device_ids text[];
    v_org_ids uuid[];
    v_device public.devices%rowtype;
    v_route_grant public.route_authorization_grants%rowtype;
    v_missing_membership boolean := false;
    v_actor_membership boolean := false;
    v_replayed boolean := false;
begin
    if p_operation_id is null
       or p_operation_id !~ '^[0-9a-f]{64}$'
       or p_outcome not in (
           'finalization_started',
           'membership_unavailable',
           'finalization_failed',
           'finalized'
       )
       or p_payload_version <> 1
       or p_payload is null
       or pg_catalog.jsonb_typeof(p_payload) <> 'object'
       or p_payload ->> 'version' <> '1'
       or (select pg_catalog.count(*) from pg_catalog.jsonb_object_keys(p_payload)) <> 13
       or not (p_payload ?& array[
           'version','initiator','destination','router','consuming_device_id','jti',
           'authorization_sha256','route_authorization_sha256','route_authorization_id',
           'route_authorization_jti','route_authorization_json','device_public_key','device_signature'
       ])
       or p_actor_id is null
       or p_payload_sha256 is null
       or pg_catalog.octet_length(p_payload_sha256) <> 32
       or p_evidence is null
       or pg_catalog.jsonb_typeof(p_evidence) <> 'object'
       or p_evidence_sha256 is null
       or pg_catalog.octet_length(p_evidence_sha256) <> 32 then
        raise exception 'invalid audit request' using errcode = '22023';
    end if;

    if extensions.digest(
        pg_catalog.convert_to(wedecent_private.canonical_jsonb(p_payload), 'UTF8'),
        'sha256'
    ) <> p_payload_sha256 then
        raise exception 'audit digest mismatch' using errcode = '22023';
    end if;

    if extensions.digest(
        pg_catalog.convert_to(wedecent_private.canonical_jsonb(p_evidence), 'UTF8'),
        'sha256'
    ) <> p_evidence_sha256 then
        raise exception 'audit evidence digest mismatch' using errcode = '22023';
    end if;

    if p_outcome <> 'finalized' and p_evidence <> '{}'::jsonb then
        raise exception 'intermediate audit transition must not contain terminal evidence' using errcode = '22023';
    end if;
    if p_outcome = 'finalized' and (
        (select pg_catalog.count(*) from pg_catalog.jsonb_object_keys(p_evidence)) <> 3
        or not (p_evidence ?& array['primary_receipt','witness_acknowledgements','revocation_proofs'])
        or p_evidence = '{}'::jsonb
        or not (p_evidence ? 'primary_receipt')
        or not (p_evidence ? 'witness_acknowledgements')
        or not (p_evidence ? 'revocation_proofs')
    ) then
        raise exception 'terminal audit evidence is incomplete' using errcode = '22023';
    end if;
    if p_outcome not in ('finalization_started', 'finalization_failed', 'membership_unavailable', 'finalized') then
        raise exception 'unsupported checkpoint audit transition' using errcode = '22023';
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

    v_device_ids := array[v_initiator, v_destination];
    if p_payload #>> '{router,device_id}' is not null then
        v_device_ids := array_append(v_device_ids, p_payload #>> '{router,device_id}');
    end if;
    v_org_ids := array(
        select distinct value::uuid
          from unnest(array[
              p_payload #>> '{initiator,organization_id}',
              p_payload #>> '{destination,organization_id}',
              p_payload #>> '{router,organization_id}'
          ]) as orgs(value)
         where value is not null
         order by value::uuid
    );

    -- Match authorization issuance lock order: organizations, memberships,
    -- device access, route grant, participant devices, then transaction.
    perform organization_row.id
      from public.organizations as organization_row
     where organization_row.id = any(v_org_ids)
     order by organization_row.id
     for share;
    if (select pg_catalog.count(*) from public.organizations o where o.id = any(v_org_ids)) <> cardinality(v_org_ids) then
        raise exception 'audit participant organization is unavailable' using errcode = '42501';
    end if;

    perform membership.organization_id
      from public.organization_memberships as membership
     where (membership.user_id, membership.organization_id) in (
        ((p_payload #>> '{initiator,account_id}')::uuid, (p_payload #>> '{initiator,organization_id}')::uuid),
        ((p_payload #>> '{destination,account_id}')::uuid, (p_payload #>> '{destination,organization_id}')::uuid)
     )
        or (
          p_payload #>> '{router,device_id}' is not null
          and membership.user_id = (p_payload #>> '{router,account_id}')::uuid
          and membership.organization_id = (p_payload #>> '{router,organization_id}')::uuid
        )
     order by membership.organization_id, membership.user_id
     for share;
    v_actor_membership := exists (
        select 1 from public.organization_memberships m
         where m.user_id = p_actor_id and m.organization_id = v_actor_organization
    );
    if not v_actor_membership then
        raise exception 'audit actor membership is unavailable' using errcode = '42501';
    end if;
    v_missing_membership :=
        not exists (
            select 1 from public.organization_memberships m
             where m.user_id = (p_payload #>> '{initiator,account_id}')::uuid
               and m.organization_id = (p_payload #>> '{initiator,organization_id}')::uuid
        )
        or not exists (
            select 1 from public.organization_memberships m
             where m.user_id = (p_payload #>> '{destination,account_id}')::uuid
               and m.organization_id = (p_payload #>> '{destination,organization_id}')::uuid
        )
        or (
            p_payload #>> '{router,device_id}' is not null and not exists (
                select 1 from public.organization_memberships m
                 where m.user_id = (p_payload #>> '{router,account_id}')::uuid
                   and m.organization_id = (p_payload #>> '{router,organization_id}')::uuid
            )
        );
    if p_outcome = 'membership_unavailable' and not v_missing_membership then
        raise exception 'membership is still available' using errcode = '23505';
    elsif p_outcome <> 'membership_unavailable' and v_missing_membership then
        raise exception 'audit participant membership is unavailable' using errcode = '42501';
    end if;

    perform access.device_id
      from public.device_access as access
     where access.device_id = any(v_device_ids)
       and access.user_id = (p_payload #>> '{initiator,account_id}')::uuid
     order by access.device_id, access.permission
     for share;

    -- Read the immutable authorization transaction to discover its route grant;
    -- acquire that grant and device locks before taking the transaction row lock.
    select transaction_row.*
      into v_transaction
      from public.port_forward_authorization_transactions as transaction_row
     where transaction_row.jti = v_jti;

    if not found
       or v_transaction.initiating_device_id <> v_initiator
       or v_transaction.destination_device_id <> v_destination
       or v_transaction.router_device_id is distinct from (p_payload #>> '{router,device_id}')
       or v_transaction.initiator_account_id::text <> p_payload #>> '{initiator,account_id}'
       or v_transaction.destination_account_id::text <> p_payload #>> '{destination,account_id}'
       or v_transaction.initiator_organization_id::text <> p_payload #>> '{initiator,organization_id}'
       or v_transaction.destination_organization_id::text <> p_payload #>> '{destination,organization_id}'
       or v_transaction.initiator_revocation_epoch <> (p_payload #>> '{initiator,revocation_epoch}')::bigint
       or v_transaction.destination_revocation_epoch <> (p_payload #>> '{destination,revocation_epoch}')::bigint
       or v_transaction.router_account_id is distinct from nullif(p_payload #>> '{router,account_id}', '')::uuid
       or v_transaction.router_organization_id is distinct from nullif(p_payload #>> '{router,organization_id}', '')::uuid
       or v_transaction.router_revocation_epoch is distinct from nullif(p_payload #>> '{router,revocation_epoch}', '')::bigint
       or pg_catalog.encode(v_transaction.authorization_sha256, 'hex') <> p_payload ->> 'authorization_sha256' then
        raise exception 'unauthorized audit actor or operation scope' using errcode = '42501';
    end if;
    v_initial_transaction := v_transaction;

    if v_transaction.router_device_id is null then
        if v_transaction.route_authorization_id is not null
           or v_transaction.route_authorization_jti is not null
           or p_payload ->> 'route_authorization_sha256' <> repeat('0', 64)
           or p_payload ->> 'route_authorization_id' <> ''
           or p_payload ->> 'route_authorization_jti' <> ''
           or p_payload ->> 'route_authorization_json' <> ''
           or p_payload -> 'router' <> 'null'::jsonb then
            raise exception 'unexpected route authorization binding' using errcode = '42501';
        end if;
    else
        if p_payload ->> 'route_authorization_sha256' = repeat('0', 64)
           or p_payload ->> 'route_authorization_id' <> v_transaction.route_authorization_id::text
           or p_payload ->> 'route_authorization_jti' <> v_transaction.route_authorization_jti
           or p_payload ->> 'route_authorization_json' = ''
           or p_payload -> 'router' = 'null'::jsonb then
            raise exception 'missing route authorization binding' using errcode = '42501';
        end if;
        select grant_row.*
          into v_route_grant
          from public.route_authorization_grants as grant_row
         where grant_row.id = v_transaction.route_authorization_id
           and grant_row.jti = v_transaction.route_authorization_jti
         for share;
        if not found
           or v_route_grant.revoked_at is not null
           or v_route_grant.user_id <> v_transaction.initiator_account_id
           or v_route_grant.organization_id <> v_transaction.initiator_organization_id
           or v_route_grant.source_device_id <> v_initiator
           or v_route_grant.destination_device_id <> v_destination
           or v_route_grant.router_device_id <> v_transaction.router_device_id
           or v_route_grant.issued_at > v_transaction.issued_at
           or v_route_grant.expires_at < v_transaction.expires_at
           or v_route_grant.permission <> 'mesh.forward' then
            raise exception 'stored route authorization is unavailable or mismatched' using errcode = '42501';
        end if;
    end if;

    if (select pg_catalog.count(*) from public.devices d where d.device_id = any(v_device_ids)) <> cardinality(v_device_ids) then
        raise exception 'audit participant device is unavailable' using errcode = '42501';
    end if;

    for v_device in
        select device_row.*
          from public.devices as device_row
         where device_row.device_id = any(v_device_ids)
         order by device_row.device_id
         for share
    loop
        if v_device.device_id = v_initiator then
            if v_device.owner_user_id::text <> p_payload #>> '{initiator,account_id}'
               or v_device.organization_id::text <> p_payload #>> '{initiator,organization_id}'
               or v_device.revocation_epoch <> (p_payload #>> '{initiator,revocation_epoch}')::bigint
               or v_device.revoked_at is not null then
                raise exception 'initiator device membership or revocation changed' using errcode = '42501';
            end if;
        elsif v_device.device_id = v_destination then
            if v_device.owner_user_id::text <> p_payload #>> '{destination,account_id}'
               or v_device.organization_id::text <> p_payload #>> '{destination,organization_id}'
               or v_device.revocation_epoch <> (p_payload #>> '{destination,revocation_epoch}')::bigint
               or v_device.revoked_at is not null then
                raise exception 'destination device membership or revocation changed' using errcode = '42501';
            end if;
        else
            if v_device.owner_user_id::text <> p_payload #>> '{router,account_id}'
               or v_device.organization_id::text <> p_payload #>> '{router,organization_id}'
               or v_device.revocation_epoch <> (p_payload #>> '{router,revocation_epoch}')::bigint
               or v_device.revoked_at is not null then
                raise exception 'router device membership or revocation changed' using errcode = '42501';
            end if;
        end if;
    end loop;

    if not exists (
        select 1 from public.device_access access
         where access.user_id = v_transaction.initiator_account_id
           and access.device_id = v_destination
           and access.permission::text = v_transaction.permission::text
    ) or (
        v_transaction.router_device_id is not null and not exists (
            select 1 from public.device_access access
             where access.user_id = v_transaction.initiator_account_id
               and access.device_id = v_transaction.router_device_id
               and access.permission::text = 'mesh.forward'
        )
    ) then
        raise exception 'audit device access has been revoked' using errcode = '42501';
    end if;

    select transaction_row.*
      into v_transaction
      from public.port_forward_authorization_transactions as transaction_row
     where transaction_row.jti = v_jti
     for share;
    if not found or v_transaction is distinct from v_initial_transaction then
        raise exception 'authorization transaction changed during audit binding' using errcode = '40001';
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
           or v_event.actor_id <> p_actor_id
           or v_event.evidence <> p_evidence
           or v_event.evidence_sha256 <> p_evidence_sha256 then
            raise exception 'outcome conflict' using errcode = '23505';
        end if;
        v_replayed := true;
    else
        select event_row.outcome
          into v_terminal_outcome
          from public.checkpoint_finalization_audit as event_row
         where event_row.operation_id = p_operation_id
           and event_row.outcome = 'finalized'
         limit 1;

        if v_terminal_outcome is not null then
            raise exception 'contradictory terminal outcome' using errcode = '23505';
        end if;

        if p_outcome = 'finalized' and not exists (
            select 1 from public.checkpoint_finalization_audit
             where operation_id = p_operation_id and outcome = 'finalization_started'
        ) then
            raise exception 'completion requires a started operation' using errcode = '23505';
        end if;
        if p_outcome in ('finalization_failed', 'membership_unavailable') and not exists (
            select 1 from public.checkpoint_finalization_audit
             where operation_id = p_operation_id and outcome = 'finalization_started'
        ) then
            raise exception 'failure transition requires a started operation' using errcode = '23505';
        end if;
        insert into public.checkpoint_finalization_audit (
            operation_id, outcome, payload_version, payload_sha256, actor_id, evidence, evidence_sha256
        )
        values (p_operation_id, p_outcome, p_payload_version, p_payload_sha256, p_actor_id, p_evidence, p_evidence_sha256)
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

revoke all on function public.record_checkpoint_finalization(text, text, integer, jsonb, bytea, jsonb, bytea, uuid)
    from public, anon, authenticated;
grant execute on function public.record_checkpoint_finalization(text, text, integer, jsonb, bytea, jsonb, bytea, uuid)
    to service_role;

comment on table public.checkpoint_finalization_operations is
    'Immutable canonical checkpoint-finalization request and authenticated actor binding.';
comment on table public.checkpoint_finalization_audit is
    'Append-only durable checkpoint-finalization outcome events with mutually exclusive terminal states.';

commit;
