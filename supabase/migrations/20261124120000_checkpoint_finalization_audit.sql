begin;
create or replace function wedecent_private.canonical_jsonb(p jsonb) returns text language plpgsql immutable strict set search_path='' as $$
declare r text; begin case jsonb_typeof(p)
when 'object' then select '{'||coalesce(string_agg(to_json(k)::text||':'||wedecent_private.canonical_jsonb(v),',' order by k),'')||'}' into r from jsonb_each(p) e(k,v);return r;
when 'array' then select '['||coalesce(string_agg(wedecent_private.canonical_jsonb(v),',' order by n),'')||']' into r from jsonb_array_elements(p) with ordinality e(v,n);return r;
else return p::text;end case;end $$;
revoke all on function wedecent_private.canonical_jsonb(jsonb) from public,anon,authenticated,service_role;
create table public.checkpoint_finalization_operations(operation_id text primary key check(operation_id~'^[0-9a-f]{64}$'),payload_version integer not null check(payload_version=1),payload jsonb not null,payload_sha256 bytea not null check(octet_length(payload_sha256)=32),actor_id uuid not null,created_at timestamptz not null default clock_timestamp());
create table public.checkpoint_finalization_audit(id uuid primary key default gen_random_uuid(),operation_id text not null references public.checkpoint_finalization_operations(operation_id),outcome text not null check(outcome in('finalization_started','membership_unavailable','finalization_failed','finalized','rejected_revocation')),payload_version integer not null check(payload_version=1),payload_sha256 bytea not null check(octet_length(payload_sha256)=32),actor_id uuid not null,created_at timestamptz not null default clock_timestamp(),unique(operation_id,outcome));
create index checkpoint_finalization_audit_created_idx on public.checkpoint_finalization_audit(created_at);
alter table public.checkpoint_finalization_operations enable row level security;alter table public.checkpoint_finalization_audit enable row level security;
revoke all on public.checkpoint_finalization_operations from public,anon,authenticated,service_role;revoke all on public.checkpoint_finalization_audit from public,anon,authenticated,service_role;
create or replace function public.record_checkpoint_finalization(p_operation_id text,p_outcome text,p_payload_version integer,p_payload jsonb,p_payload_sha256 bytea,p_actor_id uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_op public.checkpoint_finalization_operations%rowtype;v_event public.checkpoint_finalization_audit%rowtype;v_tx public.port_forward_authorization_transactions%rowtype;v_terminal text;v_jti text;v_i text;v_d text;v_replayed boolean:=false;
begin
if p_operation_id is null or p_operation_id!~'^[0-9a-f]{64}$' or p_outcome not in('finalization_started','membership_unavailable','finalization_failed','finalized','rejected_revocation') or p_payload_version<>1 or p_payload is null or jsonb_typeof(p_payload)<>'object' or p_actor_id is null or p_payload_sha256 is null or octet_length(p_payload_sha256)<>32 then raise exception 'invalid audit request' using errcode='22023';end if;
if extensions.digest(convert_to(wedecent_private.canonical_jsonb(p_payload),'UTF8'),'sha256')<>p_payload_sha256 then raise exception 'audit digest mismatch' using errcode='22023';end if;
v_jti:=p_payload->>'jti';v_i:=p_payload#>>'{initiator,device_id}';v_d:=p_payload#>>'{destination,device_id}';
if v_jti !~ '^[A-Za-z0-9_-]{22}$' or v_i !~ '^wd_[a-z2-7]{16}$' or v_d !~ '^wd_[a-z2-7]{16}$' then raise exception 'invalid audit participants' using errcode='22023';end if;
perform pg_advisory_xact_lock(hashtextextended(p_operation_id,0));
select t.* into v_tx from public.port_forward_authorization_transactions t where t.jti=v_jti for share;
if not found or v_tx.initiating_device_id<>v_i or v_tx.destination_device_id<>v_d or (p_payload->>'consuming_device_id' not in(v_i,v_d)) or v_tx.router_device_id is distinct from (p_payload#>>'{router,device_id}') or (v_tx.router_device_id is not null and (v_tx.router_account_id::text<>p_payload#>>'{router,account_id}' or v_tx.router_organization_id::text<>p_payload#>>'{router,organization_id}')) or encode(v_tx.authorization_sha256,'hex')<>p_payload->>'authorization_sha256' or v_tx.initiator_account_id::text<>p_payload#>>'{initiator,account_id}' or v_tx.destination_account_id::text<>p_payload#>>'{destination,account_id}' or v_tx.initiator_organization_id::text<>p_payload#>>'{initiator,organization_id}' or v_tx.destination_organization_id::text<>p_payload#>>'{destination,organization_id}' or p_actor_id not in(v_tx.initiator_account_id,v_tx.destination_account_id) or not exists(select 1 from public.organization_memberships m where m.user_id=p_actor_id and m.organization_id=case when p_actor_id=v_tx.initiator_account_id then v_tx.initiator_organization_id else v_tx.destination_organization_id end) then raise exception 'unauthorized audit actor' using errcode='42501';end if;
insert into public.checkpoint_finalization_operations values(p_operation_id,p_payload_version,p_payload,p_payload_sha256,p_actor_id,clock_timestamp()) on conflict do nothing;
select o.* into v_op from public.checkpoint_finalization_operations o where o.operation_id=p_operation_id for update;
if v_op.payload_version<>p_payload_version or v_op.payload_sha256<>p_payload_sha256 or v_op.payload<>p_payload or v_op.actor_id<>p_actor_id then raise exception 'operation payload conflict' using errcode='23505';end if;
select e.* into v_event from public.checkpoint_finalization_audit e where e.operation_id=p_operation_id and e.outcome=p_outcome;
if found then if v_event.payload_sha256<>p_payload_sha256 or v_event.actor_id<>p_actor_id then raise exception 'outcome conflict' using errcode='23505';end if;v_replayed:=true;
else select e.outcome into v_terminal from public.checkpoint_finalization_audit e where e.operation_id=p_operation_id and e.outcome in('finalized','rejected_revocation') limit 1;
if v_terminal is not null then raise exception 'contradictory terminal outcome' using errcode='23505';end if;
insert into public.checkpoint_finalization_audit(operation_id,outcome,payload_version,payload_sha256,actor_id) values(p_operation_id,p_outcome,p_payload_version,p_payload_sha256,p_actor_id) returning * into v_event;end if;
return jsonb_build_object('record_id',v_event.id::text,'operation_id',v_event.operation_id,'outcome',v_event.outcome,'created_at',v_event.created_at,'replayed',v_replayed);
end $$;
revoke all on function public.record_checkpoint_finalization(text,text,integer,jsonb,bytea,uuid) from public,anon,authenticated;
grant execute on function public.record_checkpoint_finalization(text,text,integer,jsonb,bytea,uuid) to service_role;
commit;