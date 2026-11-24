begin;
create or replace function wedecent_private.checkpoint_participant_vector_encoding(p_participants jsonb)
returns bytea language plpgsql immutable strict parallel safe security invoker set search_path=''
as $$
declare
 v_result bytea:=pg_catalog.convert_to('wedecent-checkpoint-participant-vector-v1','UTF8')||pg_catalog.decode('00','hex');
 v jsonb;d text;a text;o text;e bigint;g bigint;h bytea;n integer;
begin
 if pg_catalog.jsonb_typeof(p_participants)<>'array' then raise exception 'participant vector must be array' using errcode='22023';end if;
 n:=pg_catalog.jsonb_array_length(p_participants);if n<1 then raise exception 'empty participant vector' using errcode='22023';end if;
 if exists(select 1 from pg_catalog.jsonb_array_elements(p_participants) x(value) where pg_catalog.jsonb_typeof(x.value)<>'object' or pg_catalog.jsonb_object_length(x.value)<>6 or not(x.value ?& array['device_id','account_id','organization_id','revocation_epoch','head_generation','head_hash'])) then raise exception 'malformed participant' using errcode='22023';end if;
 if exists(select 1 from pg_catalog.jsonb_array_elements(p_participants) x(value) group by (x.value->>'device_id') collate "C" having pg_catalog.count(*)>1) then raise exception 'duplicate participant' using errcode='22023';end if;
 if exists(select 1 from pg_catalog.jsonb_array_elements(p_participants) x(value) where x.value->>'device_id' !~ '^wd_[a-z2-7]{16}$' or x.value->>'account_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' or x.value->>'organization_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' or x.value->>'revocation_epoch' !~ '^(0|[1-9][0-9]*)$' or x.value->>'head_generation' !~ '^(0|[1-9][0-9]*)$' or x.value->>'head_hash' !~ '^[0-9a-f]{64}$') then raise exception 'invalid identity or counters' using errcode='22023';end if;
 if (select pg_catalog.count(distinct x.value->>'organization_id') from pg_catalog.jsonb_array_elements(p_participants) x(value))<>1 then raise exception 'mixed organizations' using errcode='22023';end if;
 v_result:=v_result||pg_catalog.int4send(n);
 for v in select x.value from pg_catalog.jsonb_array_elements(p_participants) x(value) order by (x.value->>'device_id') collate "C" loop
  d:=v->>'device_id';a:=v->>'account_id';o:=v->>'organization_id';e:=(v->>'revocation_epoch')::bigint;g:=(v->>'head_generation')::bigint;h:=pg_catalog.decode(v->>'head_hash','hex');
  if (g=0 and h<>pg_catalog.decode(repeat('00',32),'hex')) or (g>0 and h=pg_catalog.decode(repeat('00',32),'hex')) then raise exception 'head generation/hash mismatch' using errcode='22023';end if;
  v_result:=v_result||pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(d,'UTF8')))||pg_catalog.convert_to(d,'UTF8')||pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(a,'UTF8')))||pg_catalog.convert_to(a,'UTF8')||pg_catalog.int4send(pg_catalog.octet_length(pg_catalog.convert_to(o,'UTF8')))||pg_catalog.convert_to(o,'UTF8')||pg_catalog.int8send(e)||pg_catalog.int8send(g)||h;
 end loop;return v_result;
exception when numeric_value_out_of_range then raise exception 'participant counter overflow' using errcode='22003';
end $$;
create or replace function wedecent_private.checkpoint_participant_vector_hash(p_participants jsonb)
returns bytea language sql immutable strict parallel safe security invoker set search_path=''
as $$ select extensions.digest(wedecent_private.checkpoint_participant_vector_encoding(p_participants),'sha256') $$;
-- Pure comparator only. The authoritative argument must come from rows locked by the calling transaction.
create or replace function wedecent_private.checkpoint_v1_transition_matches(p_claimed jsonb,p_authoritative_locked_heads jsonb)
returns boolean language sql immutable strict parallel safe security invoker set search_path=''
as $$ select wedecent_private.checkpoint_participant_vector_encoding(p_claimed)=wedecent_private.checkpoint_participant_vector_encoding(p_authoritative_locked_heads) $$;
create or replace function wedecent_private.checkpoint_event_v2_encoding_from_participants(p_action text,p_scope_kind text,p_device_id text,p_account_id text,p_organization_id text,p_operation_id text,p_request_sha256 bytea,p_participants jsonb,p_previous_hash bytea,p_generation bigint,p_revocation_epoch bigint)
returns bytea language plpgsql immutable strict parallel safe security invoker set search_path=''
as $$
declare
 v_participant_digest bytea;
begin
 v_participant_digest:=wedecent_private.checkpoint_participant_vector_hash(p_participants);
 if exists(select 1 from pg_catalog.jsonb_array_elements(p_participants) x(value)
   where x.value->>'organization_id'<>p_organization_id) then
  raise exception 'participant organization does not match event scope' using errcode='22023';
 end if;
 if p_scope_kind='device' and not exists(
   select 1 from pg_catalog.jsonb_array_elements(p_participants) x(value)
   where x.value->>'device_id'=p_device_id
     and x.value->>'account_id'=p_account_id
     and x.value->>'organization_id'=p_organization_id
     and (x.value->>'revocation_epoch')::bigint=p_revocation_epoch) then
  raise exception 'device event scope or epoch is absent from participant vector' using errcode='22023';
 end if;
 return wedecent_private.checkpoint_event_v2_encoding(
   p_action,p_scope_kind,p_device_id,p_account_id,p_organization_id,p_operation_id,
   p_request_sha256,v_participant_digest,p_previous_hash,p_generation,p_revocation_epoch);
end $$;
revoke all on function wedecent_private.checkpoint_participant_vector_encoding(jsonb) from public,anon,authenticated,service_role;
revoke all on function wedecent_private.checkpoint_participant_vector_hash(jsonb) from public,anon,authenticated,service_role;
revoke all on function wedecent_private.checkpoint_v1_transition_matches(jsonb,jsonb) from public,anon,authenticated,service_role;
revoke all on function wedecent_private.checkpoint_event_v2_encoding_from_participants(text,text,text,text,text,text,bytea,jsonb,bytea,bigint,bigint) from public,anon,authenticated,service_role;
commit;
