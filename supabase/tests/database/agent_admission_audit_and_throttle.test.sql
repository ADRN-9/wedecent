begin;

create extension if not exists pgtap with schema extensions;

select plan(22);

select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relname = 'agent_admission_audit_events'),
    'agent admission audit events have RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relname = 'agent_admission_endpoint_rate_limits'),
    'endpoint abuse limiter has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relname = 'device_revocation_dispatch_outbox'),
    'device revocation dispatch outbox has RLS enabled'
);
select ok(
    not pg_catalog.has_table_privilege('anon', 'public.device_revocation_dispatch_outbox', 'SELECT'),
    'anon cannot read device revocation dispatch state'
);
select ok(
    not pg_catalog.has_table_privilege('anon', 'public.agent_admission_audit_events', 'SELECT'),
    'anon cannot read admission audit events'
);
select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.agent_admission_audit_events', 'INSERT'),
    'authenticated users cannot forge admission audit events'
);
select ok(
    not pg_catalog.has_table_privilege('anon', 'public.agent_admission_endpoint_rate_limits', 'UPDATE'),
    'anon cannot modify endpoint abuse limits'
);
select ok(
    pg_catalog.has_function_privilege('service_role', 'public.consume_agent_admission_endpoint_request()', 'EXECUTE'),
    'service role can consume endpoint admission quota'
);
select ok(
    not pg_catalog.has_function_privilege('anon', 'public.consume_agent_admission_endpoint_request()', 'EXECUTE'),
    'anon cannot directly consume endpoint admission quota'
);
select ok(
    pg_catalog.has_function_privilege(
        'service_role',
        'public.record_agent_admission_audit(text,text,integer,text,uuid,text)',
        'EXECUTE'
    ),
    'service role can persist admission issuance and rejection audit events'
);
select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'public.record_agent_admission_audit(text,text,integer,text,uuid,text)',
        'EXECUTE'
    ),
    'authenticated users cannot forge admission audit events'
);

insert into auth.users (id, aud, role, email)
values (
    '10000000-0000-4000-8000-000000000011',
    'authenticated',
    'authenticated',
    'agent-admission-audit-test@example.test'
);

insert into public.devices (device_id, public_key, kind, name, owner_user_id)
values (
    'wd_eeeeeeeeeeeeeeee',
    repeat('E', 43),
    'agent',
    'Admission audit test agent',
    '10000000-0000-4000-8000-000000000011'
);

select is(
    public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('E', 43),
        repeat('A', 22),
        pg_catalog.now() + interval '30 seconds'
    ),
    'accepted',
    'fresh agent proof is consumed'
);
select is(
    public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('E', 43),
        repeat('A', 22),
        pg_catalog.now() + interval '30 seconds'
    ),
    'replay',
    'replayed agent proof is rejected'
);
select is(
    (select count(*)::integer from public.agent_admission_audit_events
      where device_id = 'wd_eeeeeeeeeeeeeeee' and event_type = 'consumed' and proof_jti = repeat('A', 22)),
    1,
    'successful proof consumption is durably audited'
);
select is(
    (select count(*)::integer from public.agent_admission_audit_events
      where device_id = 'wd_eeeeeeeeeeeeeeee' and event_type = 'rejected' and reason = 'proof_replay'),
    1,
    'proof replay rejection is durably audited'
);

select public.record_agent_admission_audit(
    'wd_eeeeeeeeeeeeeeee',
    'issued',
    1,
    repeat('B', 22),
    'd90987bf-bae6-45da-ab21-c82d049617bd',
    'issued'
);
select is(
    (select count(*)::integer from public.agent_admission_audit_events
      where device_id = 'wd_eeeeeeeeeeeeeeee'
        and event_type = 'issued'
        and admission_jti = 'd90987bf-bae6-45da-ab21-c82d049617bd'),
    1,
    'issued admission capability is durably audited'
);

update public.agent_admission_endpoint_rate_limits
   set window_started_at = pg_catalog.now(),
       request_count = 999,
       updated_at = pg_catalog.now()
 where singleton is true;

select ok(
    public.consume_agent_admission_endpoint_request(),
    'endpoint limiter permits the 1,000th request in a window'
);
select ok(
    not public.consume_agent_admission_endpoint_request(),
    'endpoint limiter rejects the 1,001st request in a window'
);
select ok(
    not public.consume_agent_admission_endpoint_request(),
    'endpoint limiter continues rejecting after saturation'
);
select is(
    (select count(*)::integer from public.agent_admission_audit_events
      where event_type = 'rejected' and reason = 'rate_limited' and device_id is null),
    1,
    'endpoint saturation emits one bounded audit event per window'
);

update public.devices
   set revoked_at = pg_catalog.now()
 where device_id = 'wd_eeeeeeeeeeeeeeee';

select is(
    (select count(*)::integer from public.agent_admission_audit_events
      where device_id = 'wd_eeeeeeeeeeeeeeee' and event_type = 'revoked' and reason = 'device_revoked'),
    1,
    'device revocation is durably audited'
);
select is(
    (select count(*)::integer from public.device_revocation_dispatch_outbox
      where device_id = 'wd_eeeeeeeeeeeeeeee' and status = 'pending'),
    1,
    'device revocation creates a durable pending relay dispatch'
);

select * from finish();
rollback;
