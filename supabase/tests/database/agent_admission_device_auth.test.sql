begin;

create extension if not exists pgtap with schema extensions;

select plan(11);

select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'agent_admission_proof_replays'),
    'agent admission proof replay table has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'agent_admission_rate_limits'),
    'agent admission rate-limit table has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'agent_admission_global_rate_limits'),
    'aggregate agent admission rate-limit table has RLS enabled'
);
select ok(
    not pg_catalog.has_table_privilege('anon', 'public.agent_admission_proof_replays', 'SELECT'),
    'anon cannot read agent admission proof replay state'
);
select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.agent_admission_global_rate_limits', 'UPDATE'),
    'authenticated users cannot modify aggregate agent admission rate limits'
);
select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.agent_admission_rate_limits', 'INSERT'),
    'authenticated users cannot modify agent admission rate limits'
);
select ok(
    exists (
        select 1 from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
          and p.proname = 'consume_agent_admission_proof'
          and p.prosecdef
    ),
    'agent proof consumption RPC is SECURITY DEFINER'
);
select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'public.consume_agent_admission_proof(text,text,text,timestamp with time zone)',
        'EXECUTE'
    ),
    'authenticated users cannot consume agent proof nonces'
);
select ok(
    pg_catalog.has_function_privilege(
        'service_role',
        'public.consume_agent_admission_proof(text,text,text,timestamp with time zone)',
        'EXECUTE'
    ),
    'service role can atomically consume agent proof nonces'
);
select ok(
    exists (
        select 1 from pg_catalog.pg_indexes
        where schemaname = 'public'
          and tablename = 'agent_admission_proof_replays'
          and indexname = 'agent_admission_proof_replays_expiry_idx'
    ),
    'agent proof replay cleanup index is installed'
);
select ok(
    exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'agent_admission_proof_jti_format'
          and conrelid = 'public.agent_admission_proof_replays'::regclass
    ),
    'agent proof nonce format is constrained'
);

select * from finish();
rollback;
