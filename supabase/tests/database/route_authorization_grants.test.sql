begin;

create extension if not exists pgtap with schema extensions;

select plan(6);

select ok(
    exists (
        select 1
          from pg_catalog.pg_enum e
          join pg_catalog.pg_type t
            on t.oid = e.enumtypid
          join pg_catalog.pg_namespace n
            on n.oid = t.typnamespace
         where n.nspname = 'public'
           and t.typname = 'device_permission'
           and e.enumlabel = 'mesh.forward'
    ),
    'device_permission contains mesh.forward'
);

select ok(
    (
        select c.relrowsecurity
          from pg_catalog.pg_class c
          join pg_catalog.pg_namespace n
            on n.oid = c.relnamespace
         where n.nspname = 'public'
           and c.relname =
               'route_authorization_grants'
    ),
    'route_authorization_grants has RLS enabled'
);

select ok(
    not pg_catalog.has_table_privilege(
        'authenticated',
        'public.route_authorization_grants',
        'INSERT'
    ),
    'authenticated users cannot mint route authorization rows'
);

select ok(
    exists (
        select 1
          from pg_catalog.pg_proc p
          join pg_catalog.pg_namespace n
            on n.oid = p.pronamespace
         where n.nspname = 'public'
           and p.proname =
               'issue_route_authorization'
           and p.prosecdef
    ),
    'route authorization issuance RPC is SECURITY DEFINER'
);

select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'public.issue_route_authorization(uuid,text,text,text,text,text,text,bigint,bigint)',
        'EXECUTE'
    ),
    'authenticated users cannot execute route authorization RPC directly'
);

select ok(
    pg_catalog.has_function_privilege(
        'service_role',
        'public.issue_route_authorization(uuid,text,text,text,text,text,text,bigint,bigint)',
        'EXECUTE'
    ),
    'service role can execute route authorization RPC'
);

select * from finish();

rollback;
