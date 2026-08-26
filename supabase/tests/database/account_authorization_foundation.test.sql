begin;

create extension if not exists pgtap with schema extensions;

select plan(22);

select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'organizations'),
    'organizations has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'organization_memberships'),
    'organization_memberships has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'devices'),
    'devices has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'device_access'),
    'device_access has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'device_enrollment_challenges'),
    'device_enrollment_challenges has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'connection_grants'),
    'connection_grants has RLS enabled'
);

select ok(
    not pg_catalog.has_table_privilege('anon', 'public.organizations', 'SELECT'),
    'anon cannot read organizations'
);
select ok(
    not pg_catalog.has_table_privilege('anon', 'public.devices', 'SELECT'),
    'anon cannot read devices'
);
select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.devices', 'INSERT'),
    'authenticated users cannot directly enroll devices'
);
select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.device_enrollment_challenges', 'SELECT'),
    'authenticated users cannot read enrollment challenge state'
);
select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.connection_grants', 'INSERT'),
    'authenticated users cannot mint connection-grant audit rows'
);
select ok(
    pg_catalog.has_table_privilege('authenticated', 'public.organizations', 'SELECT'),
    'authenticated users have the table grant needed for organization RLS'
);

select is(
    (
        select count(*)::bigint
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'wedecent_private'
          and p.prosecdef
          and p.proname in (
              'organization_role_for',
              'is_organization_member',
              'can_manage_organization',
              'is_organization_owner',
              'organization_has_other_owner',
              'bootstrap_organization_owner',
              'can_manage_device',
              'can_view_device',
              'can_connect_device'
          )
    ),
    9::bigint,
    'expected authorization and bootstrap functions are SECURITY DEFINER'
);

select ok(
    exists (
        select 1
        from pg_catalog.pg_trigger t
        join pg_catalog.pg_class c on c.oid = t.tgrelid
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
          and c.relname = 'organizations'
          and t.tgname = 'organizations_bootstrap_owner'
          and not t.tgisinternal
          and t.tgenabled <> 'D'
    ),
    'organization owner bootstrap trigger is installed and enabled'
);

select ok(
    not exists (
        select 1
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'wedecent_private'
          and p.proname = 'can_bootstrap_organization'
    ),
    'obsolete client bootstrap helper is removed'
);

select ok(
    exists (
        select 1
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
          and p.proname = 'complete_device_enrollment'
          and p.prosecdef
    ),
    'device enrollment completion RPC is SECURITY DEFINER'
);

select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'public.complete_device_enrollment(uuid,uuid,text,text,public.device_kind,text,uuid,text)',
        'EXECUTE'
    ),
    'authenticated users cannot execute device enrollment completion RPC'
);

select ok(
    pg_catalog.has_function_privilege(
        'service_role',
        'public.complete_device_enrollment(uuid,uuid,text,text,public.device_kind,text,uuid,text)',
        'EXECUTE'
    ),
    'service role can execute device enrollment completion RPC'
);

select ok(
    exists (
        select 1
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
          and p.proname = 'issue_connection_grant'
          and p.prosecdef
    ),
    'connection grant issuance RPC is SECURITY DEFINER'
);

select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'public.issue_connection_grant(uuid,text,text)',
        'EXECUTE'
    ),
    'authenticated users cannot execute connection grant issuance RPC directly'
);

select ok(
    pg_catalog.has_function_privilege(
        'service_role',
        'public.issue_connection_grant(uuid,text,text)',
        'EXECUTE'
    ),
    'service role can execute connection grant issuance RPC'
);

select is(
    (
        select count(*)::bigint
        from pg_catalog.pg_policies
        where schemaname = 'public'
          and tablename in (
              'organizations',
              'organization_memberships',
              'devices',
              'device_access',
              'device_enrollment_challenges',
              'connection_grants'
          )
    ),
    14::bigint,
    'expected account-authorization RLS policy set is installed'
);

select * from finish();
rollback;
