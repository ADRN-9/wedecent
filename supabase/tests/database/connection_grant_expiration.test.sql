\set ON_ERROR_STOP 1

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;

SELECT plan(3);

SELECT ok(
  has_function_privilege(
    'service_role',
    'public.issue_connection_grant(uuid,text,text)'::regprocedure,
    'EXECUTE'
  ),
  'service_role can issue connection grants'
);

SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.issue_connection_grant(uuid,text,text)'::regprocedure,
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'anon',
    'public.issue_connection_grant(uuid,text,text)'::regprocedure,
    'EXECUTE'
  ),
  'authenticated and anon cannot execute the service-role grant issuer'
);

SELECT ok(
  pg_get_functiondef('public.issue_connection_grant(uuid,text,text)'::regprocedure)
    LIKE '%grant_now := clock_timestamp()%',
  'grant authorization uses one wall-clock timestamp after device row locks'
);

SELECT * FROM finish();

COMMIT;
