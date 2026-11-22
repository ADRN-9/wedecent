begin;

create extension if not exists pgtap with schema extensions;

select plan(14);

insert into auth.users (id, aud, role, email)
values (
    '10000000-0000-4000-8000-000000000085',
    'authenticated',
    'authenticated',
    'device-revocation-generation@example.test'
);

insert into public.devices (device_id, public_key, kind, name, owner_user_id)
values (
    'wd_ffffffffffffffff',
    repeat('F', 43),
    'agent',
    'Revocation generation test agent',
    '10000000-0000-4000-8000-000000000085'
);

select is(
    (select authorization_generation from public.devices where device_id = 'wd_ffffffffffffffff'),
    1::bigint,
    'new devices start at authorization generation one'
);

update public.devices
   set revoked_at = pg_catalog.now()
 where device_id = 'wd_ffffffffffffffff';

select is(
    (select authorization_generation from public.devices where device_id = 'wd_ffffffffffffffff'),
    2::bigint,
    'revocation increments the authorization generation'
);
select ok(
    (select revocation_pending from public.devices where device_id = 'wd_ffffffffffffffff'),
    'revocation is pending until relay acknowledgement'
);
select is(
    (select authorization_generation from public.device_revocation_dispatch_outbox
      where device_id = 'wd_ffffffffffffffff' and status = 'pending'),
    2::bigint,
    'the outbox carries the fenced generation'
);
select is(
    public.authorize_agent_admission_issue(
        'wd_ffffffffffffffff', repeat('F', 43), 2, 1,
        repeat('A', 22), '10000000-0000-4000-8000-000000000086'
    ),
    false,
    'a pending or revoked device cannot issue an admission capability'
);

create temporary table first_claim as
select * from public.claim_device_revocation_dispatches(10, 60, 'wd_ffffffffffffffff');

select is((select count(*)::integer from first_claim), 1, 'one worker claims the pending outbox event');
select is(
    (select authorization_generation from first_claim limit 1),
    2::bigint,
    'claimed event preserves the current authorization generation'
);
select is(
    (select count(*)::integer from public.claim_device_revocation_dispatches(10, 60, 'wd_ffffffffffffffff')),
    0,
    'a concurrent duplicate worker cannot claim an active lease'
);

update public.device_revocation_dispatch_outbox
   set claimed_until = pg_catalog.now() - interval '1 second'
 where id = (select id from first_claim);

create temporary table second_claim as
select * from public.claim_device_revocation_dispatches(10, 60, 'wd_ffffffffffffffff');

select is((select count(*)::integer from second_claim), 1, 'an expired claim is recoverable');
select is(
    public.complete_device_revocation_dispatch(
        (select id from first_claim),
        (select claim_token from first_claim),
        2
    ),
    false,
    'a stale worker acknowledgement cannot complete a reclaimed event'
);
select is(
    public.complete_device_revocation_dispatch(
        (select id from second_claim),
        (select claim_token from second_claim),
        2
    ),
    true,
    'the current claim can complete after relay acknowledgement'
);
select ok(
    not (select revocation_pending from public.devices where device_id = 'wd_ffffffffffffffff'),
    'successful acknowledgement clears the pending marker'
);
select is(
    public.complete_device_revocation_dispatch(
        (select id from second_claim),
        (select claim_token from second_claim),
        2
    ),
    false,
    'duplicate completion is idempotently rejected'
);
select throws_ok(
    $$update public.devices set revoked_at = null where device_id = 'wd_ffffffffffffffff'$$,
    '23514',
    'device revocation is irreversible',
    'device revocation cannot be undone'
);

select * from finish();
rollback;
