begin;

create extension if not exists pgtap with schema extensions;

select plan(34);

insert into auth.users(id, aud, role, email)
values ('11000000-0000-4000-8000-000000000195','authenticated','authenticated','c195-checkpoint@example.test');

insert into public.organizations(id, name, slug, created_by)
values ('22000000-0000-4000-8000-000000000195','C195 Checkpoint','c195-checkpoint','11000000-0000-4000-8000-000000000195');

insert into public.devices(device_id, public_key, kind, name, owner_user_id, organization_id)
values
 ('wd_eeeeeeeeeeeeeeee', repeat('E',43), 'client', 'C195 A', '11000000-0000-4000-8000-000000000195', '22000000-0000-4000-8000-000000000195'),
 ('wd_ffffffffffffffff', repeat('F',43), 'agent', 'C195 B', '11000000-0000-4000-8000-000000000195', '22000000-0000-4000-8000-000000000195'),
 ('wd_gggggggggggggggg', repeat('G',43), 'agent', 'C195 C', '11000000-0000-4000-8000-000000000195', '22000000-0000-4000-8000-000000000195');

create function pg_temp.c195_participants(p_devices text[]) returns jsonb
language sql
stable
as $$
    select pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'device_id', d.device_id,
            'account_id', d.owner_user_id,
            'organization_id', d.organization_id,
            'revocation_epoch', d.revocation_epoch,
            'head_generation', coalesce(a.checkpoint_head_generation, 0),
            'head_hash', coalesce(pg_catalog.encode(a.checkpoint_head_hash, 'hex'), pg_catalog.repeat('0', 64))
        )
        order by d.device_id
    )
      from public.devices d
      left join public.port_forward_replay_authority a on a.device_id = d.device_id
     where d.device_id = any(p_devices);
$$;

create function pg_temp.c195_acks(p_operation_id text, p_action text) returns jsonb
language sql
immutable
as $$
    select pg_catalog.jsonb_build_array(
        pg_catalog.jsonb_build_object(
            'witness_id', 'witness-a',
            'token_sha256', pg_catalog.repeat('a',64),
            'generation', 1,
            'action', p_action,
            'operation_id', p_operation_id,
            'witness_key_id', 'key-a',
            'committed_at_unix_ms', 1000,
            'signature', pg_catalog.repeat('A',86) || '=='
        ),
        pg_catalog.jsonb_build_object(
            'witness_id', 'witness-b',
            'token_sha256', pg_catalog.repeat('a',64),
            'generation', 1,
            'action', p_action,
            'operation_id', p_operation_id,
            'witness_key_id', 'key-b',
            'committed_at_unix_ms', 1001,
            'signature', pg_catalog.repeat('B',86) || '=='
        )
    );
$$;

create temp table c195_snapshots (
    name text primary key,
    participants jsonb not null
);

insert into c195_snapshots values (
    'initial',
    pg_temp.c195_participants(array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff'])
);

select ok(
    (select relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='checkpoint_operations'),
    'checkpoint operation identity ledger has RLS enabled'
);
select ok(
    not pg_catalog.has_table_privilege('service_role','public.checkpoint_operations','SELECT,INSERT,UPDATE,DELETE')
    and not pg_catalog.has_table_privilege('service_role','public.checkpoint_operation_events','SELECT,INSERT,UPDATE,DELETE')
    and not pg_catalog.has_table_privilege('service_role','public.checkpoint_active_reservations','SELECT,INSERT,UPDATE,DELETE'),
    'service_role has no direct ledger or reservation table privileges'
);
select ok(
    exists (
        select 1 from information_schema.columns
         where table_schema='public' and table_name='port_forward_replay_authority'
           and column_name='checkpoint_head_generation'
    )
    and exists (
        select 1 from information_schema.columns
         where table_schema='public' and table_name='port_forward_replay_authority'
           and column_name='checkpoint_head_hash'
    )
    and not exists (
        select 1 from information_schema.columns
         where table_schema='public' and table_name='checkpoint_active_reservations'
           and column_name in ('head_generation','head_hash','checkpoint_head_generation','checkpoint_head_hash')
    ),
    'port_forward_replay_authority remains the only mutable participant-head authority'
);

select is(
    public.reserve_checkpoint_operation(
        repeat('1',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('1',64),'hex'),
        (select participants from c195_snapshots where name='initial'), 60
    )->>'status',
    'reserved',
    'first multi-participant reservation succeeds'
);
select is(
    (select count(*)::integer from public.checkpoint_active_reservations where operation_id=repeat('1',64)),
    2,
    'reservation leases are installed for every participant'
);
select is(
    public.reserve_checkpoint_operation(
        repeat('1',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('1',64),'hex'),
        (select participants from c195_snapshots where name='initial'), 60
    )->>'status',
    'reserved',
    'exact operation retry returns the existing reservation'
);
select throws_ok(
    $q$select public.reserve_checkpoint_operation(
        repeat('1',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('2',64),'hex'),
        (select participants from c195_snapshots where name='initial'), 60
    )$q$,
    '23505', null,
    'conflicting operation fingerprint is rejected'
);
select throws_ok(
    $q$select public.reserve_checkpoint_operation(
        repeat('2',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('2',64),'hex'),
        (select jsonb_build_array(value,value) from jsonb_array_elements((select participants from c195_snapshots where name='initial')) limit 1), 60
    )$q$,
    '22023', null,
    'duplicate participants are rejected'
);
select throws_ok(
    $q$select public.commit_checkpoint_operation(repeat('1',64), decode((select encode(fingerprint,'hex') from public.checkpoint_operations where operation_id=repeat('1',64)),'hex'), '[]'::jsonb)$q$,
    '22023', 'checkpoint witness acknowledgements are malformed or insufficient',
    'empty witness acknowledgement set is rejected'
);
select throws_ok(
    $q$select public.commit_checkpoint_operation(
        repeat('1',64),
        (select fingerprint from public.checkpoint_operations where operation_id=repeat('1',64)),
        jsonb_build_array(
            jsonb_build_object('witness_id','witness-a','token_sha256',repeat('a',64),'generation',1,'action','finalize','operation_id',repeat('1',64),'witness_key_id','key-a','committed_at_unix_ms',1000,'signature',repeat('A',86)||'=='),
            jsonb_build_object('witness_id','witness-a','token_sha256',repeat('a',64),'generation',1,'action','finalize','operation_id',repeat('1',64),'witness_key_id','key-a','committed_at_unix_ms',1001,'signature',repeat('A',86)||'==')
        )
    )$q$,
    '22023', 'checkpoint witness acknowledgement set conflicts',
    'duplicate witness acknowledgements are rejected'
);
select is(
    public.commit_checkpoint_operation(
        repeat('1',64),
        (select fingerprint from public.checkpoint_operations where operation_id=repeat('1',64)),
        pg_temp.c195_acks(repeat('1',64),'finalize')
    )->>'status',
    'committed',
    'commit atomically advances the complete participant set'
);
select is(
    (select count(*)::integer from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff') and checkpoint_head_generation=1),
    2,
    'every participant head advances exactly one generation'
);
select is(
    (select count(*)::integer from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff') and generation=0),
    2,
    'checkpoint commit preserves the historical replay generation and chain'
);
select ok(
    (select event_sha256 = extensions.digest(convert_to(wedecent_private.canonical_jsonb(event_payload),'UTF8'),'sha256')
       from public.checkpoint_operation_events
      where operation_id=repeat('1',64) and event_type='committed'),
    'commit evidence digest matches canonical event payload'
);
select is(
    public.commit_checkpoint_operation(
        repeat('1',64),
        (select fingerprint from public.checkpoint_operations where operation_id=repeat('1',64)),
        pg_temp.c195_acks(repeat('1',64),'finalize')
    )->>'status',
    'committed',
    'exact commit retry returns the durable receipt'
);
select is(
    (select count(*)::integer from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff') and checkpoint_head_generation=1),
    2,
    'ambiguous-response retry does not advance heads twice'
);
select is(
    public.reserve_checkpoint_operation(
        repeat('1',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('1',64),'hex'),
        (select participants from c195_snapshots where name='initial'), 60
    )->>'status',
    'committed',
    'reserve retry after commit returns the committed receipt'
);

insert into c195_snapshots values (
    'after-first',
    pg_temp.c195_participants(array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff'])
);

select is(
    public.reserve_checkpoint_operation(
        repeat('3',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('3',64),'hex'),
        (select participants from c195_snapshots where name='after-first'), 60
    )->>'status',
    'reserved',
    'second operation reserves the same participant set at the next generation'
);
select throws_ok(
    $q$select public.reserve_checkpoint_operation(
        repeat('4',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('4',64),'hex'),
        pg_temp.c195_participants(array['wd_ffffffffffffffff','wd_gggggggggggggggg']), 60
    )$q$,
    '55P03', 'checkpoint participant is reserved by another operation',
    'overlapping multi-participant reservation is rejected'
);
select is(
    (select count(*)::integer from public.checkpoint_operations where operation_id=repeat('4',64)),
    0,
    'overlapping reservation failure leaves no partial operation ledger'
);
select is(
    public.commit_checkpoint_operation(
        repeat('3',64),
        (select fingerprint from public.checkpoint_operations where operation_id=repeat('3',64)),
        pg_temp.c195_acks(repeat('3',64),'finalize')
    )->>'status',
    'committed',
    'non-overlapping operation commits after competing reservation is rejected'
);
select throws_ok(
    $q$select public.reserve_checkpoint_operation(
        repeat('5',64), 'finalize', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('5',64),'hex'),
        (select participants from c195_snapshots where name='after-first'), 60
    )$q$,
    '40001', 'checkpoint participant head is stale',
    'stale expected generation and checkpoint hash are rejected'
);
select is(
    (select count(*)::integer from public.checkpoint_operations where operation_id=repeat('5',64)),
    0,
    'stale operation leaves no durable reservation or fingerprint'
);

savepoint c195_rollback;
select public.reserve_checkpoint_operation(
    repeat('6',64), 'finalize', '22000000-0000-4000-8000-000000000195',
    '11000000-0000-4000-8000-000000000195', decode(repeat('6',64),'hex'),
    pg_temp.c195_participants(array['wd_gggggggggggggggg']), 60
);
rollback to savepoint c195_rollback;
select is(
    (select count(*)::integer from public.checkpoint_operations where operation_id=repeat('6',64)),
    0,
    'transaction rollback removes operation identity and all reservation writes'
);

select is(
    public.reserve_checkpoint_operation(
        repeat('7',64), 'revoke', '22000000-0000-4000-8000-000000000195',
        '11000000-0000-4000-8000-000000000195', decode(repeat('7',64),'hex'),
        pg_temp.c195_participants(array['wd_gggggggggggggggg']), 60
    )->>'status',
    'reserved',
    'authorized owner can reserve revocation'
);
select is(
    public.commit_checkpoint_operation(
        repeat('7',64),
        (select fingerprint from public.checkpoint_operations where operation_id=repeat('7',64)),
        pg_temp.c195_acks(repeat('7',64),'revoke')
    )->>'status',
    'committed',
    'revocation and checkpoint head commit in one transaction'
);
select is(
    (select revocation_epoch::integer from public.devices where device_id='wd_gggggggggggggggg'),
    1,
    'revocation commit advances the participant revocation epoch exactly once'
);
select is(
    (select checkpoint_head_generation::integer from public.port_forward_replay_authority where device_id='wd_gggggggggggggggg'),
    1,
    'revocation commit advances the same authoritative checkpoint head'
);

insert into c195_snapshots values (
    'before-concurrent-revoke',
    pg_temp.c195_participants(array['wd_gggggggggggggggg'])
);
select public.reserve_checkpoint_operation(
    repeat('8',64), 'finalize', '22000000-0000-4000-8000-000000000195',
    '11000000-0000-4000-8000-000000000195', decode(repeat('8',64),'hex'),
    (select participants from c195_snapshots where name='before-concurrent-revoke'), 60
);
update public.devices set revoked_at=pg_catalog.clock_timestamp()
 where device_id='wd_gggggggggggggggg';
select throws_ok(
    $q$select public.commit_checkpoint_operation(
        repeat('8',64),
        (select fingerprint from public.checkpoint_operations where operation_id=repeat('8',64)),
        pg_temp.c195_acks(repeat('8',64),'finalize')
    )$q$,
    '42501', 'checkpoint participant identity or revocation changed',
    'concurrent device revocation fences a pending finalization commit'
);
select is(
    (select checkpoint_head_generation::integer from public.port_forward_replay_authority where device_id='wd_gggggggggggggggg'),
    1,
    'revocation race leaves no partial checkpoint head advancement'
);

select throws_ok(
    $q$update public.checkpoint_operations set action='revoke' where operation_id=repeat('1',64)$q$,
    '55000', 'checkpoint operation evidence is append-only',
    'operation fingerprints cannot be mutated'
);
select throws_ok(
    $q$update public.checkpoint_operation_participants set next_generation=next_generation+1 where operation_id=repeat('1',64)$q$,
    '55000', 'checkpoint operation evidence is append-only',
    'participant snapshots cannot be mutated'
);
select throws_ok(
    $q$delete from public.checkpoint_operation_events where operation_id=repeat('1',64)$q$,
    '55000', 'checkpoint operation evidence is append-only',
    'commit evidence cannot be deleted'
);

select is(
    encode(wedecent_private.checkpoint_participant_vector_hash(
        '[{"device_id":"wd_aaaaaaaaaaaaaaaa","account_id":"11111111-1111-4111-8111-111111111111","organization_id":"22222222-2222-4222-8222-222222222222","revocation_epoch":7,"head_generation":41,"head_hash":"3333333333333333333333333333333333333333333333333333333333333333"}]'::jsonb
    ),'hex'),
    '3080ab979e283614fec564a8a112bd6f18fba4508e00f0ceba34c8e75738aa33',
    'historical v1 participant digest vector remains unchanged'
);

select * from finish();
rollback;
