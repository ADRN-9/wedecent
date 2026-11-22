-- Persist admission audit evidence and throttle unauthenticated endpoint traffic before device lookup.

begin;

alter table public.agent_admission_global_rate_limits
    drop constraint if exists agent_admission_global_rate_count_range;
alter table public.agent_admission_global_rate_limits
    add constraint agent_admission_global_rate_count_range check (request_count between 0 and 10002);

alter table public.agent_admission_rate_limits
    drop constraint if exists agent_admission_rate_count_range;
alter table public.agent_admission_rate_limits
    add constraint agent_admission_rate_count_range check (request_count between 0 and 66);

create table public.agent_admission_audit_events (
    id uuid primary key default gen_random_uuid(),
    device_id text,
    event_type text not null,
    slot integer,
    proof_jti text,
    admission_jti uuid,
    reason text not null,
    created_at timestamptz not null default pg_catalog.now(),
    constraint agent_admission_audit_device_id_format
        check (device_id is null or device_id ~ '^wd_[a-z2-7]{16}$'),
    constraint agent_admission_audit_event_type
        check (event_type in ('issued', 'consumed', 'rejected', 'revoked')),
    constraint agent_admission_audit_slot_range
        check (slot is null or slot between 1 and 32),
    constraint agent_admission_audit_proof_jti_format
        check (proof_jti is null or proof_jti ~ '^[A-Za-z0-9_-]{22}$'),
    constraint agent_admission_audit_reason
        check (reason in ('issued', 'consumed', 'proof_replay', 'rate_limited', 'request_rejected', 'invalid_proof', 'device_revoked'))
);

create index agent_admission_audit_device_created_idx
    on public.agent_admission_audit_events (device_id, created_at desc);

create index agent_admission_audit_created_idx
    on public.agent_admission_audit_events (created_at desc);

alter table public.agent_admission_audit_events enable row level security;
revoke all on table public.agent_admission_audit_events from public, anon, authenticated;

create table public.device_revocation_dispatch_outbox (
    id uuid primary key default gen_random_uuid(),
    device_id text not null,
    status text not null default 'pending',
    attempts integer not null default 0,
    created_at timestamptz not null default pg_catalog.now(),
    last_attempt_at timestamptz,
    dispatched_at timestamptz,
    last_error text,
    constraint device_revocation_dispatch_device_id_format
        check (device_id ~ '^wd_[a-z2-7]{16}    singleton boolean primary key default true check (singleton is true),
    window_started_at timestamptz not null default pg_catalog.now(),
    request_count integer not null default 0,
    updated_at timestamptz not null default pg_catalog.now(),
    constraint agent_admission_endpoint_rate_count_range check (request_count between 0 and 1002)
);

insert into public.agent_admission_endpoint_rate_limits (singleton, window_started_at, request_count, updated_at)
values (true, pg_catalog.now(), 0, pg_catalog.now());

alter table public.agent_admission_endpoint_rate_limits enable row level security;
revoke all on table public.agent_admission_endpoint_rate_limits from public, anon, authenticated;

create or replace function public.consume_agent_admission_endpoint_request()
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_now timestamptz := pg_catalog.now();
    v_request_count integer;
begin
    insert into public.agent_admission_endpoint_rate_limits as rl (
        singleton, window_started_at, request_count, updated_at
    )
    values (true, v_now, 1, v_now)
    on conflict (singleton) do update
       set window_started_at = case
               when rl.window_started_at <= v_now - interval '60 seconds' then v_now
               else rl.window_started_at
           end,
           request_count = case
               when rl.window_started_at <= v_now - interval '60 seconds' then 1
               else least(rl.request_count + 1, 1002)
           end,
           updated_at = v_now
    returning request_count into v_request_count;

    if v_request_count = 1001 then
        insert into public.agent_admission_audit_events (event_type, reason)
        values ('rejected', 'rate_limited');
    end if;

    return v_request_count <= 1000;
end;
$$;

revoke all on function public.consume_agent_admission_endpoint_request()
from public, anon, authenticated;

grant execute on function public.consume_agent_admission_endpoint_request()
to service_role;

create or replace function public.record_agent_admission_audit(
    p_device_id text,
    p_event_type text,
    p_slot integer,
    p_proof_jti text,
    p_admission_jti uuid,
    p_reason text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_event_type not in ('issued', 'rejected') then
        raise exception 'invalid agent admission audit event type' using errcode = '22023';
    end if;
    if p_device_id is not null and p_device_id !~ '^wd_[a-z2-7]{16}$' then
        raise exception 'invalid agent admission audit device' using errcode = '22023';
    end if;
    if p_slot is not null and p_slot not between 1 and 32 then
        raise exception 'invalid agent admission audit slot' using errcode = '22023';
    end if;
    if p_proof_jti is not null and p_proof_jti !~ '^[A-Za-z0-9_-]{22}$' then
        raise exception 'invalid agent admission audit proof nonce' using errcode = '22023';
    end if;
    if p_reason not in ('issued', 'request_rejected', 'invalid_proof', 'rate_limited', 'proof_replay', 'device_revoked') then
        raise exception 'invalid agent admission audit reason' using errcode = '22023';
    end if;

    insert into public.agent_admission_audit_events (
        device_id, event_type, slot, proof_jti, admission_jti, reason
    )
    values (
        p_device_id, p_event_type, p_slot, p_proof_jti, p_admission_jti, p_reason
    );
end;
$$;

revoke all on function public.record_agent_admission_audit(text, text, integer, text, uuid, text)
from public, anon, authenticated;

grant execute on function public.record_agent_admission_audit(text, text, integer, text, uuid, text)
to service_role;

create or replace function public.audit_agent_device_revocation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if old.revoked_at is null and new.revoked_at is not null then
        insert into public.agent_admission_audit_events (device_id, event_type, reason)
        values (new.device_id, 'revoked', 'device_revoked');
        insert into public.device_revocation_dispatch_outbox (device_id, status)
        values (new.device_id, 'pending')
        on conflict (device_id) where status = 'pending' do nothing;
    end if;
    return new;
end;
$$;

revoke all on function public.audit_agent_device_revocation()
from public, anon, authenticated;

drop trigger if exists agent_device_revocation_audit on public.devices;
create trigger agent_device_revocation_audit
after update of revoked_at on public.devices
for each row
execute function public.audit_agent_device_revocation();

create or replace function public.consume_agent_admission_proof(
    p_device_id text,
    p_public_key text,
    p_jti text,
    p_expires_at timestamptz
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_device public.devices%rowtype;
    v_now timestamptz := pg_catalog.now();
    v_request_count integer;
    v_global_request_count integer;
begin
    if p_device_id is null or p_device_id !~ '^wd_[a-z2-7]{16}$' then
        raise exception 'invalid agent device' using errcode = '22023';
    end if;
    if p_public_key is null or p_public_key !~ '^[A-Za-z0-9_-]{43}$' then
        raise exception 'invalid enrolled agent public key' using errcode = '22023';
    end if;
    if p_jti is null or p_jti !~ '^[A-Za-z0-9_-]{22}$' then
        raise exception 'invalid agent proof nonce' using errcode = '22023';
    end if;
    if p_expires_at is null or p_expires_at <= v_now or p_expires_at > v_now + interval '60 seconds' then
        raise exception 'invalid agent proof expiry' using errcode = '22023';
    end if;

    select d.*
      into v_device
      from public.devices as d
     where d.device_id = p_device_id
     for share;

    if not found
       or v_device.public_key <> p_public_key
       or v_device.revoked_at is not null
       or v_device.kind not in ('agent', 'hybrid') then
        raise exception 'agent device is not enrolled or is revoked' using errcode = '42501';
    end if;

    insert into public.agent_admission_global_rate_limits as gr (
        singleton, window_started_at, request_count, updated_at
    )
    values (true, v_now, 1, v_now)
    on conflict (singleton) do update
       set window_started_at = case
               when gr.window_started_at <= v_now - interval '60 seconds' then v_now
               else gr.window_started_at
           end,
           request_count = case
               when gr.window_started_at <= v_now - interval '60 seconds' then 1
               else least(gr.request_count + 1, 10002)
           end,
           updated_at = v_now
    returning request_count into v_global_request_count;

    if v_global_request_count > 10000 then
        if v_global_request_count = 10001 then
            insert into public.agent_admission_audit_events (device_id, event_type, reason)
            values (p_device_id, 'rejected', 'rate_limited');
        end if;
        return 'rate_limited';
    end if;

    insert into public.agent_admission_rate_limits as rl (
        device_id, window_started_at, request_count, updated_at
    )
    values (p_device_id, v_now, 1, v_now)
    on conflict (device_id) do update
       set window_started_at = case
               when rl.window_started_at <= v_now - interval '60 seconds' then v_now
               else rl.window_started_at
           end,
           request_count = case
               when rl.window_started_at <= v_now - interval '60 seconds' then 1
               else least(rl.request_count + 1, 66)
           end,
           updated_at = v_now
    returning request_count into v_request_count;

    if v_request_count > 64 then
        if v_request_count = 65 then
            insert into public.agent_admission_audit_events (device_id, event_type, reason)
            values (p_device_id, 'rejected', 'rate_limited');
        end if;
        return 'rate_limited';
    end if;

    insert into public.agent_admission_proof_replays (device_id, jti, expires_at)
    values (p_device_id, p_jti, p_expires_at)
    on conflict (device_id, jti) do nothing;

    if not found then
        insert into public.agent_admission_audit_events (device_id, event_type, proof_jti, reason)
        values (p_device_id, 'rejected', p_jti, 'proof_replay');
        return 'replay';
    end if;

    insert into public.agent_admission_audit_events (device_id, event_type, proof_jti, reason)
    values (p_device_id, 'consumed', p_jti, 'consumed');

    delete from public.agent_admission_proof_replays
     where ctid in (
         select replay.ctid
           from public.agent_admission_proof_replays as replay
          where replay.expires_at <= v_now
          order by replay.expires_at
          limit 500
     );

    return 'accepted';
end;
$$;

revoke all on function public.consume_agent_admission_proof(text, text, text, timestamptz)
from public, anon, authenticated;

grant execute on function public.consume_agent_admission_proof(text, text, text, timestamptz)
to service_role;

comment on table public.agent_admission_audit_events is
'Durable, non-secret audit evidence for agent admission issuance, proof consumption, rejection, and device revocation.';

comment on table public.device_revocation_dispatch_outbox is
'Durable pending relay-session revocation dispatches. Failed dispatches remain pending for retry.';

comment on function public.consume_agent_admission_endpoint_request() is
'Applies a fixed global 1,000-request rolling 60-second ceiling before untrusted admission request parsing and device lookup.';

commit;
),
    constraint device_revocation_dispatch_status
        check (status in ('pending', 'dispatched')),
    constraint device_revocation_dispatch_attempts
        check (attempts between 0 and 1000000),
    constraint device_revocation_dispatch_last_error
        check (last_error is null or pg_catalog.length(last_error) <= 256)
);

create unique index device_revocation_dispatch_one_pending_idx
    on public.device_revocation_dispatch_outbox (device_id)
    where status = 'pending';

create index device_revocation_dispatch_pending_idx
    on public.device_revocation_dispatch_outbox (created_at)
    where status = 'pending';

alter table public.device_revocation_dispatch_outbox enable row level security;
revoke all on table public.device_revocation_dispatch_outbox from public, anon, authenticated;
grant select, insert, update on table public.device_revocation_dispatch_outbox to service_role;

create table public.agent_admission_endpoint_rate_limits (
    singleton boolean primary key default true check (singleton is true),
    window_started_at timestamptz not null default pg_catalog.now(),
    request_count integer not null default 0,
    updated_at timestamptz not null default pg_catalog.now(),
    constraint agent_admission_endpoint_rate_count_range check (request_count between 0 and 1002)
);

insert into public.agent_admission_endpoint_rate_limits (singleton, window_started_at, request_count, updated_at)
values (true, pg_catalog.now(), 0, pg_catalog.now());

alter table public.agent_admission_endpoint_rate_limits enable row level security;
revoke all on table public.agent_admission_endpoint_rate_limits from public, anon, authenticated;

create or replace function public.consume_agent_admission_endpoint_request()
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_now timestamptz := pg_catalog.now();
    v_request_count integer;
begin
    insert into public.agent_admission_endpoint_rate_limits as rl (
        singleton, window_started_at, request_count, updated_at
    )
    values (true, v_now, 1, v_now)
    on conflict (singleton) do update
       set window_started_at = case
               when rl.window_started_at <= v_now - interval '60 seconds' then v_now
               else rl.window_started_at
           end,
           request_count = case
               when rl.window_started_at <= v_now - interval '60 seconds' then 1
               else least(rl.request_count + 1, 1002)
           end,
           updated_at = v_now
    returning request_count into v_request_count;

    if v_request_count = 1001 then
        insert into public.agent_admission_audit_events (event_type, reason)
        values ('rejected', 'rate_limited');
    end if;

    return v_request_count <= 1000;
end;
$$;

revoke all on function public.consume_agent_admission_endpoint_request()
from public, anon, authenticated;

grant execute on function public.consume_agent_admission_endpoint_request()
to service_role;

create or replace function public.record_agent_admission_audit(
    p_device_id text,
    p_event_type text,
    p_slot integer,
    p_proof_jti text,
    p_admission_jti uuid,
    p_reason text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_event_type not in ('issued', 'rejected') then
        raise exception 'invalid agent admission audit event type' using errcode = '22023';
    end if;
    if p_device_id is not null and p_device_id !~ '^wd_[a-z2-7]{16}$' then
        raise exception 'invalid agent admission audit device' using errcode = '22023';
    end if;
    if p_slot is not null and p_slot not between 1 and 32 then
        raise exception 'invalid agent admission audit slot' using errcode = '22023';
    end if;
    if p_proof_jti is not null and p_proof_jti !~ '^[A-Za-z0-9_-]{22}$' then
        raise exception 'invalid agent admission audit proof nonce' using errcode = '22023';
    end if;
    if p_reason not in ('issued', 'request_rejected', 'invalid_proof', 'rate_limited', 'proof_replay', 'device_revoked') then
        raise exception 'invalid agent admission audit reason' using errcode = '22023';
    end if;

    insert into public.agent_admission_audit_events (
        device_id, event_type, slot, proof_jti, admission_jti, reason
    )
    values (
        p_device_id, p_event_type, p_slot, p_proof_jti, p_admission_jti, p_reason
    );
end;
$$;

revoke all on function public.record_agent_admission_audit(text, text, integer, text, uuid, text)
from public, anon, authenticated;

grant execute on function public.record_agent_admission_audit(text, text, integer, text, uuid, text)
to service_role;

create or replace function public.audit_agent_device_revocation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if old.revoked_at is null and new.revoked_at is not null then
        insert into public.agent_admission_audit_events (device_id, event_type, reason)
        values (new.device_id, 'revoked', 'device_revoked');
    end if;
    return new;
end;
$$;

revoke all on function public.audit_agent_device_revocation()
from public, anon, authenticated;

drop trigger if exists agent_device_revocation_audit on public.devices;
create trigger agent_device_revocation_audit
after update of revoked_at on public.devices
for each row
execute function public.audit_agent_device_revocation();

create or replace function public.consume_agent_admission_proof(
    p_device_id text,
    p_public_key text,
    p_jti text,
    p_expires_at timestamptz
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_device public.devices%rowtype;
    v_now timestamptz := pg_catalog.now();
    v_request_count integer;
    v_global_request_count integer;
begin
    if p_device_id is null or p_device_id !~ '^wd_[a-z2-7]{16}$' then
        raise exception 'invalid agent device' using errcode = '22023';
    end if;
    if p_public_key is null or p_public_key !~ '^[A-Za-z0-9_-]{43}$' then
        raise exception 'invalid enrolled agent public key' using errcode = '22023';
    end if;
    if p_jti is null or p_jti !~ '^[A-Za-z0-9_-]{22}$' then
        raise exception 'invalid agent proof nonce' using errcode = '22023';
    end if;
    if p_expires_at is null or p_expires_at <= v_now or p_expires_at > v_now + interval '60 seconds' then
        raise exception 'invalid agent proof expiry' using errcode = '22023';
    end if;

    select d.*
      into v_device
      from public.devices as d
     where d.device_id = p_device_id
     for share;

    if not found
       or v_device.public_key <> p_public_key
       or v_device.revoked_at is not null
       or v_device.kind not in ('agent', 'hybrid') then
        raise exception 'agent device is not enrolled or is revoked' using errcode = '42501';
    end if;

    insert into public.agent_admission_global_rate_limits as gr (
        singleton, window_started_at, request_count, updated_at
    )
    values (true, v_now, 1, v_now)
    on conflict (singleton) do update
       set window_started_at = case
               when gr.window_started_at <= v_now - interval '60 seconds' then v_now
               else gr.window_started_at
           end,
           request_count = case
               when gr.window_started_at <= v_now - interval '60 seconds' then 1
               else least(gr.request_count + 1, 10002)
           end,
           updated_at = v_now
    returning request_count into v_global_request_count;

    if v_global_request_count > 10000 then
        if v_global_request_count = 10001 then
            insert into public.agent_admission_audit_events (device_id, event_type, reason)
            values (p_device_id, 'rejected', 'rate_limited');
        end if;
        return 'rate_limited';
    end if;

    insert into public.agent_admission_rate_limits as rl (
        device_id, window_started_at, request_count, updated_at
    )
    values (p_device_id, v_now, 1, v_now)
    on conflict (device_id) do update
       set window_started_at = case
               when rl.window_started_at <= v_now - interval '60 seconds' then v_now
               else rl.window_started_at
           end,
           request_count = case
               when rl.window_started_at <= v_now - interval '60 seconds' then 1
               else least(rl.request_count + 1, 66)
           end,
           updated_at = v_now
    returning request_count into v_request_count;

    if v_request_count > 64 then
        if v_request_count = 65 then
            insert into public.agent_admission_audit_events (device_id, event_type, reason)
            values (p_device_id, 'rejected', 'rate_limited');
        end if;
        return 'rate_limited';
    end if;

    insert into public.agent_admission_proof_replays (device_id, jti, expires_at)
    values (p_device_id, p_jti, p_expires_at)
    on conflict (device_id, jti) do nothing;

    if not found then
        insert into public.agent_admission_audit_events (device_id, event_type, proof_jti, reason)
        values (p_device_id, 'rejected', p_jti, 'proof_replay');
        return 'replay';
    end if;

    insert into public.agent_admission_audit_events (device_id, event_type, proof_jti, reason)
    values (p_device_id, 'consumed', p_jti, 'consumed');

    delete from public.agent_admission_proof_replays
     where ctid in (
         select replay.ctid
           from public.agent_admission_proof_replays as replay
          where replay.expires_at <= v_now
          order by replay.expires_at
          limit 500
     );

    return 'accepted';
end;
$$;

revoke all on function public.consume_agent_admission_proof(text, text, text, timestamptz)
from public, anon, authenticated;

grant execute on function public.consume_agent_admission_proof(text, text, text, timestamptz)
to service_role;

comment on table public.agent_admission_audit_events is
'Durable, non-secret audit evidence for agent admission issuance, proof consumption, rejection, and device revocation.';

comment on function public.consume_agent_admission_endpoint_request() is
'Applies a fixed global 1,000-request rolling 60-second ceiling before untrusted admission request parsing and device lookup.';

commit;
