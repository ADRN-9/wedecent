-- Single-use device proofs and bounded per-device and aggregate admission issuance.
-- Agent admission is not a terminal connection grant; terminal authorization remains separate.

begin;

create table public.agent_admission_proof_replays (
    device_id text not null references public.devices(device_id) on delete cascade,
    jti text not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default pg_catalog.now(),
    primary key (device_id, jti),
    constraint agent_admission_proof_jti_format
        check (jti ~ '^[A-Za-z0-9_-]{22}$')
);

create index agent_admission_proof_replays_expiry_idx
    on public.agent_admission_proof_replays (expires_at);

alter table public.agent_admission_proof_replays enable row level security;
revoke all on table public.agent_admission_proof_replays from public, anon, authenticated;

create table public.agent_admission_rate_limits (
    device_id text primary key references public.devices(device_id) on delete cascade,
    window_started_at timestamptz not null default pg_catalog.now(),
    request_count integer not null default 0,
    updated_at timestamptz not null default pg_catalog.now(),
    constraint agent_admission_rate_count_range check (request_count between 0 and 65)
);

alter table public.agent_admission_rate_limits enable row level security;
revoke all on table public.agent_admission_rate_limits from public, anon, authenticated;

create table public.agent_admission_global_rate_limits (
    singleton boolean primary key default true check (singleton is true),
    window_started_at timestamptz not null default pg_catalog.now(),
    request_count integer not null default 0,
    updated_at timestamptz not null default pg_catalog.now(),
    constraint agent_admission_global_rate_count_range check (request_count between 0 and 10001)
);

insert into public.agent_admission_global_rate_limits (singleton, window_started_at, request_count, updated_at)
values (true, pg_catalog.now(), 0, pg_catalog.now());

alter table public.agent_admission_global_rate_limits enable row level security;
revoke all on table public.agent_admission_global_rate_limits from public, anon, authenticated;

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
               else least(gr.request_count + 1, 10001)
           end,
           updated_at = v_now
    returning request_count into v_global_request_count;

    if v_global_request_count > 10000 then
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
               else least(rl.request_count + 1, 65)
           end,
           updated_at = v_now
    returning request_count into v_request_count;

    if v_request_count > 64 then
        return 'rate_limited';
    end if;

    insert into public.agent_admission_proof_replays (device_id, jti, expires_at)
    values (p_device_id, p_jti, p_expires_at)
    on conflict (device_id, jti) do nothing;

    if not found then
        return 'replay';
    end if;

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

comment on function public.consume_agent_admission_proof(text, text, text, timestamptz) is
'Atomically rechecks enrolled device key and revocation, applies per-device and aggregate rate limits, and consumes a short-lived device proof nonce. Terminal connection authorization is separate.';

commit;
