-- Cross-system revocation uses a monotonic generation fence and a claim/ack outbox.
begin;

alter table public.devices
    add column if not exists authorization_generation bigint not null default 1;
alter table public.devices
    add column if not exists revocation_pending boolean not null default false;

do $$
begin
    if not exists (
        select 1 from pg_catalog.pg_constraint
         where conname = 'devices_authorization_generation_positive'
           and conrelid = 'public.devices'::regclass
    ) then
        alter table public.devices
            add constraint devices_authorization_generation_positive
            check (authorization_generation > 0);
    end if;
end;
$$;

alter table public.device_revocation_dispatch_outbox
    add column if not exists authorization_generation bigint not null default 1;
alter table public.device_revocation_dispatch_outbox
    add column if not exists next_attempt_at timestamptz not null default pg_catalog.now();
alter table public.device_revocation_dispatch_outbox
    add column if not exists claim_token uuid;
alter table public.device_revocation_dispatch_outbox
    add column if not exists claimed_until timestamptz;

do $$
begin
    if not exists (
        select 1 from pg_catalog.pg_constraint
         where conname = 'device_revocation_dispatch_generation_positive'
           and conrelid = 'public.device_revocation_dispatch_outbox'::regclass
    ) then
        alter table public.device_revocation_dispatch_outbox
            add constraint device_revocation_dispatch_generation_positive
            check (authorization_generation > 0);
    end if;
end;
$$;

create index if not exists device_revocation_dispatch_due_idx
    on public.device_revocation_dispatch_outbox (next_attempt_at, created_at, id)
    where status = 'pending';

-- Existing revoked devices must be fenced again on the relay after rollout.
update public.devices
   set authorization_generation = authorization_generation + 1,
       revocation_pending = true
 where revoked_at is not null
   and not revocation_pending;

insert into public.device_revocation_dispatch_outbox (
    device_id, status, authorization_generation, next_attempt_at
)
select device_id, 'pending', authorization_generation, pg_catalog.now()
  from public.devices
 where revoked_at is not null
   and revocation_pending
on conflict (device_id) where status = 'pending'
do update set
    authorization_generation = greatest(
        public.device_revocation_dispatch_outbox.authorization_generation,
        excluded.authorization_generation
    ),
    next_attempt_at = least(
        public.device_revocation_dispatch_outbox.next_attempt_at,
        excluded.next_attempt_at
    );

create or replace function public.guard_device_authorization_generation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if new.authorization_generation < old.authorization_generation then
        raise exception 'device authorization generation cannot decrease' using errcode = '23514';
    end if;
    if old.revoked_at is not null and new.revoked_at is null then
        raise exception 'device revocation is irreversible' using errcode = '23514';
    end if;
    if old.revocation_pending and not new.revocation_pending
       and pg_catalog.current_setting('app.wedecent_revocation_ack', true) is distinct from 'true' then
        raise exception 'device revocation pending state requires relay acknowledgement' using errcode = '42501';
    end if;
    if old.revoked_at is null and new.revoked_at is not null then
        new.authorization_generation := old.authorization_generation + 1;
        new.revocation_pending := true;
    end if;
    return new;
end;
$$;

revoke all on function public.guard_device_authorization_generation()
from public, anon, authenticated;

drop trigger if exists device_authorization_generation_guard on public.devices;
create trigger device_authorization_generation_guard
before update of revoked_at, authorization_generation, revocation_pending
on public.devices
for each row
execute function public.guard_device_authorization_generation();

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

        insert into public.device_revocation_dispatch_outbox (
            device_id, status, authorization_generation, next_attempt_at
        )
        values (new.device_id, 'pending', new.authorization_generation, pg_catalog.now())
        on conflict (device_id) where status = 'pending'
        do update set
            authorization_generation = greatest(
                public.device_revocation_dispatch_outbox.authorization_generation,
                excluded.authorization_generation
            ),
            next_attempt_at = least(
                public.device_revocation_dispatch_outbox.next_attempt_at,
                excluded.next_attempt_at
            );
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

create or replace function public.authorize_agent_admission_issue(
    p_device_id text,
    p_public_key text,
    p_authorization_generation bigint,
    p_slot integer,
    p_proof_jti text,
    p_admission_jti uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_device public.devices%rowtype;
begin
    if p_device_id is null or p_device_id !~ '^wd_[a-z2-7]{16}$'
       or p_public_key is null or p_public_key !~ '^[A-Za-z0-9_-]{43}$'
       or p_authorization_generation is null or p_authorization_generation < 1
       or p_slot is null or p_slot not between 1 and 32
       or p_proof_jti is null or p_proof_jti !~ '^[A-Za-z0-9_-]{22}$'
       or p_admission_jti is null then
        raise exception 'invalid agent admission issue scope' using errcode = '22023';
    end if;

    select d.*
      into v_device
      from public.devices as d
     where d.device_id = p_device_id
     for update;

    if not found
       or v_device.public_key is distinct from p_public_key
       or v_device.kind not in ('agent', 'hybrid')
       or v_device.revoked_at is not null
       or v_device.revocation_pending
       or v_device.authorization_generation <> p_authorization_generation then
        return false;
    end if;

    insert into public.agent_admission_audit_events (
        device_id, event_type, slot, proof_jti, admission_jti, reason
    )
    values (
        p_device_id, 'issued', p_slot, p_proof_jti, p_admission_jti, 'issued'
    );
    return true;
end;
$$;

revoke all on function public.authorize_agent_admission_issue(text, text, bigint, integer, text, uuid)
from public, anon, authenticated;
grant execute on function public.authorize_agent_admission_issue(text, text, bigint, integer, text, uuid)
to service_role;

create or replace function public.claim_device_revocation_dispatches(
    p_limit integer default 20,
    p_lease_seconds integer default 60,
    p_device_id text default null
)
returns table (
    id uuid,
    device_id text,
    authorization_generation bigint,
    claim_token uuid
)
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_limit is null or p_limit < 1 or p_limit > 100
       or p_lease_seconds is null or p_lease_seconds < 10 or p_lease_seconds > 300
       or (p_device_id is not null and p_device_id !~ '^wd_[a-z2-7]{16}$') then
        raise exception 'invalid device revocation dispatch claim' using errcode = '22023';
    end if;

    return query
    with candidates as (
        select outbox.id
          from public.device_revocation_dispatch_outbox as outbox
         where outbox.status = 'pending'
           and outbox.next_attempt_at <= pg_catalog.now()
           and (outbox.claimed_until is null or outbox.claimed_until <= pg_catalog.now())
           and (p_device_id is null or outbox.device_id = p_device_id)
         order by outbox.next_attempt_at, outbox.created_at, outbox.id
         for update skip locked
         limit p_limit
    )
    update public.device_revocation_dispatch_outbox as outbox
       set claim_token = gen_random_uuid(),
           claimed_until = pg_catalog.now() + pg_catalog.make_interval(secs => p_lease_seconds),
           attempts = least(outbox.attempts + 1, 1000000),
           last_attempt_at = pg_catalog.now()
      from candidates
     where outbox.id = candidates.id
    returning outbox.id, outbox.device_id, outbox.authorization_generation, outbox.claim_token;
end;
$$;

revoke all on function public.claim_device_revocation_dispatches(integer, integer, text)
from public, anon, authenticated;
grant execute on function public.claim_device_revocation_dispatches(integer, integer, text)
to service_role;

create or replace function public.complete_device_revocation_dispatch(
    p_id uuid,
    p_claim_token uuid,
    p_authorization_generation bigint
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_device_id text;
begin
    if p_id is null or p_claim_token is null or p_authorization_generation is null
       or p_authorization_generation < 1 then
        raise exception 'invalid device revocation dispatch acknowledgement' using errcode = '22023';
    end if;

    update public.device_revocation_dispatch_outbox as outbox
       set status = 'dispatched',
           dispatched_at = pg_catalog.now(),
           claim_token = null,
           claimed_until = null,
           last_error = null
     where outbox.id = p_id
       and outbox.status = 'pending'
       and outbox.claim_token = p_claim_token
       and outbox.authorization_generation = p_authorization_generation
       and outbox.claimed_until > pg_catalog.now()
    returning outbox.device_id into v_device_id;

    if not found then
        return false;
    end if;

    perform pg_catalog.set_config('app.wedecent_revocation_ack', 'true', true);
    update public.devices
       set revocation_pending = false
     where device_id = v_device_id
       and authorization_generation = p_authorization_generation
       and revoked_at is not null
       and revocation_pending;

    return true;
end;
$$;

revoke all on function public.complete_device_revocation_dispatch(uuid, uuid, bigint)
from public, anon, authenticated;
grant execute on function public.complete_device_revocation_dispatch(uuid, uuid, bigint)
to service_role;

create or replace function public.fail_device_revocation_dispatch(
    p_id uuid,
    p_claim_token uuid,
    p_authorization_generation bigint,
    p_error_code text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_attempts integer;
    v_backoff_seconds integer;
begin
    if p_id is null or p_claim_token is null or p_authorization_generation is null
       or p_authorization_generation < 1
       or p_error_code is null or p_error_code !~ '^[a-z0-9_]{1,64}$' then
        raise exception 'invalid device revocation dispatch failure' using errcode = '22023';
    end if;

    select outbox.attempts
      into v_attempts
      from public.device_revocation_dispatch_outbox as outbox
     where outbox.id = p_id
       and outbox.status = 'pending'
       and outbox.claim_token = p_claim_token
       and outbox.authorization_generation = p_authorization_generation
       and outbox.claimed_until > pg_catalog.now()
     for update;

    if not found then
        return false;
    end if;

    v_backoff_seconds := least(3600, (5 * pg_catalog.power(2, least(greatest(v_attempts - 1, 0), 10)))::integer);
    update public.device_revocation_dispatch_outbox
       set next_attempt_at = pg_catalog.now() + pg_catalog.make_interval(secs => v_backoff_seconds),
           claim_token = null,
           claimed_until = null,
           last_error = p_error_code
     where id = p_id
       and status = 'pending'
       and claim_token = p_claim_token
       and authorization_generation = p_authorization_generation;

    return found;
end;
$$;

revoke all on function public.fail_device_revocation_dispatch(uuid, uuid, bigint, text)
from public, anon, authenticated;
grant execute on function public.fail_device_revocation_dispatch(uuid, uuid, bigint, text)
to service_role;

commit;
