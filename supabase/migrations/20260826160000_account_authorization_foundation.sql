-- WeDecent account authorization foundation.
--
-- This migration intentionally does not issue relay grants yet. It creates the
-- account/device registry and RLS boundary that the future trusted grant issuer
-- will use. Browser-authenticated users cannot insert or mutate device identity
-- rows directly; enrollment must go through a trusted server/Edge Function that
-- verifies proof of possession of the endpoint's Ed25519 identity key.

begin;

create schema if not exists wedecent_private;
revoke all on schema wedecent_private from public;
revoke all on schema wedecent_private from anon;
revoke all on schema wedecent_private from authenticated;
grant usage on schema wedecent_private to authenticated;

create type public.organization_role as enum ('owner', 'admin', 'member');
create type public.device_kind as enum ('client', 'agent', 'hybrid');
create type public.device_permission as enum ('terminal.connect');

create table public.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    slug text not null unique,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint organizations_name_length
        check (char_length(btrim(name)) between 1 and 128),
    constraint organizations_slug_format
        check (
            char_length(slug) between 3 and 64
            and slug = lower(slug)
            and slug ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$'
        )
);

create table public.organization_memberships (
    organization_id uuid not null references public.organizations(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role public.organization_role not null default 'member',
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    primary key (organization_id, user_id)
);

create index organization_memberships_user_id_idx
    on public.organization_memberships (user_id);

create index organization_memberships_org_role_idx
    on public.organization_memberships (organization_id, role);

create table public.devices (
    device_id text primary key,
    public_key text not null unique,
    kind public.device_kind not null,
    name text not null,
    owner_user_id uuid not null references auth.users(id) on delete cascade,
    organization_id uuid references public.organizations(id) on delete set null,
    enrolled_at timestamptz not null default now(),
    last_seen_at timestamptz,
    revoked_at timestamptz,
    metadata jsonb not null default '{}'::jsonb,
    constraint devices_device_id_format
        check (device_id ~ '^wd_[a-z2-7]{16}$'),
    constraint devices_public_key_format
        check (public_key ~ '^[A-Za-z0-9_-]{43}$'),
    constraint devices_name_length
        check (char_length(btrim(name)) between 1 and 128),
    constraint devices_metadata_object
        check (jsonb_typeof(metadata) = 'object')
);

create index devices_owner_user_id_idx
    on public.devices (owner_user_id);

create index devices_organization_id_idx
    on public.devices (organization_id)
    where organization_id is not null;

create table public.device_access (
    device_id text not null references public.devices(device_id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    permission public.device_permission not null,
    granted_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    primary key (device_id, user_id, permission),
    constraint device_access_expiry
        check (expires_at is null or expires_at > created_at)
);

create index device_access_user_id_idx
    on public.device_access (user_id, device_id);

-- Trusted enrollment code writes this table with a service credential. The
-- browser never receives table privileges. Store only the digest of the random
-- challenge; the signed challenge itself is supplied back by the endpoint.
create table public.device_enrollment_challenges (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    device_id text not null,
    challenge_sha256 bytea not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint device_enrollment_challenge_device_id_format
        check (device_id ~ '^wd_[a-z2-7]{16}$'),
    constraint device_enrollment_challenge_digest_length
        check (octet_length(challenge_sha256) = 32),
    constraint device_enrollment_challenge_expiry
        check (expires_at > created_at)
);

create index device_enrollment_challenges_lookup_idx
    on public.device_enrollment_challenges (user_id, device_id, expires_at desc);

-- This is the durable audit record for future short-lived authorization grants.
-- Only a trusted grant issuer may insert/revoke these rows. The signed grant is
-- not stored here; jti is the server-side identifier used for audit/revocation.
create table public.connection_grants (
    id uuid primary key default gen_random_uuid(),
    jti uuid not null unique default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    organization_id uuid references public.organizations(id) on delete set null,
    client_device_id text not null references public.devices(device_id) on delete cascade,
    target_device_id text not null references public.devices(device_id) on delete cascade,
    permission public.device_permission not null default 'terminal.connect',
    issued_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked_at timestamptz,
    constraint connection_grants_distinct_devices
        check (client_device_id <> target_device_id),
    constraint connection_grants_short_lived
        check (
            expires_at > issued_at
            and expires_at <= issued_at + interval '5 minutes'
        )
);

create index connection_grants_user_issued_idx
    on public.connection_grants (user_id, issued_at desc);

create index connection_grants_target_active_idx
    on public.connection_grants (target_device_id, expires_at)
    where revoked_at is null;

-- Keep updated_at server-controlled instead of trusting clients to supply it.
create or replace function wedecent_private.touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

create trigger organizations_touch_updated_at
before update on public.organizations
for each row execute function wedecent_private.touch_updated_at();

create or replace function wedecent_private.organization_role_for(target_organization_id uuid)
returns public.organization_role
language sql
stable
security definer
set search_path = ''
as $$
    select m.role
    from public.organization_memberships as m
    where m.organization_id = target_organization_id
      and m.user_id = (select auth.uid())
    limit 1;
$$;

create or replace function wedecent_private.is_organization_member(target_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.organization_memberships as m
        where m.organization_id = target_organization_id
          and m.user_id = (select auth.uid())
    );
$$;

create or replace function wedecent_private.can_manage_organization(target_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select coalesce(
        (select wedecent_private.organization_role_for(target_organization_id)) in ('owner', 'admin'),
        false
    );
$$;

create or replace function wedecent_private.is_organization_owner(target_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select coalesce(
        (select wedecent_private.organization_role_for(target_organization_id)) = 'owner',
        false
    );
$$;

create or replace function wedecent_private.organization_has_other_owner(
    target_organization_id uuid,
    excluded_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.organization_memberships as m
        where m.organization_id = target_organization_id
          and m.user_id <> excluded_user_id
          and m.role = 'owner'
    );
$$;

create or replace function wedecent_private.can_bootstrap_organization(target_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.organizations as o
        where o.id = target_organization_id
          and o.created_by = (select auth.uid())
    )
    and not exists (
        select 1
        from public.organization_memberships as m
        where m.organization_id = target_organization_id
    );
$$;

create or replace function wedecent_private.can_manage_device(target_device_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.devices as d
        where d.device_id = target_device_id
          and d.revoked_at is null
          and (
              d.owner_user_id = (select auth.uid())
              or (
                  d.organization_id is not null
                  and (select wedecent_private.can_manage_organization(d.organization_id))
              )
          )
    );
$$;

create or replace function wedecent_private.can_view_device(target_device_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.devices as d
        where d.device_id = target_device_id
          and d.revoked_at is null
          and (
              d.owner_user_id = (select auth.uid())
              or (
                  d.organization_id is not null
                  and (select wedecent_private.is_organization_member(d.organization_id))
              )
              or exists (
                  select 1
                  from public.device_access as a
                  where a.device_id = d.device_id
                    and a.user_id = (select auth.uid())
                    and (a.expires_at is null or a.expires_at > now())
              )
          )
    );
$$;

create or replace function wedecent_private.can_connect_device(target_device_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.devices as d
        where d.device_id = target_device_id
          and d.revoked_at is null
          and (
              d.owner_user_id = (select auth.uid())
              or (
                  d.organization_id is not null
                  and (select wedecent_private.can_manage_organization(d.organization_id))
              )
              or exists (
                  select 1
                  from public.device_access as a
                  where a.device_id = d.device_id
                    and a.user_id = (select auth.uid())
                    and a.permission = 'terminal.connect'
                    and (a.expires_at is null or a.expires_at > now())
              )
          )
    );
$$;

-- Final-owner protection is enforced by membership RLS using the
-- security-definer organization_has_other_owner() helper.

alter table public.organizations enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.devices enable row level security;
alter table public.device_access enable row level security;
alter table public.device_enrollment_challenges enable row level security;
alter table public.connection_grants enable row level security;

-- Remove implicit Data API privileges first, then grant only the operations that
-- have matching RLS policies. anon receives no privileges on control-plane data.
revoke all on public.organizations from anon, authenticated;
revoke all on public.organization_memberships from anon, authenticated;
revoke all on public.devices from anon, authenticated;
revoke all on public.device_access from anon, authenticated;
revoke all on public.device_enrollment_challenges from anon, authenticated;
revoke all on public.connection_grants from anon, authenticated;

revoke all on function wedecent_private.organization_role_for(uuid) from public, anon;
revoke all on function wedecent_private.is_organization_member(uuid) from public, anon;
revoke all on function wedecent_private.can_manage_organization(uuid) from public, anon;
revoke all on function wedecent_private.is_organization_owner(uuid) from public, anon;
revoke all on function wedecent_private.organization_has_other_owner(uuid, uuid) from public, anon;
revoke all on function wedecent_private.can_bootstrap_organization(uuid) from public, anon;
revoke all on function wedecent_private.can_manage_device(text) from public, anon;
revoke all on function wedecent_private.can_view_device(text) from public, anon;
revoke all on function wedecent_private.can_connect_device(text) from public, anon;

grant execute on function wedecent_private.organization_role_for(uuid) to authenticated;
grant execute on function wedecent_private.is_organization_member(uuid) to authenticated;
grant execute on function wedecent_private.can_manage_organization(uuid) to authenticated;
grant execute on function wedecent_private.is_organization_owner(uuid) to authenticated;
grant execute on function wedecent_private.organization_has_other_owner(uuid, uuid) to authenticated;
grant execute on function wedecent_private.can_bootstrap_organization(uuid) to authenticated;
grant execute on function wedecent_private.can_manage_device(text) to authenticated;
grant execute on function wedecent_private.can_view_device(text) to authenticated;
grant execute on function wedecent_private.can_connect_device(text) to authenticated;

grant select on public.organizations to authenticated;
grant insert (name, slug, created_by) on public.organizations to authenticated;
grant update (name, slug) on public.organizations to authenticated;
grant delete on public.organizations to authenticated;

grant select, delete on public.organization_memberships to authenticated;
grant insert (organization_id, user_id, role, created_by)
    on public.organization_memberships to authenticated;
grant update (role) on public.organization_memberships to authenticated;

grant select on public.devices to authenticated;

grant select, delete on public.device_access to authenticated;
grant insert (device_id, user_id, permission, granted_by, expires_at)
    on public.device_access to authenticated;
grant update (expires_at) on public.device_access to authenticated;

grant select on public.connection_grants to authenticated;

-- Trusted server/Edge Function code uses the Supabase service role. RLS still
-- remains enabled so accidentally using a user token does not gain write access.
grant all on public.organizations to service_role;
grant all on public.organization_memberships to service_role;
grant all on public.devices to service_role;
grant all on public.device_access to service_role;
grant all on public.device_enrollment_challenges to service_role;
grant all on public.connection_grants to service_role;

-- Organization policies.
create policy organizations_select_member
on public.organizations
for select
to authenticated
using (
    created_by = (select auth.uid())
    or (select wedecent_private.is_organization_member(id))
);

create policy organizations_insert_self
on public.organizations
for insert
to authenticated
with check (created_by = (select auth.uid()));

create policy organizations_update_manager
on public.organizations
for update
to authenticated
using (
    created_by = (select auth.uid())
    or (select wedecent_private.can_manage_organization(id))
)
with check (
    created_by = (select auth.uid())
    or (select wedecent_private.can_manage_organization(id))
);

create policy organizations_delete_owner
on public.organizations
for delete
to authenticated
using (
    created_by = (select auth.uid())
    or (select wedecent_private.is_organization_owner(id))
);

-- Membership policies. The creator may bootstrap exactly their own owner row.
create policy organization_memberships_select_member
on public.organization_memberships
for select
to authenticated
using ((select wedecent_private.is_organization_member(organization_id)));

create policy organization_memberships_insert_manager_or_bootstrap
on public.organization_memberships
for insert
to authenticated
with check (
    (
        user_id = (select auth.uid())
        and role = 'owner'
        and created_by = (select auth.uid())
        and (select wedecent_private.can_bootstrap_organization(organization_id))
    )
    or (
        (select wedecent_private.can_manage_organization(organization_id))
        and created_by = (select auth.uid())
        and (
            role <> 'owner'
            or (select wedecent_private.is_organization_owner(organization_id))
        )
    )
);

create policy organization_memberships_update_manager
on public.organization_memberships
for update
to authenticated
using (
    (select wedecent_private.can_manage_organization(organization_id))
    and (
        role <> 'owner'
        or (
            (select wedecent_private.is_organization_owner(organization_id))
            and (select wedecent_private.organization_has_other_owner(organization_id, user_id))
        )
    )
)
with check (
    (select wedecent_private.can_manage_organization(organization_id))
    and (
        role <> 'owner'
        or (select wedecent_private.is_organization_owner(organization_id))
    )
);

create policy organization_memberships_delete_manager
on public.organization_memberships
for delete
to authenticated
using (
    (select wedecent_private.can_manage_organization(organization_id))
    and (
        role <> 'owner'
        or (
            (select wedecent_private.is_organization_owner(organization_id))
            and (select wedecent_private.organization_has_other_owner(organization_id, user_id))
        )
    )
);

-- Device identity rows are service-managed. Browser users may only read rows
-- that are relevant to them; there are intentionally no insert/update/delete
-- policies or grants on public.devices.
create policy devices_select_authorized
on public.devices
for select
to authenticated
using ((select wedecent_private.can_view_device(device_id)));

-- Explicit per-user terminal access is manageable only by a device owner or an
-- organization owner/admin. A user can always see their own access rows.
create policy device_access_select_relevant
on public.device_access
for select
to authenticated
using (
    user_id = (select auth.uid())
    or (select wedecent_private.can_manage_device(device_id))
);

create policy device_access_insert_manager
on public.device_access
for insert
to authenticated
with check (
    (select wedecent_private.can_manage_device(device_id))
    and granted_by = (select auth.uid())
);

create policy device_access_update_manager
on public.device_access
for update
to authenticated
using ((select wedecent_private.can_manage_device(device_id)))
with check ((select wedecent_private.can_manage_device(device_id)));

create policy device_access_delete_manager
on public.device_access
for delete
to authenticated
using ((select wedecent_private.can_manage_device(device_id)));

-- Short-lived grants are issued/revoked by trusted server code. Authenticated
-- users can inspect only their own audit records.
create policy connection_grants_select_self
on public.connection_grants
for select
to authenticated
using (user_id = (select auth.uid()));

comment on table public.devices is
'Cryptographic WeDecent endpoint registry. Writes are restricted to trusted enrollment code that verifies Ed25519 proof of possession.';

comment on table public.device_enrollment_challenges is
'Server-only enrollment challenge state. No anon/authenticated Data API privileges or RLS policies are granted.';

comment on table public.connection_grants is
'Audit/revocation records for future server-issued short-lived terminal authorization grants. Writes are server-only.';

commit;
