-- Make organization-owner bootstrap atomic and server-side.
--
-- An authenticated user may create an organization only when created_by = auth.uid()
-- (enforced by organizations_insert_self). A SECURITY DEFINER trigger then creates
-- the first owner membership in the same transaction. This avoids the circular RLS
-- problem of asking an INSERT policy on organization_memberships to prove that the
-- membership table is empty while inserting the first membership row.

begin;

create or replace function wedecent_private.bootstrap_organization_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if new.created_by is null then
        raise exception 'organization creator is required';
    end if;

    insert into public.organization_memberships (
        organization_id,
        user_id,
        role,
        created_by
    )
    values (
        new.id,
        new.created_by,
        'owner'::public.organization_role,
        new.created_by
    );

    return new;
end;
$$;

revoke all on function wedecent_private.bootstrap_organization_owner()
from public, anon, authenticated;

drop trigger if exists organizations_bootstrap_owner
on public.organizations;

create trigger organizations_bootstrap_owner
after insert on public.organizations
for each row
execute function wedecent_private.bootstrap_organization_owner();

-- Repair organizations created before the trigger existed but which still have no
-- membership rows. This is intentionally limited to completely empty membership
-- sets so it cannot silently add an owner to an already-managed organization.
insert into public.organization_memberships (
    organization_id,
    user_id,
    role,
    created_by
)
select
    o.id,
    o.created_by,
    'owner'::public.organization_role,
    o.created_by
from public.organizations as o
where o.created_by is not null
  and not exists (
      select 1
      from public.organization_memberships as m
      where m.organization_id = o.id
  );

-- First-owner creation is now handled only by the trusted trigger. Authenticated
-- membership inserts are reserved for organization managers.
drop policy if exists organization_memberships_insert_manager_or_bootstrap
on public.organization_memberships;

create policy organization_memberships_insert_manager
on public.organization_memberships
for insert
to authenticated
with check (
    (select wedecent_private.can_manage_organization(organization_id))
    and created_by = (select auth.uid())
    and (
        role <> 'owner'
        or (select wedecent_private.is_organization_owner(organization_id))
    )
);

-- The bootstrap helper is no longer part of the client-facing authorization path.
revoke all on function wedecent_private.can_bootstrap_organization(uuid)
from public, anon, authenticated;

drop function wedecent_private.can_bootstrap_organization(uuid);

commit;
