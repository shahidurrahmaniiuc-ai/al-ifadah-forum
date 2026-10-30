-- Al-Ifadah Forum: member unit and status management
-- Run once in Supabase SQL Editor.
begin;

alter table public.members
  add column if not exists units integer not null default 1
    check (units >= 0),
  add column if not exists is_active boolean not null default true,
  add column if not exists unit_updated_at timestamptz not null default now();

create table if not exists public.member_unit_history (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.members(id) on delete restrict,
  old_units integer not null check (old_units >= 0),
  new_units integer not null check (new_units >= 0),
  changed_at timestamptz not null default now(),
  changed_by uuid references auth.users(id) on delete set null,
  note text
);

alter table public.member_unit_history enable row level security;
grant select on public.member_unit_history to anon, authenticated;
grant insert on public.member_unit_history to authenticated;

drop policy if exists "Public can view unit change history" on public.member_unit_history;
create policy "Public can view unit change history"
on public.member_unit_history for select to anon, authenticated
using (true);

drop policy if exists "Admins can record unit changes" on public.member_unit_history;
create policy "Admins can record unit changes"
on public.member_unit_history for insert to authenticated
with check (public.is_forum_admin());

-- Inactive members remain in the database so historical deposits are preserved.
-- Do not delete member rows or their deposit records.

commit;
