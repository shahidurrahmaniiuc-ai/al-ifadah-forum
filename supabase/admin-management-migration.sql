-- Al-Ifadah Forum: secure member account linking and admin role management
begin;

alter table public.members
  add column if not exists user_id uuid unique references auth.users(id) on delete set null;

create or replace function public.is_forum_super_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select lower(coalesce(auth.jwt() ->> 'email', '')) = 'shahidur.rahman.iiuc@gmail.com';
$$;

create or replace function public.is_forum_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_forum_super_admin()
    or exists (
      select 1 from public.members m
      where m.user_id = auth.uid() and m.role = 'admin'
    );
$$;

create or replace function public.claim_forum_member_account(
  p_member_code text,
  p_phone text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_email text;
  v_member_id uuid;
begin
  if auth.uid() is null then
    raise exception 'প্রথমে ইমেইল ও পাসওয়ার্ড দিয়ে লগইন করুন।';
  end if;

  v_email := lower(coalesce(auth.jwt() ->> 'email', ''));
  if v_email = '' or auth.jwt() ->> 'email_confirmed_at' is null then
    raise exception 'আগে ইমেইল নিশ্চিত করুন।';
  end if;

  update public.members
     set user_id = auth.uid()
   where upper(trim(member_code)) = upper(trim(p_member_code))
     and regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g')
         = regexp_replace(coalesce(p_phone,''), '[^0-9]', '', 'g')
     and lower(trim(coalesce(email,''))) = v_email
     and user_id is null
     and is_active is distinct from false
  returning id into v_member_id;

  if v_member_id is null then
    raise exception 'সদস্যের ID, মোবাইল ও লগইন ইমেইল মেলেনি, অথবা অ্যাকাউন্ট আগে যুক্ত আছে।';
  end if;

  return jsonb_build_object('success', true, 'member_id', v_member_id);
end;
$$;

create or replace function public.set_forum_member_role(
  p_member_code text,
  p_phone text,
  p_email text,
  p_role text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_member_id uuid;
begin
  if not public.is_forum_super_admin() then
    raise exception 'শুধু Super Admin এই কাজ করতে পারবেন।';
  end if;

  if p_role not in ('member', 'admin') then
    raise exception 'অনুমোদিত ভূমিকা নয়।';
  end if;

  if upper(trim(p_member_code)) = 'IF-0001'
     and p_role <> 'admin' then
    raise exception 'প্রধান Super Admin-এর ভূমিকা পরিবর্তন করা যাবে না।';
  end if;

  update public.members
     set role = p_role
   where upper(trim(member_code)) = upper(trim(p_member_code))
     and regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g')
         = regexp_replace(coalesce(p_phone,''), '[^0-9]', '', 'g')
     and lower(trim(coalesce(email,''))) = lower(trim(coalesce(p_email,'')))
     and user_id is not null
     and is_active is distinct from false
  returning id into v_member_id;

  if v_member_id is null then
    raise exception 'সদস্যের তথ্য মেলেনি, সদস্য অ্যাকাউন্ট সক্রিয় নয়, অথবা সে আগে ওয়েবসাইট অ্যাকাউন্ট যুক্ত করেনি।';
  end if;

  return jsonb_build_object('success', true, 'member_id', v_member_id, 'role', p_role);
end;
$$;

revoke all on function public.claim_forum_member_account(text,text) from public;
grant execute on function public.claim_forum_member_account(text,text) to authenticated;
revoke all on function public.set_forum_member_role(text,text,text,text) from public;
grant execute on function public.set_forum_member_role(text,text,text,text) to authenticated;

commit;
