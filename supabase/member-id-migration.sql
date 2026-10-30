begin;
create sequence if not exists public.member_code_seq start with 1;
alter table public.members add column if not exists member_code text;
alter table public.members alter column member_code set default ('IF-' || lpad(nextval('public.member_code_seq')::text, 4, '0'));
update public.members set member_code='IF-' || lpad(nextval('public.member_code_seq')::text, 4, '0') where member_code is null;
create unique index if not exists members_member_code_unique on public.members(member_code);
commit;
