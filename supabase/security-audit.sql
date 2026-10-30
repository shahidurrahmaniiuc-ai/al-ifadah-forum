-- Al-Ifadah Forum: read-only security audit
-- This script does NOT change data, permissions, or policies.

-- 1) All columns in public tables (identify member/contact/nominee/NID fields)
select table_name, column_name, data_type, is_nullable
from information_schema.columns
where table_schema = 'public'
order by table_name, ordinal_position;

-- 2) RLS status for every public table
select n.nspname as schema_name,
       c.relname as table_name,
       c.relrowsecurity as rls_enabled,
       c.relforcerowsecurity as force_rls
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind in ('r','p')
order by c.relname;

-- 3) All current policies in public schema
select schemaname, tablename, policyname, permissive,
       roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
order by tablename, policyname;

-- 4) Table privileges granted to anon/authenticated
select table_name, grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and grantee in ('anon','authenticated')
order by table_name, grantee, privilege_type;

-- 5) All Storage buckets and public/private visibility
select id, name, public
from storage.buckets
order by id;

-- 6) Storage policies
select schemaname, tablename, policyname, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'storage'
order by tablename, policyname;
