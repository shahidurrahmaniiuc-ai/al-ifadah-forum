-- Al-Ifadah Forum: read-only security audit
-- Run this in Supabase SQL Editor. It does not change any data or permissions.

-- 1) Columns in forum tables (look for nominee / NID fields)
select table_name, column_name, data_type, is_nullable
from information_schema.columns
where table_schema = 'public'
  and table_name in (
    'members','deposits','investments','plans',
    'member_unit_history','documents'
  )
order by table_name, ordinal_position;

-- 2) Current RLS status
select n.nspname as schema_name,
       c.relname as table_name,
       c.relrowsecurity as rls_enabled,
       c.relforcerowsecurity as force_rls
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and c.relname in (
    'members','deposits','investments','plans',
    'member_unit_history','documents'
  )
order by c.relname;

-- 3) Current policies on those tables
select schemaname, tablename, policyname, permissive,
       roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
  and tablename in (
    'members','deposits','investments','plans',
    'member_unit_history','documents'
  )
order by tablename, policyname;

-- 4) Storage bucket visibility (PDF bucket)
select id, name, public
from storage.buckets
where id = 'forum-documents';
