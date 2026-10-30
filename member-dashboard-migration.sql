-- Al-Ifadah Forum member dashboard migration
-- Run once in Supabase SQL Editor.
ALTER TABLE public.members
  ADD COLUMN IF NOT EXISTS nominee_name text,
  ADD COLUMN IF NOT EXISTS nominee_phone text,
  ADD COLUMN IF NOT EXISTS nominee_nid text,
  ADD COLUMN IF NOT EXISTS nominee_relation text;

CREATE INDEX IF NOT EXISTS deposits_member_date_idx
  ON public.deposits (member_id, deposit_date DESC);

REVOKE ALL ON TABLE public.members, public.deposits, public.investments,
  public.plans, public.member_unit_history FROM anon;

-- Private bucket must remain private. Members receive access only through
-- an authenticated application flow and a future signed-download endpoint.
UPDATE storage.buckets
SET public = false
WHERE id = 'forum-private-documents';
