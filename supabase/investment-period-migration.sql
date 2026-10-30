-- Al-Ifadah Forum: investment period tracking
-- Run once in Supabase SQL Editor.
alter table public.investments
  add column if not exists investment_end_date date;

comment on column public.investments.investment_end_date
  is 'Planned end date for this forum-level investment; investment_date is the start date.';
