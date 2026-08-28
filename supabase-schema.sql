-- ACRAFT dashboard + calendar app: Supabase schema
-- Run this once in the Supabase project's SQL Editor
-- (https://supabase.com/dashboard/project/timytwkdfmchzojvzjzq/sql/new).
--
-- Data is protected by a single shared passcode instead of per-user
-- login. The passcode is checked two ways:
--   1. check_passcode(): callable by anyone, used by the app to verify
--      a passcode the visitor typed in before saving it locally.
--   2. Row Level Security policies on every table, which require the
--      same passcode to be sent as the "x-app-passcode" request header
--      on every read/write. This is the actual enforcement -- even if
--      someone reads the anon key out of the page source, they still
--      need the header to get real data back.
--
-- To change the passcode later, update the literal 'daruma' value
-- in has_valid_passcode() and check_passcode() below and re-run just
-- those two CREATE OR REPLACE FUNCTION statements.

-- ============================================================
-- 1. Task dashboard (index.html) -- flat task list
-- ============================================================

create table if not exists public.dashboard_tasks (
  id text primary key,
  assignee text not null,
  project text not null,
  due date not null,
  status text not null default '未着手',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ============================================================
-- 2. Calendar app (calendar.html) -- projects with nested tasks
-- ============================================================

create table if not exists public.calendar_projects (
  id text primary key,
  name text not null,
  due_date date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.calendar_tasks (
  id text primary key,
  project_id text not null references public.calendar_projects(id) on delete cascade,
  name text not null,
  assignee text not null,
  due date not null,
  status text not null default '未着手',
  total integer not null default 1,
  done integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists calendar_tasks_project_id_idx on public.calendar_tasks(project_id);

-- ============================================================
-- 3. Passcode functions
-- ============================================================

-- Checks the request's "x-app-passcode" header. Used inside RLS
-- policies below -- this is what actually gates every read/write.
create or replace function public.has_valid_passcode()
returns boolean
language sql
stable
as $$
  select coalesce(current_setting('request.headers', true)::json->>'x-app-passcode', '') = 'daruma';
$$;

-- Lets the app verify a typed-in passcode via an explicit true/false
-- RPC call, independent of whether any table has rows yet (a plain
-- SELECT can't distinguish "wrong passcode" from "no data").
create or replace function public.check_passcode(input_passcode text)
returns boolean
language sql
stable
as $$
  select input_passcode = 'daruma';
$$;

grant execute on function public.check_passcode(text) to anon;

-- ============================================================
-- 4. Row Level Security
-- ============================================================

alter table public.dashboard_tasks enable row level security;
alter table public.calendar_projects enable row level security;
alter table public.calendar_tasks enable row level security;

drop policy if exists "passcode gate" on public.dashboard_tasks;
create policy "passcode gate" on public.dashboard_tasks
  for all to anon
  using (public.has_valid_passcode())
  with check (public.has_valid_passcode());

drop policy if exists "passcode gate" on public.calendar_projects;
create policy "passcode gate" on public.calendar_projects
  for all to anon
  using (public.has_valid_passcode())
  with check (public.has_valid_passcode());

drop policy if exists "passcode gate" on public.calendar_tasks;
create policy "passcode gate" on public.calendar_tasks
  for all to anon
  using (public.has_valid_passcode())
  with check (public.has_valid_passcode());

grant select, insert, update, delete on public.dashboard_tasks to anon;
grant select, insert, update, delete on public.calendar_projects to anon;
grant select, insert, update, delete on public.calendar_tasks to anon;
