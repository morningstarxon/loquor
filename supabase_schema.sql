-- ============================================================
-- Loquor Supabase Schema
-- Run this in Supabase SQL Editor (Project > SQL Editor > New query)
-- ============================================================

-- Users: username/password auth (server-side hashing, NOT Supabase Auth)
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  username_lower text unique not null, -- for case-insensitive lookup
  password_hash text not null,          -- scrypt hash, format: salt:hash
  avatar_url text,                      -- public URL in Storage, null = default
  created_at timestamptz not null default now()
);

create index if not exists idx_users_username_lower on users (username_lower);

-- Sessions: random tokens for "remember me" auto-login (token itself is
-- never stored, only its SHA-256 hash, same principle as password hashing)
create table if not exists sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  token_hash text unique not null,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index if not exists idx_sessions_token_hash on sessions (token_hash);
create index if not exists idx_sessions_user_id on sessions (user_id);

-- Messages: covers both the public room and DMs.
-- room = 'public' for the public room.
-- room = 'dm:<uuid1>:<uuid2>' (user ids sorted lexicographically) for DMs.
create table if not exists messages (
  id bigint generated always as identity primary key,
  room text not null,
  sender_id uuid not null references users(id) on delete cascade,
  sender_username text not null,   -- denormalized for fast render, avoids join
  text text not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_messages_room_created on messages (room, created_at desc);

-- Row Level Security: locked down. All access goes through the Node server
-- using the service_role key, never the anon key, so RLS just needs to
-- deny the anon/public role entirely.
alter table users enable row level security;
alter table sessions enable row level security;
alter table messages enable row level security;

-- No policies created for anon/authenticated roles = no access for them.
-- The server uses the service_role key which bypasses RLS by design.

-- ============================================================
-- Storage: avatar bucket
-- Run this section too (or set up via Dashboard > Storage > New bucket)
-- ============================================================
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do nothing;

-- Public read for avatars (so <img src> works directly), no public write
-- (server uses service_role key to upload, bypassing this policy anyway)
create policy if not exists "Public read avatars"
  on storage.objects for select
  using (bucket_id = 'avatars');
