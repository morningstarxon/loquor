# Loquor — Setup & Deploy Guide

## 1. Supabase setup

1. Go to https://supabase.com, create a free project (pick a region close to
   where your Render service will run, e.g. Oregon/US-West).
2. Once it's provisioned, open **SQL Editor** (left sidebar) → **New query**.
3. Paste in the entire contents of `supabase_schema.sql` and run it. This creates:
   - `users` — username, password hash, avatar URL
   - `sessions` — hashed "remember me" tokens
   - `messages` — public + DM history
   - an `avatars` **Storage** bucket (public read)
4. Go to **Project Settings → API**. You need two values for Render:
   - **Project URL** → `SUPABASE_URL`
   - **service_role key** (NOT the `anon` key — this one bypasses Row Level
     Security, which is what lets the Node server manage everything server-side)
     → `SUPABASE_SERVICE_ROLE_KEY`

   ⚠️ The `service_role` key is effectively a master key to your database.
   Never put it in frontend code — it only ever lives in Render's environment
   variables, which is exactly how this app uses it.

That's it for Supabase — no Auth product setup needed, since login is
handled entirely by our own server logic (scrypt-hashed passwords, hashed
session tokens), not Supabase Auth.

## 2. Render setup

1. Push this project to a GitHub repo.
2. On Render: **New → Web Service**, connect the repo.
3. Settings:
   - **Runtime**: Node
   - **Build command**: `npm install`
   - **Start command**: `npm start`
   - **Instance type**: Free is fine to start (it'll spin down on
     inactivity — that's fine, since all state lives in Supabase, not memory)
4. Add environment variables (Render dashboard → Environment):
   - `SUPABASE_URL` = your project URL
   - `SUPABASE_SERVICE_ROLE_KEY` = your service_role key
   - `PORT` is set automatically by Render, no need to add it
5. Deploy. Once live, visit the Render URL — you should see the Loquor
   login screen.

## 3. How auth works (so you know what you're deploying)

- **Sign up**: password is hashed server-side with `scrypt` (Node's built-in,
  no external crypto lib needed) before it ever touches the database. The
  raw password is never stored anywhere.
- **Log in**: server re-hashes the submitted password with the stored salt
  and compares in constant time (`crypto.timingSafeEqual`), then issues a
  random 32-byte session token.
- **"Remember me"**: only the token is saved in the browser's localStorage —
  never the password. The server stores only a SHA-256 hash of that token
  in Supabase, so even a leaked database doesn't hand out usable tokens.
  Tokens expire after 30 days (`SESSION_TTL_DAYS` in `server.js`).
- **WebSocket auth**: the token is passed as a query param when opening the
  socket; the server validates it against Supabase before accepting the
  connection.

## 4. Rooms & history retention

- Public room keeps the **last 10 messages**.
- Each DM thread keeps the **last 13 messages**.
- Older messages are pruned automatically after each new message (best-effort,
  fire-and-forget, so it never slows down sending).

## 5. Avatars

- Users upload PNG/JPEG/WEBP/GIF, capped at 500KB (enforced both client-side
  for instant feedback and server-side as the real check).
- Stored in the Supabase `avatars` Storage bucket at `<user_id>/avatar.<ext>`,
  publicly readable, served directly from Supabase's CDN — the Node server
  never proxies image bytes.

## 6. Low-frame-rate device notes

A few deliberate choices to keep this smooth on weak/low-power devices:
- No CSS animations on message render (removed the old fade-in keyframe
  that ran on every single message).
- No `transition` on layout-affecting properties in the hot path.
- Message list re-render is append-only on new messages (`appendChild`),
  full re-render (`innerHTML = ''` + rebuild) only happens on room switch,
  not on every incoming message.
- WebSocket heartbeat (30s ping/pong) proactively drops dead sockets so
  reconnect logic kicks in cleanly instead of a device hanging on a zombie
  connection.
