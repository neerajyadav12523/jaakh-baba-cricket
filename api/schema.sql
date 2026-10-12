-- Jaakh Baba Cricket Pratiyogita: team registrations (Cloudflare D1 / SQLite)
-- Apply with: npx wrangler d1 execute jaakh-baba --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS teams (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  village       TEXT NOT NULL,
  captain       TEXT NOT NULL,
  phone         TEXT NOT NULL,             -- visible to admin only
  pin_salt      TEXT,                      -- set when the admin approves the team
  pin_hash      TEXT,                      -- HMAC-SHA256(PIN_PEPPER, salt + pin); the PIN itself is never stored
  status        TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
  players       TEXT NOT NULL DEFAULT '[]',        -- JSON array of {"name": "..."}; more fields can be added later
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  ip_hash       TEXT NOT NULL,             -- for spam limits only
  fail_count    INTEGER NOT NULL DEFAULT 0,      -- wrong PIN attempts (phase 2)
  locked_until  TEXT                              -- PIN lock-out end time (phase 2)
);

CREATE UNIQUE INDEX IF NOT EXISTS teams_name_live ON teams (lower(name)) WHERE status != 'rejected';
CREATE INDEX IF NOT EXISTS teams_status ON teams (status);
CREATE INDEX IF NOT EXISTS teams_ip ON teams (ip_hash, created_at);
