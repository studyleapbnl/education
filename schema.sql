-- Study LEAP — D1 database schema (run once in Cloudflare → D1 → studyleap-leads → Console)

CREATE TABLE IF NOT EXISTS leads (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  phone       TEXT NOT NULL,
  email       TEXT DEFAULT '',
  city        TEXT DEFAULT '',
  loanType    TEXT DEFAULT '',
  loanAmount  TEXT DEFAULT '',
  course      TEXT DEFAULT '',
  destination TEXT DEFAULT '',
  source      TEXT DEFAULT 'Website',
  status      TEXT DEFAULT 'New',
  assignedTo  TEXT DEFAULT '',
  followup    TEXT DEFAULT '',
  message     TEXT DEFAULT '',
  notes       TEXT DEFAULT '[]',
  createdAt   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_leads_status_created ON leads (status, createdAt);
CREATE INDEX IF NOT EXISTS idx_leads_created        ON leads (createdAt);

CREATE TABLE IF NOT EXISTS rate_limits (
  ip         TEXT PRIMARY KEY,
  timestamps TEXT DEFAULT '[]',
  updatedAt  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_updated ON rate_limits (updatedAt);

-- v6: server-side OTP for the document-upload page (the Worker also creates these on first use)
CREATE TABLE IF NOT EXISTS otp_codes (
  phone        TEXT PRIMARY KEY,
  code_hash    TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  sent_at      INTEGER NOT NULL,
  send_count   INTEGER NOT NULL DEFAULT 1,
  window_start INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hit_limits (
  k         TEXT PRIMARY KEY,
  hits      TEXT NOT NULL,
  updatedAt INTEGER NOT NULL
);
