-- Optional PromptPaws decision log table for Supabase.
-- Run in Supabase SQL Editor, then set SUPABASE_URL and SUPABASE_SERVICE_KEY
-- on your server-side host. The service role key bypasses RLS; never expose it
-- to browser code.

create table if not exists promptpaws_decisions (
  id bigserial primary key,
  ts timestamptz not null,
  layer text not null,          -- firewall / screening / session
  decision text not null,       -- pass / flag / block / allow / heighten / refuse / reset
  risk_score real not null,
  signals jsonb not null default '[]',
  session_id text,
  raw_input text,
  extra jsonb not null default '{}'
);

create index if not exists promptpaws_decisions_ts
  on promptpaws_decisions (ts desc);
create index if not exists promptpaws_decisions_session
  on promptpaws_decisions (session_id);
create index if not exists promptpaws_decisions_review
  on promptpaws_decisions (decision, ts desc)
  where decision <> 'pass';

alter table promptpaws_decisions enable row level security;
