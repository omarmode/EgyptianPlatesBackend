-- 20260911_client_name_and_usage_simulation.sql
-- Add optional client_name to licenses + voice usage events table for multi-device simulation.

-- 1. Optional client_name on licenses
alter table public.licenses
  add column if not exists client_name text;

comment on column public.licenses.client_name is 'Optional customer/client name for display and billing simulation.';

-- 2. Voice usage events table for idempotent cross-device cost simulation
create table if not exists public.voice_usage_events (
  usage_event_id text primary key,
  license_code text not null,
  device_id text,
  session_id text,
  model text,
  estimation_method text not null default 'TOKEN_USAGE',
  session_seconds real not null default 0,
  prompt_tokens integer not null default 0,
  response_tokens integer not null default 0,
  total_tokens integer not null default 0,
  audio_input_tokens integer not null default 0,
  audio_output_tokens integer not null default 0,
  text_input_tokens integer not null default 0,
  text_output_tokens integer not null default 0,
  estimated_usd real not null default 0,
  estimated_egp real not null default 0,
  raw_metadata jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_voice_usage_created_license
  on public.voice_usage_events (created_at desc, license_code);
