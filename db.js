// db.js — Supabase connection (server-side, uses the service_role key).
//
// The service_role key bypasses Row Level Security, so this client has full
// access to every table. It MUST stay on the server and never be shipped to a
// client app. All our public tables have RLS enabled with no policies, so any
// request that is NOT made with this key gets zero access.

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    '[db] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY. ' +
      'Copy .env.example to .env and fill in the values.'
  );
  process.exit(1);
}

if (SUPABASE_SERVICE_ROLE_KEY === 'paste-your-service_role-key-here') {
  console.error(
    '[db] SUPABASE_SERVICE_ROLE_KEY is still the placeholder. ' +
      'Get the real key from Supabase Dashboard -> Project Settings -> API -> service_role.'
  );
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});

module.exports = { supabase };
