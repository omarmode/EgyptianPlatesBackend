#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const seedPath = path.join(__dirname, 'admin-accounts.seed.json');
const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
const url = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!url || !serviceKey) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in backend/.env');
  process.exit(1);
}

const supabase = createClient(url, serviceKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

async function findUserByEmail(email) {
  const target = String(email).toLowerCase();
  let page = 1;
  const perPage = 200;
  while (page <= 10) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const match = (data?.users || []).find((user) => String(user.email || '').toLowerCase() === target);
    if (match) return match;
    if (!data?.users?.length || data.users.length < perPage) return null;
    page += 1;
  }
  return null;
}

async function upsertAuthUser(account) {
  const existing = await findUserByEmail(account.email);
  const payload = {
    email: account.email,
    password: account.password,
    email_confirm: true,
    user_metadata: { full_name: account.full_name || account.role },
    app_metadata: { role: account.role },
  };
  if (existing) {
    const { data, error } = await supabase.auth.admin.updateUserById(existing.id, payload);
    if (error) throw error;
    return { user: data.user, created: false };
  }
  const { data, error } = await supabase.auth.admin.createUser(payload);
  if (error) throw error;
  return { user: data.user, created: true };
}

async function upsertAdminRow(account) {
  const { data, error } = await supabase
    .from('admin_users')
    .upsert(
      {
        email: String(account.email).toLowerCase(),
        full_name: account.full_name || null,
        is_active: true,
      },
      { onConflict: 'email' },
    )
    .select()
    .single();
  if (error) throw error;
  return data;
}

(async () => {
  const results = [];
  for (const account of seed.accounts || []) {
    const auth = await upsertAuthUser(account);
    const row = await upsertAdminRow(account);
    results.push({
      email: account.email,
      role: account.role,
      auth_id: auth.user?.id || null,
      created: auth.created,
      admin_users: row?.email || account.email,
    });
    console.log(`${auth.created ? 'created' : 'updated'} ${account.role}: ${account.email}`);
  }
  console.log(JSON.stringify({ ok: true, results }, null, 2));
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
