// server.js — EgyptianPlatesBackend
// License / device control + Role-Based Access Control on top of Supabase Auth.
//
// ROLES (resolved from the authenticated email):
//   superadmin -> SUPER_ADMIN_EMAIL (hard default: omarabdelrahman369@gmail.com)
//   admin      -> email in ADMIN_EMAILS env OR active row in public.admin_users
//   user       -> any other authenticated user (field operators usually don't log in)
//
// AUTH:
//   - Admin/super-admin routes accept a Supabase "Authorization: Bearer <access_token>".
//   - As a compatibility fallback, the legacy "x-admin-key" header is treated as super-admin
//     (used by the built-in web dashboard at /admin).
//
// DEVICE ROUTES (no login; used by field devices with an activation code):
//   POST /api/license/verify   POST /api/session/status   POST /api/location/save
//
// ADMIN ROUTES (admin + superadmin):
//   POST /api/admin/license/create   POST /api/admin/device/revoke|unrevoke
//   GET  /api/admin/system|licenses|devices|locations
//
// SUPER-ADMIN ONLY:
//   POST /api/superadmin/killswitch   POST /api/superadmin/codefreeze
//   GET/POST /api/superadmin/admins
//
// AUTH INFO:
//   GET /api/auth/me  -> returns the caller's email + resolved role

require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { supabase } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

// Serve the (legacy) web dashboard from ./public — still works via x-admin-key.
app.use(express.static(path.join(__dirname, 'public')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const SUPER_ADMIN_EMAIL = (process.env.SUPER_ADMIN_EMAIL || 'omarabdelrahman369@gmail.com').toLowerCase();
const ENV_ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// ===========================================================================
// Helpers
// ===========================================================================

async function getSystemControl() {
  const { data, error } = await supabase
    .from('system_control')
    .select('is_system_enabled, admin_message, code_generation_enabled')
    .eq('id', 1)
    .single();
  if (error) throw error;
  return data;
}

// Decide a role from an email address.
async function resolveRole(email) {
  if (!email) return 'user';
  const e = email.toLowerCase();
  if (e === SUPER_ADMIN_EMAIL) return 'superadmin';
  if (ENV_ADMIN_EMAILS.includes(e)) return 'admin';
  const { data } = await supabase
    .from('admin_users')
    .select('is_active')
    .eq('email', e)
    .maybeSingle();
  if (data && data.is_active) return 'admin';
  return 'user';
}

// Core authentication: resolves req.user = { email, role, id?, via }.
async function authenticate(req) {
  // 1) Legacy super-admin key (used by the built-in web dashboard).
  const legacyKey = req.get('x-admin-key');
  if (legacyKey && ADMIN_API_KEY && legacyKey === ADMIN_API_KEY) {
    return { email: SUPER_ADMIN_EMAIL, role: 'superadmin', via: 'admin-key' };
  }

  // 2) Supabase access token.
  const authz = req.get('authorization') || '';
  if (!authz.toLowerCase().startsWith('bearer ')) {
    const err = new Error('Missing Bearer token.');
    err.status = 401;
    err.code = 'NO_TOKEN';
    throw err;
  }
  const token = authz.slice(7).trim();
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data || !data.user) {
    const err = new Error('Invalid or expired token.');
    err.status = 401;
    err.code = 'INVALID_TOKEN';
    throw err;
  }
  const email = data.user.email;
  const role = await resolveRole(email);
  return { id: data.user.id, email, role, via: 'supabase' };
}

// Middleware factory: authenticate then require one of the allowed roles.
function makeGuard(allowedRoles) {
  return async function guard(req, res, next) {
    try {
      req.user = await authenticate(req);
      if (!allowedRoles.includes(req.user.role)) {
        return res.status(403).json({
          ok: false,
          code: 'FORBIDDEN',
          message: 'Insufficient role for this action.',
          role: req.user.role,
        });
      }
      next();
    } catch (err) {
      res.status(err.status || 500).json({
        ok: false,
        code: err.code || 'AUTH_ERROR',
        message: err.message,
      });
    }
  };
}

const requireAuth = makeGuard(['user', 'admin', 'superadmin']);
const requireAdmin = makeGuard(['admin', 'superadmin']);
const requireSuperAdmin = makeGuard(['superadmin']);

// Block device/data traffic when the global kill-switch is off.
async function enforceKillSwitch(req, res, next) {
  try {
    const control = await getSystemControl();
    if (!control.is_system_enabled) {
      return res.status(503).json({
        ok: false,
        code: 'SYSTEM_DISABLED',
        message: control.admin_message || 'النظام متوقف حالياً من قبل الإدارة.',
      });
    }
    next();
  } catch (err) {
    console.error('[killswitch] failed:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: 'Failed to read system state.' });
  }
}

async function upsertSession({ device_id, license_code, device_name }) {
  const patch = { device_id, last_seen_at: new Date().toISOString() };
  if (license_code !== undefined) patch.license_code = license_code;
  if (device_name !== undefined) patch.device_name = device_name;
  const { data, error } = await supabase
    .from('device_sessions')
    .upsert(patch, { onConflict: 'device_id' })
    .select()
    .single();
  if (error) throw error;
  return data;
}

function generateLicenseCode() {
  const raw = crypto.randomBytes(8).toString('hex').toUpperCase();
  return raw.match(/.{1,4}/g).join('-');
}

// ===========================================================================
// Health + auth info
// ===========================================================================
app.get('/health', (req, res) => res.json({ ok: true, service: 'EgyptianPlatesBackend' }));

// GET /api/auth/me -> who am I + my role (used by the app after Google login).
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: { email: req.user.email, role: req.user.role } });
});

// ===========================================================================
// PUBLIC / DEVICE ROUTES
// ===========================================================================

// POST /api/license/verify  Body: { code, device_id, device_name?, user_email? }
app.post('/api/license/verify', enforceKillSwitch, async (req, res) => {
  try {
    const { code, device_id, device_name, user_email } = req.body || {};
    if (!code || !device_id) {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'code and device_id are required.' });
    }
    const email = user_email ? String(user_email).toLowerCase() : null;

    const { data: license, error } = await supabase
      .from('licenses').select('*').eq('code', code).maybeSingle();
    if (error) throw error;

    if (!license) return res.status(404).json({ ok: false, code: 'INVALID_CODE', message: 'Activation code not found.' });
    if (!license.is_active) return res.status(403).json({ ok: false, code: 'CODE_DISABLED', message: 'This code has been disabled.' });

    // Allow same account to re-use on same/new device; block other devices/accounts.
    if (license.bound_device_id && license.bound_device_id !== device_id) {
      const sameUser = email && license.bound_user_email && license.bound_user_email === email;
      if (!sameUser) {
        return res.status(409).json({ ok: false, code: 'ALREADY_BOUND', message: 'This code is already activated on another device.' });
      }
    }

    let updatedLicense = license;
    if (!license.bound_device_id || (email && license.bound_user_email !== email) || license.bound_device_id !== device_id) {
      const now = new Date();
      const expires = license.expires_at
        ? new Date(license.expires_at)
        : new Date(now.getTime() + license.duration_days * 24 * 60 * 60 * 1000);
      const patch = {
        bound_device_id: device_id,
        bound_device_name: device_name || license.bound_device_name || null,
        expires_at: expires.toISOString(),
      };
      if (!license.first_used_at) patch.first_used_at = now.toISOString();
      if (email) patch.bound_user_email = email;

      const { data, error: updErr } = await supabase
        .from('licenses')
        .update(patch)
        .eq('id', license.id)
        .eq('is_active', true)
        .select()
        .single();
      if (updErr) throw updErr;
      updatedLicense = data;
    }

    const expired = updatedLicense.expires_at && new Date(updatedLicense.expires_at) < new Date();
    await upsertSession({ device_id, license_code: code, device_name });

    if (expired) {
      return res.status(403).json({ ok: false, code: 'EXPIRED', message: 'This license has expired.', expires_at: updatedLicense.expires_at });
    }

    return res.json({
      ok: true,
      code: 'ACTIVATED',
      message: 'License is valid for this device.',
      license: {
        code: updatedLicense.code,
        bound_device_id: updatedLicense.bound_device_id,
        bound_user_email: updatedLicense.bound_user_email || email,
        first_used_at: updatedLicense.first_used_at,
        expires_at: updatedLicense.expires_at,
        duration_days: updatedLicense.duration_days,
        is_active: updatedLicense.is_active,
      },
    });
  } catch (err) {
    console.error('[verify] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/license/status  Body: { device_id?, user_email?, code? }
// Checks whether the field user still has an active, non-expired license.
app.post('/api/license/status', enforceKillSwitch, async (req, res) => {
  try {
    const { device_id, user_email, code } = req.body || {};
    const email = user_email ? String(user_email).toLowerCase() : null;
    if (!device_id && !email && !code) {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'device_id, user_email, or code is required.' });
    }

    let query = supabase.from('licenses').select('*').eq('is_active', true).order('first_used_at', { ascending: false }).limit(1);
    if (code) query = supabase.from('licenses').select('*').eq('code', code).maybeSingle();
    else if (email) query = supabase.from('licenses').select('*').eq('bound_user_email', email).eq('is_active', true).order('first_used_at', { ascending: false }).limit(1).maybeSingle();
    else query = supabase.from('licenses').select('*').eq('bound_device_id', device_id).eq('is_active', true).order('first_used_at', { ascending: false }).limit(1).maybeSingle();

    const { data: license, error } = await query;
    if (error) throw error;
    if (!license) {
      return res.json({ ok: true, valid: false, code: 'NO_LICENSE', message: 'No active license found.' });
    }
    if (!license.is_active) {
      return res.json({ ok: true, valid: false, code: 'CODE_DISABLED', message: 'License is deactivated.', license });
    }
    const expired = license.expires_at && new Date(license.expires_at) < new Date();
    if (expired) {
      return res.json({ ok: true, valid: false, code: 'EXPIRED', message: 'License expired.', license });
    }
    return res.json({ ok: true, valid: true, code: 'ACTIVE', license });
  } catch (err) {
    console.error('[license/status] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/session/status  Body: { device_id }
app.post('/api/session/status', enforceKillSwitch, async (req, res) => {
  try {
    const { device_id } = req.body || {};
    if (!device_id) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'device_id is required.' });

    const session = await upsertSession({ device_id });
    if (session.is_revoked) {
      return res.status(403).json({ ok: false, code: 'REVOKED', message: 'This device has been revoked by the administrator.' });
    }

    let licenseInfo = null;
    if (session.license_code) {
      const { data: lic } = await supabase
        .from('licenses').select('code, is_active, expires_at, bound_device_id').eq('code', session.license_code).maybeSingle();
      if (lic) {
        const expired = lic.expires_at && new Date(lic.expires_at) < new Date();
        licenseInfo = { code: lic.code, is_active: lic.is_active, expires_at: lic.expires_at, expired };
        if (!lic.is_active || expired) {
          return res.status(403).json({ ok: false, code: 'EXPIRED', message: 'License is inactive or expired.', license: licenseInfo });
        }
      }
    }
    res.json({ ok: true, code: 'ACTIVE', last_seen_at: session.last_seen_at, license: licenseInfo });
  } catch (err) {
    console.error('[status] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/location/save
// Body: { plate_number, latitude?, longitude?, place_name?, device_id?, detected_by_user? }
app.post('/api/location/save', enforceKillSwitch, async (req, res) => {
  try {
    const { plate_number, latitude, longitude, place_name, device_id, detected_by_user } = req.body || {};
    if (!plate_number) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'plate_number is required.' });

    if (device_id) {
      const { data: session } = await supabase
        .from('device_sessions').select('is_revoked').eq('device_id', device_id).maybeSingle();
      if (session && session.is_revoked) {
        return res.status(403).json({ ok: false, code: 'REVOKED', message: 'This device has been revoked.' });
      }
    }

    const { data, error } = await supabase
      .from('detected_locations')
      .insert({
        plate_number,
        latitude: latitude ?? null,
        longitude: longitude ?? null,
        place_name: place_name ?? null,
        device_id: device_id ?? null,
        detected_by_user: detected_by_user ?? null,
      })
      .select()
      .single();
    if (error) throw error;

    res.status(201).json({ ok: true, code: 'SAVED', location: data });
  } catch (err) {
    console.error('[location] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// ===========================================================================
// ADMIN ROUTES (admin + superadmin)
// ===========================================================================

// POST /api/admin/license/create  Body: { duration_days?, code? }
// Regular admins are blocked when the super admin froze code generation.
app.post('/api/admin/license/create', requireAdmin, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const control = await getSystemControl();
      if (!control.code_generation_enabled) {
        return res.status(403).json({
          ok: false,
          code: 'CODE_FROZEN',
          message: 'إنشاء الأكواد مجمّد حالياً من قبل الإدارة العليا. يرجى التواصل مع الدعم.',
        });
      }
    }

    const { duration_days, code } = req.body || {};
    const newCode = code || generateLicenseCode();
    const days = Number.isInteger(duration_days) && duration_days > 0 ? duration_days : 30;

    const { data, error } = await supabase
      .from('licenses')
      .insert({ code: newCode, duration_days: days, issued_by: req.user.email })
      .select()
      .single();
    if (error) throw error;

    res.status(201).json({ ok: true, code: 'CREATED', license: data });
  } catch (err) {
    console.error('[admin/create] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/admin/license/deactivate  Body: { code } -> sets is_active=false immediately
app.post('/api/admin/license/deactivate', requireAdmin, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'code is required.' });
    const { data, error } = await supabase
      .from('licenses')
      .update({ is_active: false })
      .eq('code', code)
      .select()
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'License not found.' });
    res.json({ ok: true, code: 'DEACTIVATED', license: data });
  } catch (err) {
    console.error('[admin/deactivate] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/admin/license/delete  Body: { code } -> hard delete
app.post('/api/admin/license/delete', requireAdmin, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'code is required.' });
    const { data, error } = await supabase
      .from('licenses')
      .delete()
      .eq('code', code)
      .select()
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'License not found.' });
    res.json({ ok: true, code: 'DELETED', license: data });
  } catch (err) {
    console.error('[admin/delete] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

async function setRevoked(req, res, value, label) {
  try {
    const { device_id } = req.body || {};
    if (!device_id) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'device_id is required.' });
    const { data, error } = await supabase
      .from('device_sessions').update({ is_revoked: value }).eq('device_id', device_id).select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'No session for that device_id.' });
    res.json({ ok: true, code: label, session: data });
  } catch (err) {
    console.error(`[admin/${label}] error:`, err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
}
app.post('/api/admin/device/revoke', requireAdmin, (req, res) => setRevoked(req, res, true, 'REVOKED'));
app.post('/api/admin/device/unrevoke', requireAdmin, (req, res) => setRevoked(req, res, false, 'UNREVOKED'));

// GET system state (includes code-freeze flag).
app.get('/api/admin/system', requireAdmin, async (req, res) => {
  try {
    const system = await getSystemControl();
    res.json({ ok: true, system, role: req.user.role });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.get('/api/admin/licenses', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('licenses').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ ok: false, message: error.message });
  res.json({ ok: true, licenses: data });
});
app.get('/api/admin/devices', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('device_sessions').select('*').order('last_seen_at', { ascending: false });
  if (error) return res.status(500).json({ ok: false, message: error.message });
  res.json({ ok: true, devices: data });
});
// GET /api/admin/locations -> markers for the in-app map.
app.get('/api/admin/locations', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('detected_locations').select('*').order('created_at', { ascending: false }).limit(1000);
  if (error) return res.status(500).json({ ok: false, message: error.message });
  res.json({ ok: true, locations: data });
});

// ===========================================================================
// SUPER-ADMIN ONLY
// ===========================================================================

// POST /api/superadmin/killswitch  Body: { is_system_enabled: boolean, admin_message?: string }
app.post('/api/superadmin/killswitch', requireSuperAdmin, async (req, res) => {
  try {
    const { is_system_enabled, admin_message } = req.body || {};
    if (typeof is_system_enabled !== 'boolean') {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'is_system_enabled (boolean) is required.' });
    }
    const { data, error } = await supabase
      .from('system_control')
      .update({ is_system_enabled, admin_message: admin_message ?? null, updated_at: new Date().toISOString() })
      .eq('id', 1)
      .select('is_system_enabled, admin_message, code_generation_enabled')
      .single();
    if (error) throw error;
    res.json({ ok: true, code: 'UPDATED', system: data });
  } catch (err) {
    console.error('[superadmin/killswitch] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// Backwards-compatible alias for the built-in web dashboard (super-admin only now).
app.post('/api/admin/system/killswitch', requireSuperAdmin, async (req, res) => {
  try {
    const { is_system_enabled, admin_message } = req.body || {};
    if (typeof is_system_enabled !== 'boolean') {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'is_system_enabled (boolean) is required.' });
    }
    const { data, error } = await supabase
      .from('system_control')
      .update({ is_system_enabled, admin_message: admin_message ?? null, updated_at: new Date().toISOString() })
      .eq('id', 1)
      .select('is_system_enabled, admin_message, code_generation_enabled')
      .single();
    if (error) throw error;
    res.json({ ok: true, code: 'UPDATED', system: data });
  } catch (err) {
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/superadmin/codefreeze  Body: { code_generation_enabled: boolean }
app.post('/api/superadmin/codefreeze', requireSuperAdmin, async (req, res) => {
  try {
    const { code_generation_enabled } = req.body || {};
    if (typeof code_generation_enabled !== 'boolean') {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'code_generation_enabled (boolean) is required.' });
    }
    const { data, error } = await supabase
      .from('system_control')
      .update({ code_generation_enabled, updated_at: new Date().toISOString() })
      .eq('id', 1)
      .select('is_system_enabled, admin_message, code_generation_enabled')
      .single();
    if (error) throw error;
    res.json({ ok: true, code: 'UPDATED', system: data });
  } catch (err) {
    console.error('[superadmin/codefreeze] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// Manage the approved admin (client) list.
app.get('/api/superadmin/admins', requireSuperAdmin, async (req, res) => {
  const { data, error } = await supabase.from('admin_users').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ ok: false, message: error.message });
  res.json({ ok: true, admins: data });
});
app.post('/api/superadmin/admins', requireSuperAdmin, async (req, res) => {
  try {
    const { email, full_name, is_active } = req.body || {};
    if (!email) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'email is required.' });
    const { data, error } = await supabase
      .from('admin_users')
      .upsert({ email: String(email).toLowerCase(), full_name: full_name ?? null, is_active: is_active ?? true }, { onConflict: 'email' })
      .select()
      .single();
    if (error) throw error;
    res.json({ ok: true, code: 'SAVED', admin: data });
  } catch (err) {
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// ===========================================================================
// PLATES LOG (field daily logs) + ADMIN ALIASES
// ===========================================================================

// POST /api/plates/log  — accept detection + GPS for field users (also mirrors detected_locations)
app.post('/api/plates/log', enforceKillSwitch, async (req, res) => {
  try {
    const {
      plate_number,
      latitude,
      longitude,
      place_name,
      device_id,
      detected_by_user,
      user_email,
      letters,
      detected_at,
    } = req.body || {};
    if (!plate_number) {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'plate_number is required.' });
    }
    const uid = (user_email || detected_by_user || '').toString().toLowerCase() || null;
    const { data, error } = await supabase
      .from('detected_locations')
      .insert({
        plate_number,
        latitude: latitude ?? null,
        longitude: longitude ?? null,
        place_name: place_name ?? null,
        device_id: device_id ?? null,
        detected_by_user: uid,
      })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({
      ok: true,
      code: 'LOGGED',
      plate: {
        ...data,
        letters: letters || null,
        detected_at: detected_at || data.created_at,
        user_email: uid,
      },
    });
  } catch (err) {
    console.error('[plates/log] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// GET /api/plates/daily?date=YYYY-MM-DD&user_email=...&device_id=...
app.get('/api/plates/daily', enforceKillSwitch, async (req, res) => {
  try {
    const dateStr = (req.query.date || new Date().toISOString().slice(0, 10)).toString();
    const userEmail = (req.query.user_email || '').toString().toLowerCase() || null;
    const deviceId = (req.query.device_id || '').toString() || null;
    if (!userEmail && !deviceId) {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'user_email or device_id is required.' });
    }
    const start = new Date(`${dateStr}T00:00:00.000Z`);
    const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
    let query = supabase
      .from('detected_locations')
      .select('*')
      .gte('created_at', start.toISOString())
      .lt('created_at', end.toISOString())
      .order('created_at', { ascending: false })
      .limit(2000);
    if (userEmail) query = query.eq('detected_by_user', userEmail);
    else query = query.eq('device_id', deviceId);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ ok: true, date: dateStr, count: (data || []).length, plates: data || [] });
  } catch (err) {
    console.error('[plates/daily] error:', err.message);
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// Aliases requested by client contract
app.post('/api/admin/kill-switch', requireSuperAdmin, async (req, res) => {
  req.url = '/api/superadmin/killswitch';
  // reuse body: is_system_enabled / enabled
  if (typeof req.body?.enabled === 'boolean' && typeof req.body.is_system_enabled !== 'boolean') {
    req.body.is_system_enabled = req.body.enabled;
  }
  try {
    const { is_system_enabled, admin_message } = req.body || {};
    if (typeof is_system_enabled !== 'boolean') {
      return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'is_system_enabled (boolean) is required.' });
    }
    const { data, error } = await supabase
      .from('system_control')
      .update({ is_system_enabled, admin_message: admin_message ?? null, updated_at: new Date().toISOString() })
      .eq('id', 1)
      .select('is_system_enabled, admin_message, code_generation_enabled')
      .single();
    if (error) throw error;
    res.json({ ok: true, code: 'UPDATED', system: data });
  } catch (err) {
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// Force logout / terminate device session immediately
app.post('/api/admin/force-logout', requireAdmin, async (req, res) => {
  try {
    const { device_id } = req.body || {};
    if (!device_id) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'device_id is required.' });
    const { data, error } = await supabase
      .from('device_sessions')
      .update({ is_revoked: true, last_seen_at: new Date().toISOString() })
      .eq('device_id', device_id)
      .select()
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'No session for that device_id.' });
    res.json({ ok: true, code: 'FORCE_LOGOUT', session: data });
  } catch (err) {
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

app.patch('/api/admin/licenses/:id/revoke', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    let q = supabase.from('licenses').update({ is_active: false }).select().maybeSingle();
    // allow id as uuid or as code
    if (/^[0-9a-f-]{36}$/i.test(id)) q = supabase.from('licenses').update({ is_active: false }).eq('id', id).select().maybeSingle();
    else q = supabase.from('licenses').update({ is_active: false }).eq('code', id).select().maybeSingle();
    const { data, error } = await q;
    if (error) throw error;
    if (!data) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'License not found.' });
    res.json({ ok: true, code: 'REVOKED', license: data });
  } catch (err) {
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

app.delete('/api/admin/licenses/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    let q;
    if (/^[0-9a-f-]{36}$/i.test(id)) q = supabase.from('licenses').delete().eq('id', id).select().maybeSingle();
    else q = supabase.from('licenses').delete().eq('code', id).select().maybeSingle();
    const { data, error } = await q;
    if (error) throw error;
    if (!data) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'License not found.' });
    res.json({ ok: true, code: 'DELETED', license: data });
  } catch (err) {
    res.status(500).json({ ok: false, code: 'INTERNAL_ERROR', message: err.message });
  }
});

// ---------------------------------------------------------------------------
app.use((req, res) => res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'Route not found.' }));

app.listen(PORT, () => {
  console.log(`EgyptianPlatesBackend listening on http://localhost:${PORT}`);
  console.log(`Super admin: ${SUPER_ADMIN_EMAIL}`);
});
