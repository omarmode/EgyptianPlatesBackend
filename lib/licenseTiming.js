// licenseTiming.js — flexible license duration + remaining-time payload.

function asPositiveInt(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

function addMonths(date, months) {
  const next = new Date(date.getTime());
  next.setMonth(next.getMonth() + months);
  return next;
}

/**
 * Resolve create-payload into a unit + duration_days (legacy column) + optional expires_at.
 * Accepted body fields (all optional except that one duration style should be present):
 *   duration_hours | duration_days | duration_months | expires_at | unit
 */
function resolveLicenseDuration(body = {}) {
  const customExpiry = body.expires_at ? new Date(body.expires_at) : null;
  if (customExpiry && !Number.isNaN(customExpiry.getTime())) {
    return {
      duration_unit: 'custom',
      duration_days: Math.max(1, Math.ceil((customExpiry.getTime() - Date.now()) / 86400000)),
      duration_hours: null,
      duration_months: null,
      expires_at: customExpiry.toISOString(),
    };
  }

  const unit = String(body.unit || body.duration_unit || '').toLowerCase();
  const hours = asPositiveInt(body.duration_hours);
  const days = asPositiveInt(body.duration_days);
  const months = asPositiveInt(body.duration_months);

  if (unit === 'hours' || (hours && !days && !months)) {
    const h = hours || 1;
    return {
      duration_unit: 'hours',
      duration_hours: h,
      duration_days: Math.max(1, Math.ceil(h / 24)),
      duration_months: null,
      expires_at: null,
    };
  }

  if (unit === 'months' || (months && !hours)) {
    const m = months || 1;
    return {
      duration_unit: 'months',
      duration_hours: null,
      duration_days: Math.max(1, m * 30),
      duration_months: m,
      expires_at: null,
    };
  }

  const d = days || 30;
  return {
    duration_unit: 'days',
    duration_hours: null,
    duration_days: d,
    duration_months: null,
    expires_at: null,
  };
}

function computeExpiryAt(license, fromDate = new Date()) {
  if (license?.duration_unit === 'custom' && license.expires_at) {
    return new Date(license.expires_at);
  }
  if (license?.duration_unit === 'hours' && asPositiveInt(license.duration_hours)) {
    return new Date(fromDate.getTime() + license.duration_hours * 60 * 60 * 1000);
  }
  if (license?.duration_unit === 'months' && asPositiveInt(license.duration_months)) {
    return addMonths(fromDate, license.duration_months);
  }
  if (license?.duration_hours && !license.first_used_at) {
    return new Date(fromDate.getTime() + Number(license.duration_hours) * 60 * 60 * 1000);
  }
  if (license?.expires_at && license.first_used_at) {
    return new Date(license.expires_at);
  }
  const days = asPositiveInt(license?.duration_days) || 30;
  return new Date(fromDate.getTime() + days * 24 * 60 * 60 * 1000);
}

function remainingFrom(expiresAt) {
  if (!expiresAt) {
    return {
      expires_at: null,
      remaining_minutes: null,
      remaining_hours: null,
      remaining_ms: null,
      expired: false,
    };
  }
  const end = new Date(expiresAt);
  const ms = end.getTime() - Date.now();
  const remaining_ms = Math.max(0, ms);
  return {
    expires_at: end.toISOString(),
    remaining_minutes: Math.floor(remaining_ms / 60000),
    remaining_hours: Math.round((remaining_ms / 3600000) * 100) / 100,
    remaining_ms,
    expired: ms < 0,
  };
}

function licenseStatusPayload(license, extra = {}) {
  const remaining = remainingFrom(license?.expires_at);
  const deactivated = license && license.is_active === false;
  let status = 'active';
  if (deactivated) status = 'deactivated';
  else if (remaining.expired) status = 'expired';
  return {
    code: license?.code,
    bound_device_id: license?.bound_device_id || null,
    bound_user_email: license?.bound_user_email || extra.email || null,
    first_used_at: license?.first_used_at || null,
    expires_at: remaining.expires_at,
    duration_days: license?.duration_days ?? null,
    duration_hours: license?.duration_hours ?? null,
    duration_months: license?.duration_months ?? null,
    duration_unit: license?.duration_unit || (license?.duration_days ? 'days' : null),
    client_name: license?.client_name || null,
    is_active: !!license?.is_active,
    status,
    remaining_minutes: remaining.remaining_minutes,
    remaining_hours: remaining.remaining_hours,
    remaining_ms: remaining.remaining_ms,
  };
}

module.exports = {
  resolveLicenseDuration,
  computeExpiryAt,
  remainingFrom,
  licenseStatusPayload,
};
