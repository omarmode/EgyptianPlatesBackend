// googleAuth.js — verify Google ID / access tokens from the admin browser.

const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

async function verifyGoogleIdToken(idToken) {
  const { ok, data } = await fetchJson(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`,
  );
  if (!ok || !data?.email) return null;
  if (GOOGLE_CLIENT_ID && data.aud && data.aud !== GOOGLE_CLIENT_ID) return null;
  const verified = data.email_verified === true || data.email_verified === 'true';
  if (!verified) return null;
  return { email: String(data.email).toLowerCase(), sub: data.sub || null, via: 'google-id-token' };
}

async function verifyGoogleAccessToken(accessToken) {
  const { ok, data } = await fetchJson('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!ok || !data?.email) return null;
  const verified = data.email_verified === true || data.email_verified === 'true';
  if (!verified) return null;
  return { email: String(data.email).toLowerCase(), sub: data.sub || null, via: 'google-access-token' };
}

function looksLikeJwt(token) {
  return typeof token === 'string' && token.split('.').length === 3;
}

async function verifyGoogleBearer(token) {
  if (!token) return null;
  if (looksLikeJwt(token)) {
    const fromId = await verifyGoogleIdToken(token);
    if (fromId) return fromId;
  }
  return verifyGoogleAccessToken(token);
}

module.exports = {
  GOOGLE_CLIENT_ID,
  verifyGoogleBearer,
  verifyGoogleIdToken,
  verifyGoogleAccessToken,
};
