'use strict';
const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

/* ===== Helpers (auth) ===== */
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || token.indexOf('.') === -1) return null;
  const idx = token.lastIndexOf('.');
  const body = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expectedSig = b64url(crypto.createHmac('sha256', secret).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(body).toString('utf8')); } catch (e) { return null; }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  return payload;
}

/* ===== Helpers (store) ===== */
function reportsStore() { return getStore('inspectcnd-reports'); }
function metaStore() { return getStore('inspectcnd-meta'); }
async function getSecret() {
  const store = metaStore();
  let secret = await store.get('app-secret', { type: 'text' });
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    await store.set('app-secret', secret);
  }
  return secret;
}

/* ===== Helpers (http) ===== */
function json(statusCode, data) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
    },
    body: JSON.stringify(data)
  };
}
function getBearerToken(event) {
  const h = event.headers && (event.headers.authorization || event.headers.Authorization);
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1] : null;
}

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return json(200, {});

  const token = getBearerToken(event);
  const secret = await getSecret();
  const user = token ? verifyToken(token, secret) : null;
  if (!user) return json(401, { error: 'Session expirée, reconnectez-vous.' });

  const store = reportsStore();

  if (event.httpMethod === 'GET') {
    const id = event.queryStringParameters && event.queryStringParameters.id;
    if (id) {
      const r = await store.get(id, { type: 'json' });
      if (!r) return json(404, { error: 'PV introuvable' });
      return json(200, r);
    }
    const listing = await store.list();
    const list = [];
    for (const b of (listing.blobs || [])) {
      const r = await store.get(b.key, { type: 'json' });
      if (r) list.push(r);
    }
    return json(200, list);
  }

  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch (e) { return json(400, { error: 'Requête invalide' }); }
    if (!body.id) return json(400, { error: 'id manquant' });
    body.updatedAtMs = Date.now();
    body.updatedBy = user.nom;
    if (!body.createdAtMs) body.createdAtMs = Date.now();
    if (!body.createdBy) body.createdBy = user.nom;
    await store.setJSON(body.id, body);
    return json(200, { ok: true, id: body.id });
  }

  return json(405, { error: 'Méthode non autorisée' });
};
