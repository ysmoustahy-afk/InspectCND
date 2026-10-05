'use strict';
const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

/* ===== Helpers (auth) ===== */
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
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
function accountsStore() { return getStore('inspectcnd-accounts'); }
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

async function requireAuth(event) {
  const token = getBearerToken(event);
  if (!token) return null;
  const secret = await getSecret();
  return verifyToken(token, secret);
}

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return json(200, {});

  const user = await requireAuth(event);
  if (!user) return json(401, { error: 'Session expirée, reconnectez-vous.' });

  const store = accountsStore();

  if (event.httpMethod === 'GET') {
    const listing = await store.list();
    const list = [];
    for (const b of (listing.blobs || [])) {
      const acc = await store.get(b.key, { type: 'json' });
      if (acc) list.push({ nom: acc.nom, niveau: acc.niveau || '', certif: acc.certif || '', contact: acc.contact || '', isAdmin: !!acc.isAdmin });
    }
    list.sort(function (a, b) { return a.nom.localeCompare(b.nom); });
    return json(200, list);
  }

  if (!user.isAdmin) return json(403, { error: 'Réservé à l’administrateur.' });

  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch (e) { return json(400, { error: 'Requête invalide' }); }
    const nom = String(body.nom || '').trim();
    if (!nom) return json(400, { error: 'Nom requis' });
    const key = nom.toLowerCase();
    const existing = await store.get(key, { type: 'json' });

    let salt, hash;
    if (body.password) {
      if (String(body.password).length < 4) return json(400, { error: 'Le mot de passe doit faire au moins 4 caractères' });
      const h = hashPassword(body.password);
      salt = h.salt; hash = h.hash;
    } else if (existing) {
      salt = existing.salt; hash = existing.hash;
    } else {
      return json(400, { error: 'Un mot de passe est requis pour créer ce compte' });
    }

    const account = {
      nom,
      niveau: String(body.niveau || ''),
      certif: String(body.certif || ''),
      contact: String(body.contact || ''),
      salt, hash,
      isAdmin: !!body.isAdmin,
      createdAtMs: (existing && existing.createdAtMs) || Date.now()
    };
    await store.setJSON(key, account);
    return json(200, { ok: true });
  }

  if (event.httpMethod === 'DELETE') {
    const nom = String((event.queryStringParameters && event.queryStringParameters.nom) || '').trim();
    if (!nom) return json(400, { error: 'Nom requis' });
    if (nom.toLowerCase() === user.nom.toLowerCase()) return json(400, { error: 'Vous ne pouvez pas supprimer votre propre compte.' });
    await store.delete(nom.toLowerCase());
    return json(200, { ok: true });
  }

  return json(405, { error: 'Méthode non autorisée' });
};
