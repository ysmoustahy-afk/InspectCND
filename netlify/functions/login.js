'use strict';
const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

/* ===== Helpers (auth) ===== */
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(String(password), salt, 64).toString('hex');
  const a = Buffer.from(check, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function signToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(body).digest();
  return body + '.' + b64url(sig);
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

const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 jours

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return json(200, {});
  if (event.httpMethod !== 'POST') return json(405, { error: 'Méthode non autorisée' });

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch (e) { return json(400, { error: 'Requête invalide' }); }
  const nom = String(body.nom || '').trim();
  const password = String(body.password || '');
  if (!nom || !password) return json(400, { error: 'Nom et mot de passe requis' });
  if (password.length < 4) return json(400, { error: 'Le mot de passe doit faire au moins 4 caractères' });

  const store = accountsStore();
  const key = nom.toLowerCase();
  const existing = await store.get(key, { type: 'json' });

  let account;
  if (!existing) {
    const listing = await store.list();
    const isFirstEver = !listing.blobs || listing.blobs.length === 0;
    if (!isFirstEver) {
      return json(401, { error: 'Nom ou mot de passe incorrect' });
    }
    const { salt, hash } = hashPassword(password);
    account = { nom, niveau: '', certif: '', contact: '', salt, hash, isAdmin: true, createdAtMs: Date.now() };
    await store.setJSON(key, account);
  } else {
    if (!verifyPassword(password, existing.salt, existing.hash)) {
      return json(401, { error: 'Nom ou mot de passe incorrect' });
    }
    account = existing;
  }

  const secret = await getSecret();
  const token = signToken({ nom: account.nom, isAdmin: !!account.isAdmin, exp: Date.now() + TOKEN_TTL_MS }, secret);
  return json(200, {
    token,
    nom: account.nom,
    isAdmin: !!account.isAdmin,
    niveau: account.niveau || '',
    certif: account.certif || ''
  });
};
