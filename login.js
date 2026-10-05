'use strict';
const { accountsStore, getSecret } = require('./_lib/store');
const { hashPassword, verifyPassword, signToken } = require('./_lib/auth');
const { json } = require('./_lib/http');

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
    // Personne n'a encore ce nom : on vérifie si c'est le tout premier compte jamais créé.
    const listing = await store.list();
    const isFirstEver = !listing.blobs || listing.blobs.length === 0;
    if (!isFirstEver) {
      return json(401, { error: 'Nom ou mot de passe incorrect' });
    }
    // Premier compte créé sur cette appli = administrateur automatiquement.
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
