'use strict';
const { accountsStore, getSecret } = require('./_lib/store');
const { verifyToken, hashPassword } = require('./_lib/auth');
const { json, getBearerToken } = require('./_lib/http');

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

  // Au-delà de la lecture, seul l'administrateur peut gérer les comptes.
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
