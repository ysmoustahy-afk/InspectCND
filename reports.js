'use strict';
const { reportsStore, getSecret } = require('./_lib/store');
const { verifyToken } = require('./_lib/auth');
const { json, getBearerToken } = require('./_lib/http');

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
