'use strict';
const { getStore } = require('@netlify/blobs');

function accountsStore() { return getStore('inspectcnd-accounts'); }
function reportsStore() { return getStore('inspectcnd-reports'); }
function metaStore() { return getStore('inspectcnd-meta'); }

async function getSecret() {
  const store = metaStore();
  let secret = await store.get('app-secret', { type: 'text' });
  if (!secret) {
    secret = require('crypto').randomBytes(32).toString('hex');
    await store.set('app-secret', secret);
  }
  return secret;
}

module.exports = { accountsStore, reportsStore, metaStore, getSecret };
