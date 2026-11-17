import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { validateDestination } from '../src/index.js';

class MemoryD1 {
  constructor() { this.rows = new Map(); }
  prepare(sql) {
    const db = this;
    return {
      values: [],
      bind(...values) { this.values = values; return this; },
      async run() {
        if (sql.startsWith('INSERT INTO shares')) {
          const [id, iv, ciphertext, revokeHash, createdAt, expiresAt] = this.values;
          db.rows.set(id, { id, iv, ciphertext, revoke_hash: revokeHash, created_at: createdAt, expires_at: expiresAt, revoked_at: null });
          return { meta: { changes: 1 } };
        }
        if (sql.startsWith('UPDATE shares')) {
          const [revokedAt, id] = this.values;
          const row = db.rows.get(id);
          if (row && row.revoked_at === null) row.revoked_at = revokedAt;
          return { meta: { changes: row ? 1 : 0 } };
        }
        if (sql.startsWith('DELETE FROM shares WHERE id')) {
          db.rows.delete(this.values[0]);
          return { meta: { changes: 1 } };
        }
        if (sql.startsWith('DELETE FROM shares WHERE expires_at')) {
          let changes = 0;
          for (const [id, row] of db.rows) {
            if (row.expires_at <= this.values[0] || row.revoked_at !== null) {
              db.rows.delete(id); changes += 1;
            }
          }
          return { meta: { changes } };
        }
        return { meta: { changes: 0 } };
      },
      async first() {
        const row = db.rows.get(this.values[0]);
        if (!row) return null;
        if (sql.includes('revoke_hash')) return { revoke_hash: row.revoke_hash, revoked_at: row.revoked_at };
        return { iv: row.iv, ciphertext: row.ciphertext, expires_at: row.expires_at, revoked_at: row.revoked_at };
      },
    };
  }
}

function makeEnv() {
  return {
    DB: new MemoryD1(),
    LINKLOCK_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
    CREATE_RATE_LIMITER: { limit: async () => ({ success: true }) },
  };
}

test('destination validation accepts HTTP and HTTPS links', () => {
  assert.equal(validateDestination('https://example.com/a').ok, true);
  assert.equal(validateDestination(' http://example.org/path ').url, 'http://example.org/path');
});

test('destination validation blocks unsafe schemes, credentials, and local hosts', () => {
  for (const url of [
    'javascript:alert(1)',
    'file:///etc/passwd',
    'https://user:pass@example.com/',
    'http://localhost/admin',
    'http://127.0.0.1/',
    'http://192.168.1.1/',
    'http://printer.local/',
  ]) assert.equal(validateDestination(url).ok, false, url);
});

test('share creation stores ciphertext and GET redirects to the original URL', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/private?q=hello' }),
  }), env);
  assert.equal(response.status, 201);
  const created = await response.json();
  assert.match(created.id, /^[A-Za-z0-9_-]{24}$/u);
  assert.equal(created.shareUrl, `https://share.example/s/${created.id}`);
  assert.ok(created.revokeToken);
  assert.equal(env.DB.rows.size, 1);
  const stored = env.DB.rows.get(created.id);
  assert.equal(stored.ciphertext.includes('example.com'), false);

  const opened = await worker.fetch(new Request(created.shareUrl), env);
  assert.equal(opened.status, 302);
  assert.equal(opened.headers.get('location'), 'https://example.com/private?q=hello');
  assert.equal(opened.headers.get('cache-control'), 'no-store, max-age=0');
});

test('share can be revoked only with its management token', async () => {
  const env = makeEnv();
  const createdResponse = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' }),
  }), env);
  const created = await createdResponse.json();

  const denied = await worker.fetch(new Request(`https://share.example/api/shares/${created.id}`, {
    method: 'DELETE', headers: { authorization: 'Bearer wrong-token-value-wrong-token-value-wrong' },
  }), env);
  assert.equal(denied.status, 403);

  const revoked = await worker.fetch(new Request(`https://share.example/api/shares/${created.id}`, {
    method: 'DELETE', headers: { authorization: `Bearer ${created.revokeToken}` },
  }), env);
  assert.equal(revoked.status, 200);
  const opened = await worker.fetch(new Request(created.shareUrl), env);
  assert.equal(opened.status, 404);
});

test('invalid URL and unsupported TTL are rejected before storage', async () => {
  const env = makeEnv();
  const invalid = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'javascript:alert(1)' }),
  }), env);
  assert.equal(invalid.status, 400);
  const badTtl = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com', ttlSeconds: 60 }),
  }), env);
  assert.equal(badTtl.status, 400);
  assert.equal(env.DB.rows.size, 0);
});


test('share ciphertext is bound to its share ID', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/bound' }),
  }), env);
  const created = await response.json();
  const original = env.DB.rows.get(created.id);
  const substitutedId = 'Z'.repeat(24);
  env.DB.rows.set(substitutedId, { ...original, id: substitutedId });
  const opened = await worker.fetch(new Request(`https://share.example/s/${substitutedId}`), env);
  assert.equal(opened.status, 503);
  assert.equal(opened.headers.get('location'), null);
});

test('expired shares return 410 and are deleted from storage', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/expired' }),
  }), env);
  const created = await response.json();
  env.DB.rows.get(created.id).expires_at = Math.floor(Date.now() / 1000) - 1;
  const opened = await worker.fetch(new Request(created.shareUrl), env);
  assert.equal(opened.status, 410);
  assert.equal(env.DB.rows.has(created.id), false);
});

test('malformed JSON shapes are rejected without throwing', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: 'null',
  }), env);
  assert.equal(response.status, 400);
  assert.equal(env.DB.rows.size, 0);
});


test('create endpoint returns 429 when rate limiter blocks the source', async () => {
  const env = makeEnv();
  env.CREATE_RATE_LIMITER.limit = async () => ({ success: false });
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' }),
  }), env);
  assert.equal(response.status, 429);
  assert.equal(env.DB.rows.size, 0);
});


test('oversized request bodies are rejected before JSON parsing', async () => {
  const env = makeEnv();
  const response = await worker.fetch(new Request('https://share.example/api/shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: `https://example.com/${'a'.repeat(5000)}` }),
  }), env);
  assert.equal(response.status, 413);
  assert.equal(env.DB.rows.size, 0);
});
