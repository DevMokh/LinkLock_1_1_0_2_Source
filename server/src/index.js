const MAX_URL_LENGTH = 2048;
const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const MIN_TTL_SECONDS = 60 * 60;
const MAX_TTL_SECONDS = 30 * 24 * 60 * 60;
const ID_BYTES = 18;
const REVOKE_TOKEN_BYTES = 32;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store, max-age=0',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

function plain(message, status) {
  return new Response(message, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store, max-age=0',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function fromBase64(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
}

function randomToken(byteLength) {
  return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function isPrivateIpv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/u.test(part))) return false;
  const octets = parts.map(Number);
  if (octets.some((part) => part > 255)) return true;
  const [a, b] = octets;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) || a >= 224;
}

export function validateDestination(value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return { ok: false, error: 'اكتب الرابط الأول' };
  }
  const trimmed = value.trim();
  if (trimmed.length > MAX_URL_LENGTH) {
    return { ok: false, error: 'الرابط أطول من الحد المسموح' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, error: 'الرابط غير صالح' };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { ok: false, error: 'المسموح روابط HTTP وHTTPS فقط' };
  }
  if (!parsed.hostname || parsed.username || parsed.password) {
    return { ok: false, error: 'صيغة الرابط غير مسموح بها' };
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/gu, '');
  const privateIpv6 = host.includes(':') && (
    host === '::' || host === '::1' || host.startsWith('fc') ||
    host.startsWith('fd') || host.startsWith('fe80:') ||
    host.startsWith('::ffff:')
  );
  if (
    host === 'localhost' || host.endsWith('.localhost') ||
    host.endsWith('.local') || host.endsWith('.lan') ||
    host.endsWith('.home') || host.endsWith('.home.arpa') ||
    host.endsWith('.internal') || host.endsWith('.intranet') ||
    privateIpv6 || isPrivateIpv4(host)
  ) {
    return { ok: false, error: 'روابط الشبكات المحلية غير مسموح بها' };
  }
  return { ok: true, url: parsed.toString() };
}

async function loadMasterKey(env) {
  if (typeof env.LINKLOCK_MASTER_KEY !== 'string' || !env.LINKLOCK_MASTER_KEY) {
    throw new Error('Missing LINKLOCK_MASTER_KEY secret');
  }
  const keyBytes = fromBase64(env.LINKLOCK_MASTER_KEY.trim());
  if (keyBytes.length !== 32) throw new Error('LINKLOCK_MASTER_KEY must decode to 32 bytes');
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptDestination(url, id, env) {
  const key = await loadMasterKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(url);
  const aad = new TextEncoder().encode(`linklock-share-v1:${id}`);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128, additionalData: aad },
    key,
    plaintext,
  );
  return { iv: base64Url(iv), ciphertext: base64Url(new Uint8Array(ciphertext)) };
}

async function decryptDestination(row, id, env) {
  const key = await loadMasterKey(env);
  const clear = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: fromBase64(row.iv),
      tagLength: 128,
      additionalData: new TextEncoder().encode(`linklock-share-v1:${id}`),
    },
    key,
    fromBase64(row.ciphertext),
  );
  return new TextDecoder('utf-8', { fatal: true }).decode(clear);
}

async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function readLimitedBody(request, maximumBytes) {
  if (!request.body) return { tooLarge: false, text: '' };
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        return { tooLarge: true, text: '' };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { tooLarge: false, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
}

async function createShare(request, env) {
  const rawLength = request.headers.get('content-length');
  const contentLength = rawLength === null ? null : Number(rawLength);
  if (contentLength !== null && (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > 4096)) {
    return json({ error: 'حجم الطلب أكبر من المسموح' }, 413);
  }
  if (!request.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    return json({ error: 'نوع الطلب غير مدعوم' }, 415);
  }

  let body;
  try {
    const bounded = await readLimitedBody(request, 4096);
    if (bounded.tooLarge) return json({ error: 'حجم الطلب أكبر من المسموح' }, 413);
    body = JSON.parse(bounded.text);
  } catch {
    return json({ error: 'بيانات الطلب غير صالحة' }, 400);
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json({ error: 'بيانات الطلب غير صالحة' }, 400);
  }
  const checked = validateDestination(body.url);
  if (!checked.ok) return json({ error: checked.error }, 400);

  const ttl = body.ttlSeconds === undefined ? DEFAULT_TTL_SECONDS : body.ttlSeconds;
  if (!Number.isInteger(ttl) || ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    return json({ error: 'مدة الصلاحية لازم تكون من ساعة إلى 30 يوم' }, 400);
  }

  try {
    const id = randomToken(ID_BYTES);
    const encrypted = await encryptDestination(checked.url, id, env);
    const revokeToken = randomToken(REVOKE_TOKEN_BYTES);
    const revokeHash = await sha256Hex(revokeToken);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + ttl;

    await env.DB.prepare(
      'INSERT INTO shares (id, iv, ciphertext, revoke_hash, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)',
    ).bind(id, encrypted.iv, encrypted.ciphertext, revokeHash, now, expiresAt).run();

    const origin = new URL(request.url).origin;
    return json({
      id,
      shareUrl: `${origin}/s/${id}`,
      revokeToken,
      expiresAt: new Date(expiresAt * 1000).toISOString(),
    }, 201);
  } catch {
    return json({ error: 'الخادم لم يستطع إنشاء رابط المشاركة' }, 503);
  }
}

async function revokeShare(request, env, id) {
  if (!/^[A-Za-z0-9_-]{24}$/u.test(id)) return json({ error: 'الرابط غير موجود' }, 404);
  const authorization = request.headers.get('authorization') || '';
  const match = /^Bearer ([A-Za-z0-9_-]{40,50})$/u.exec(authorization);
  if (!match) return json({ error: 'رمز الإلغاء غير صحيح' }, 401);

  try {
    const suppliedHash = await sha256Hex(match[1]);
    const row = await env.DB.prepare('SELECT revoke_hash, revoked_at FROM shares WHERE id = ?')
      .bind(id).first();
    if (!row || row.revoked_at !== null || !constantTimeEqual(suppliedHash, row.revoke_hash)) {
      return json({ error: 'تعذر إلغاء الرابط؛ تحقق من الرمز أو حالة الرابط' }, 403);
    }
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare('UPDATE shares SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
      .bind(now, id).run();
    return json({ revoked: true });
  } catch {
    return json({ error: 'الخادم لم يستطع إلغاء الرابط' }, 503);
  }
}

async function openShare(env, id) {
  if (!/^[A-Za-z0-9_-]{24}$/u.test(id)) return plain('الرابط غير موجود', 404);
  try {
    const row = await env.DB.prepare(
      'SELECT iv, ciphertext, expires_at, revoked_at FROM shares WHERE id = ?',
    ).bind(id).first();
    if (!row || row.revoked_at !== null) return plain('الرابط غير موجود أو تم إلغاؤه', 404);
    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at <= now) {
      await env.DB.prepare('DELETE FROM shares WHERE id = ?').bind(id).run();
      return plain('انتهت صلاحية رابط المشاركة', 410);
    }

    const destination = await decryptDestination(row, id, env);
    const checked = validateDestination(destination);
    if (!checked.ok || checked.url !== destination) return plain('تعذر فتح الرابط', 410);
    return new Response(null, {
      status: 302,
      headers: {
        location: destination,
        'cache-control': 'no-store, max-age=0',
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return plain('تعذر فتح رابط المشاركة حاليًا', 503);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/api/shares') {
      try {
        const sourceIp = request.headers.get('cf-connecting-ip') || 'unknown';
        const { success } = await env.CREATE_RATE_LIMITER.limit({ key: sourceIp });
        if (!success) return json({ error: 'طلبات إنشاء كثيرة من نفس الشبكة. جرّب بعد دقيقة.' }, 429);
      } catch {
        return json({ error: 'حماية معدل الطلبات غير متاحة حاليًا.' }, 503);
      }
      return createShare(request, env);
    }
    if (request.method === 'DELETE' && url.pathname.startsWith('/api/shares/')) {
      const id = url.pathname.slice('/api/shares/'.length);
      return revokeShare(request, env, id);
    }
    if (request.method === 'GET' && url.pathname.startsWith('/s/')) {
      const id = url.pathname.slice('/s/'.length);
      if (id.includes('/')) return plain('الرابط غير موجود', 404);
      return openShare(env, id);
    }
    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true });
    }
    return json({ error: 'غير موجود' }, 404);
  },

  async scheduled(_controller, env) {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare('DELETE FROM shares WHERE expires_at <= ? OR revoked_at IS NOT NULL')
      .bind(now).run();
  },
};
