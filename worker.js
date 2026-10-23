/**
 * v6.0 (2026-10-21) - security + reliability release
 *   - NEW: server-side OTP for the document-upload page (POST /otp/send, POST /otp/verify).
 *     The code is generated here with crypto.getRandomValues, stored only as a salted hash in
 *     D1 (table otp_codes, created automatically), expires in 10 min, max 5 attempts, rate-limited
 *     per IP and per phone. A successful verify returns a signed 60-minute token that Code.gs
 *     (Apps Script) checks before accepting any upload. REQUIRES secret OTP_SECRET (same value
 *     must be saved in Apps Script > Project Settings > Script Properties as UPLOAD_SECRET).
 *   - Lead alerts now use the approved WhatsApp templates (studyleap_new_lead /
 *     studyleap_lead_reminde) and fall back to plain text if a template send fails.
 *   - Stricter phone validation (rejects 0000000000, 1234567890, 7-digit junk, bad Indian mobiles).
 *   - Origin check no longer accepts look-alike Referer hosts (exact origin match).
 *   - CRM secret comparison is constant-time and fails closed when CRM_SECRET is unset.
 *   - Telegram messages are sent as plain text (Markdown parsing broke on _ and * in names).
 *   - Duplicate lead (same phone within 10 min) is acknowledged but not re-notified;
 *     auto-reply email is limited to 1 per address per 24 h; sub-1.5s form fills are dropped.
 *   - Turnstile now also protects /otp/send. TURNSTILE_REQUIRED="true" = strict (token mandatory,
 *     verification errors block); unset = monitor mode (failures are logged, never block).
 *   Optional variables: WHATSAPP_OTP_TEMPLATE (default studyleap_otp2), WHATSAPP_LEAD_TEMPLATE,
 *     WHATSAPP_REMINDER_TEMPLATE, WHATSAPP_TEMPLATE_LANG (default en), WHATSAPP_TEMPLATES=off
 *     (to force plain-text alerts).
 */
/**
 * Study LEAP Cloudflare Worker — v5.2
 * ─────────────────────────────────────────────────────────────────────────────
 * FIX v5.2 (2026-08-18) — WhatsApp/Telegram notifications not arriving:
 *   ✅ Telegram was previously wired as a FALLBACK that only ran when
 *      WhatsApp's send failed — it could never fire as its own channel.
 *      If WhatsApp and Telegram were both misconfigured (or WhatsApp failed
 *      for any reason), NEITHER notification went out, while EmailJS kept
 *      working because it was never gated on the other two. WhatsApp and
 *      Telegram now send independently, in parallel, every time.
 *   ✅ WhatsApp/Telegram/EmailJS failures were pushed into an `errors` array
 *      in the API response but were NEVER printed to console — so nothing
 *      showed up in Cloudflare's real-time logs. Added console.error/log for
 *      every channel (including partial WhatsApp failures across recipients,
 *      which were previously dropped entirely if at least one number worked).
 *   ℹ️  `ok: true` in the response is intentionally left as-is — it reflects
 *      "the lead was captured," not "every notification channel succeeded."
 *      A WhatsApp/Telegram outage on our end must never show a real customer
 *      a false "submission failed" error. Check `errors` / the Worker logs
 *      to monitor channel health instead.
 *   → Most likely root cause of the original outage: WHATSAPP_TOKEN /
 *     TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing or invalid in the
 *     Worker's Settings → Variables, OR WhatsApp hit Meta's 24-hour
 *     session-messaging window (this sends a free-form `type: 'text'`
 *     message, which Meta blocks outside an open customer conversation —
 *     see notes near sendWhatsApp()). Check the Worker logs after a test
 *     submission to confirm which it is.
 *
 * FIX v5.1 (2026-06-01):
 *   ✅ CRITICAL: Fixed GET routing — now serves ALL static assets via env.ASSETS,
 *      not just '/' and '*.html'. Previously all directory-based page paths
 *      (e.g. /education-loan-delhi/) returned a JSON 404, causing 35+ redirect
 *      errors and 404s in Google Search Console.
 *   ✅ Google Maps API key injection now applies to ALL HTML responses (not just '/')
 *   ✅ leads_v3.html access restricted via worker (returns 403 to bots)
 *
 * Changes from v5.0: only the fetch() router is modified. All other logic is unchanged.
 *
 * Environment Variables (Cloudflare Dashboard → Worker → Settings → Variables):
 *   WHATSAPP_TOKEN          — Meta permanent system user token
 *   WHATSAPP_PHONE_ID       — Meta Phone ID from your own WhatsApp Business account
 *   WHATSAPP_RECIPIENTS     — Comma-separated numbers to alert, e.g. "918837693510"
 *   TELEGRAM_BOT_TOKEN      — Telegram bot token
 *   TELEGRAM_CHAT_ID        — Telegram chat/group ID
 *   EMAILJS_SERVICE_ID      — EmailJS service ID
 *   EMAILJS_TEMPLATE_ID     — EmailJS admin notification template ID
 *   EMAILJS_AUTOREPLY_TEMPLATE_ID — EmailJS student auto-reply template ID
 *   EMAILJS_PUBLIC_KEY      — EmailJS public key
 *   EMAILJS_PRIVATE_KEY     — EmailJS private key
 *   CRM_SECRET              — Secret token for CRM endpoints (min 16 chars)
 *   TURNSTILE_SECRET        — Cloudflare Turnstile secret key
 *   INDEXNOW_KEY            — IndexNow key
 *   GOOGLE_PLACES_KEY       — Google Maps / Places API key (injected into HTML)
 */

const ALLOWED_ORIGINS = [
  'https://www.studyleap.in',
  'https://studyleap.in',
];

// Fallback recipients if WHATSAPP_RECIPIENTS env var not set
const WA_FALLBACK_NUMBERS = ['918837693510']; // TODO(Study LEAP): add a second number here if you want alerts sent to more than one phone

function isAllowedOrigin(o) { return ALLOWED_ORIGINS.includes(o); }

function getCorsHeaders(requestOrigin) {
  const origin = isAllowedOrigin(requestOrigin) ? requestOrigin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-CRM-Secret',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, requestOrigin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...getCorsHeaders(requestOrigin), 'Content-Type': 'application/json' },
  });
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

// -- v6 helpers ---------------------------------------------------------------
const _enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function sha256Hex(str) { return toHex(await crypto.subtle.digest('SHA-256', _enc.encode(str))); }
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', _enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, _enc.encode(msg)));
}
function safeEqual(a, b) {
  a = String(a ?? ''); b = String(b ?? '');
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
// CRM endpoints: constant-time compare, fails closed if the secret is not configured.
function authOk(request, env) {
  if (!env.CRM_SECRET) return false;
  return safeEqual(request.headers.get('X-CRM-Secret') || '', env.CRM_SECRET);
}
// Exact-origin check (the old Referer startsWith() also matched https://studyleap.in.evil.com).
function requestOriginAllowed(request) {
  const origin = request.headers.get('Origin') || '';
  if (origin) return isAllowedOrigin(origin);
  try { return isAllowedOrigin(new URL(request.headers.get('Referer') || '').origin); }
  catch { return false; }
}
// Generic sliding-window limiter on its own table (does not share cleanup with the lead limiter).
let _hitTableReady = false;
async function hitLimit(db, key, max, windowMs) {
  const now = Date.now();
  try {
    if (!_hitTableReady) {
      await db.prepare('CREATE TABLE IF NOT EXISTS hit_limits (k TEXT PRIMARY KEY, hits TEXT NOT NULL, updatedAt INTEGER NOT NULL)').run();
      _hitTableReady = true;
    }
    const row  = await db.prepare('SELECT hits FROM hit_limits WHERE k = ?').bind(key).first();
    const hits = (row ? JSON.parse(row.hits || '[]') : []).filter(t => now - t < windowMs);
    if (hits.length >= max) return true;
    hits.push(now);
    await db.prepare(`INSERT INTO hit_limits (k, hits, updatedAt) VALUES (?,?,?)
      ON CONFLICT(k) DO UPDATE SET hits = excluded.hits, updatedAt = excluded.updatedAt`)
      .bind(key, JSON.stringify(hits), now).run();
    if (Math.random() < 0.05)
      db.prepare('DELETE FROM hit_limits WHERE updatedAt < ?').bind(now - 2 * 24 * 3600 * 1000).run().catch(() => {});
    return false;
  } catch (err) {
    console.error('hitLimit error:', err.message);
    return false; // fail open
  }
}
// Phone analysis: Indian mobiles must be 10 digits starting 6-9; other countries 7-15 digits.
// Obvious fakes (all same digit, <=2 distinct digits, straight sequences) are rejected.
function isJunkNumber(d) {
  if (/^(\d)\1+$/.test(d)) return true;
  if (new Set(d).size <= 2) return true;
  const up = '01234567890123456789', down = '98765432109876543210';
  return up.includes(d) || down.includes(d);
}
function analysePhone(raw) {
  const s = String(raw || '').trim();
  const d = s.replace(/\D/g, '');
  const indian = (l) => ({ ok: /^[6-9]\d{9}$/.test(l) && !isJunkNumber(l), national: l, country: 'IN' });
  if (s.startsWith('+')) {
    if (d.startsWith('91')) return indian(d.slice(2));
    return { ok: d.length >= 7 && d.length <= 15 && !isJunkNumber(d), national: d, country: 'INTL' };
  }
  if (d.length === 12 && d.startsWith('91')) return indian(d.slice(2));
  if (d.length === 11 && d.startsWith('0'))  return indian(d.slice(1));
  if (d.length === 10)                       return indian(d);
  return { ok: false, national: d, country: '' };
}
const phoneKey = (raw) => String(raw || '').replace(/\D/g, '').slice(-10);
// WhatsApp template parameters must be single-line, non-empty text.
function waParam(v, max = 200) {
  const t = String(v ?? '').replace(/[\r\n\t]+/g, ' ').replace(/ {4,}/g, '   ').trim().slice(0, max);
  return t || '-';
}
// Telegram: strip WhatsApp-style *bold* / _italic_ markers and send as plain text.
function toPlain(msg) {
  return String(msg || '').replace(/\*([^*\n]+)\*/g, '$1').replace(/^_(.*)_$/gm, '$1');
}

// ── D1-backed Rate Limiter — per-IP sliding window (5 req / 10 min) ──────────
async function isRateLimited(ip, db) {
  const WINDOW = 10 * 60 * 1000;
  const MAX    = 5;
  const now    = Date.now();
  const cutoff = new Date(now - WINDOW).toISOString();

  try {
    const row = await db
      .prepare('SELECT timestamps FROM rate_limits WHERE ip = ?')
      .bind(ip).first();

    const timestamps = row ? JSON.parse(row.timestamps || '[]') : [];
    const recent = timestamps.filter(t => now - t < WINDOW);
    if (recent.length >= MAX) return true;

    const updated = [...recent, now];
    await db.prepare(`
      INSERT INTO rate_limits (ip, timestamps, updatedAt) VALUES (?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET
        timestamps = excluded.timestamps,
        updatedAt  = excluded.updatedAt
    `).bind(ip, JSON.stringify(updated), new Date().toISOString()).run();

    db.prepare('DELETE FROM rate_limits WHERE updatedAt < ?').bind(cutoff).run()
      .catch(e => console.warn('Rate limit cleanup error:', e.message));

    return false;
  } catch (err) {
    console.error('D1 rate limit error:', err.message);
    return false; // fail open
  }
}

// ── Cloudflare Turnstile verification ─────────────────────────────────────
async function verifyTurnstile(token, secret, remoteip, strict = false) {
  if (!secret) {
    console.warn('TURNSTILE_SECRET not set — skipping (dev mode)');
    return { success: true, skipped: true };
  }
  if (!token || token.trim() === '') {
    return { success: false, error: 'missing-input-response' };
  }
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret, response: token, remoteip }),
      signal: AbortSignal.timeout(5000),
    });
    return await res.json();
  } catch (err) {
    console.error('Turnstile verify error:', err.message);
    return { success: !strict, error: 'verify_fetch_failed' }; // fail open unless strict mode
  }
}

// Decides whether a request passes the bot check.
//  - TURNSTILE_REQUIRED = "true"  (strict): a valid token is mandatory; verification errors block.
//  - otherwise (monitor mode): a missing/invalid token is logged but allowed, so a key or
//    hostname mix-up in the dashboard can never stop real leads. Check the Worker logs for
//    "[Turnstile] monitor" lines, then switch strict mode on.
async function checkTurnstile(env, token, ip) {
  const strict = env.TURNSTILE_REQUIRED === 'true';
  if (strict && !env.TURNSTILE_SECRET) {
    console.error('[Turnstile] strict mode is on but TURNSTILE_SECRET is not set');
    return { ok: false, reason: 'not-configured' };
  }
  if (!token && !strict) return { ok: true, skipped: true };
  const r = await verifyTurnstile(token, env.TURNSTILE_SECRET, ip, strict);
  if (r.success) return { ok: true };
  const why = r['error-codes'] || r.error;
  if (!strict) { console.warn('[Turnstile] monitor mode - failed but allowed:', why); return { ok: true, monitored: true }; }
  console.warn('[Turnstile] blocked:', why);
  return { ok: false, reason: why };
}

// ── Validation ─────────────────────────────────────────────────────────────
const PHONE_RE = /^[\+\d\s\-\(\)]{7,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const XSS_RE   = /<script|javascript:|on\w+=/i;

function validateLead(p) {
  const errors = [];
  const name  = (p['Full Name'] || '').trim();
  const phone = (p['Phone']     || '').trim();
  const email = (p['Email']     || '').trim();
  if (!name || name.length < 2)        errors.push('Full name is required');
  if (name.length > 100)               errors.push('Full name too long');
  if (!phone)                          errors.push('Phone number is required');
  if (phone && (!PHONE_RE.test(phone) || !analysePhone(phone).ok)) errors.push('Invalid phone number');
  if (email && !EMAIL_RE.test(email))  errors.push('Invalid email format');
  for (const [k, v] of Object.entries(p)) {
    if (typeof v === 'string') {
      if (XSS_RE.test(v))  errors.push(`Invalid characters in ${k}`);
      if (v.length > 2000) errors.push(`${k} is too long`);
    }
  }
  return errors;
}

// ── WhatsApp ───────────────────────────────────────────────────────────────
function buildWhatsAppMessage(lead) {
  return [
    `🎓 *New Lead — Study LEAP*`,
    `━━━━━━━━━━━━━━━━━━━━`,
    `👤 *Name:* ${lead.name}`,
    `📱 *Phone:* ${lead.phone}`,
    lead.email       ? `📧 *Email:* ${lead.email}`             : null,
    lead.city        ? `🏙️ *City:* ${lead.city}`               : null,
    `💰 *Loan Type:* ${lead.loanType}`,
    lead.loanAmount  ? `💵 *Amount:* ${lead.loanAmount}`       : null,
    lead.course      ? `📚 *Course:* ${lead.course}`           : null,
    lead.destination ? `✈️ *Destination:* ${lead.destination}` : null,
    lead.message     ? `💬 *Message:* ${lead.message}`         : null,
    `━━━━━━━━━━━━━━━━━━━━`,
    `🕐 *Time:* ${new Date(lead.createdAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`,
    `🔗 *Source:* ${lead.source}`,
    `🆔 *Lead ID:* ${lead.id}`,
  ].filter(Boolean).join('\n');
}

// NOTE: this sends type:'text' (free-form), not an approved template.
// Meta's WhatsApp Cloud API only allows free-form business-initiated
// messages to a number that has messaged your WhatsApp Business number
// within the last 24 hours ("session window"). If WA_FALLBACK_NUMBERS /
// WHATSAPP_RECIPIENTS haven't messaged the business number recently, every
// send here will fail (commonly error code 131047 "re-engagement message"
// or similar). The Code.gs OTP flow avoids this by using an approved
// template — the same fix (a template) would make this immune to the
// 24-hour window too, at the cost of needing Meta template approval.
async function waPost(env, to, payload) {
  try {
    const res = await fetch(
      `https://graph.facebook.com/v19.0/${env.WHATSAPP_PHONE_ID}/messages`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.WHATSAPP_TOKEN}`,
        },
        body: JSON.stringify({ messaging_product: 'whatsapp', recipient_type: 'individual', to, ...payload }),
        signal: AbortSignal.timeout(10000),
      }
    );
    const data = await res.json().catch(() => ({}));
    if (data.error) return { to, ok: false, error: `(#${data.error.code}) ${data.error.message}` };
    if (!res.ok)    return { to, ok: false, error: `HTTP ${res.status}` };
    return { to, ok: true, message_id: data.messages?.[0]?.id };
  } catch (err) {
    return { to, ok: false, error: err.message };
  }
}

// Staff alerts: tries the approved TEMPLATE first (works outside the 24h window), then falls
// back to free-form text (works only inside the 24h window). tpl = { name, params: [...] }.
async function sendWhatsApp(env, message, tpl) {
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID)
    return { ok: false, error: 'WhatsApp env vars not set' };

  const numbers = env.WHATSAPP_RECIPIENTS
    ? env.WHATSAPP_RECIPIENTS.split(',').map(n => n.trim()).filter(Boolean)
    : WA_FALLBACK_NUMBERS;
  const lang = env.WHATSAPP_TEMPLATE_LANG || 'en';

  const results = await Promise.all(numbers.map(async (to) => {
    if (tpl && env.WHATSAPP_TEMPLATES !== 'off') {
      const t = await waPost(env, to, {
        type: 'template',
        template: {
          name: tpl.name,
          language: { code: lang },
          components: [{ type: 'body', parameters: tpl.params.map(p => ({ type: 'text', text: waParam(p) })) }],
        },
      });
      if (t.ok) return { ...t, via: 'template' };
      console.warn(`WhatsApp template ${tpl.name} failed for ${to}: ${t.error} - falling back to text`);
    }
    const r = await waPost(env, to, { type: 'text', text: { preview_url: false, body: message } });
    return r.ok ? { ...r, via: 'text' } : r;
  }));

  const failed = results.filter(r => !r.ok);
  if (failed.length)
    console.error('WhatsApp send failures:', failed.map(r => `${r.to}: ${r.error}`).join(' | '));
  if (failed.length === numbers.length)
    return { ok: false, error: failed.map(r => `${r.to}: ${r.error}`).join(' | ') };
  return { ok: true, results };
}

// OTP: approved AUTHENTICATION template (body = code, copy-code button = code).
async function sendWhatsAppOtp(env, phone10, code) {
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID) return { ok: false, error: 'WhatsApp env vars not set' };
  return waPost(env, '91' + phone10, {
    type: 'template',
    template: {
      name: env.WHATSAPP_OTP_TEMPLATE || 'studyleap_otp2',
      language: { code: env.WHATSAPP_OTP_LANG || 'en' },
      components: [
        { type: 'body',   parameters: [{ type: 'text', text: code }] },
        { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: code }] },
      ],
    },
  });
}

// ── Telegram ───────────────────────────────────────────────────────────────
async function sendTelegram(env, message) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID)
    return { ok: false, error: 'Telegram env vars not set' };
  try {
    const res = await fetch(
      `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:    env.TELEGRAM_CHAT_ID,
          text:       toPlain(message),
        }),
      }
    );
    const data = await res.json();
    if (!data.ok) return { ok: false, error: data.description };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// ── Router ─────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const method = request.method;
    const origin = request.headers.get('Origin') || '';

    // ── CORS preflight ────────────────────────────────────────────────────
    if (method === 'OPTIONS')
      return new Response(null, { status: 204, headers: getCorsHeaders(origin) });

    // ── API Routes — handle BEFORE static asset fallback ─────────────────

    // POST / — form submission (check CORS origin first)
    if (method === 'POST' && url.pathname === '/') {
      if (!requestOriginAllowed(request)) return json({ ok: false, error: 'Forbidden' }, 403, origin);
      return handleFormSubmit(request, env, origin);
    }

    // POST /otp/send, /otp/verify - server-side OTP for the document-upload page
    if (method === 'POST' && (url.pathname === '/otp/send' || url.pathname === '/otp/verify')) {
      if (!requestOriginAllowed(request)) return json({ ok: false, error: 'Forbidden' }, 403, origin);
      return url.pathname === '/otp/send'
        ? handleOtpSend(request, env, origin)
        : handleOtpVerify(request, env, origin);
    }

    if (method === 'POST'   && url.pathname === '/indexnow')       return handleIndexNow(request, env, origin);
    if (method === 'GET'    && url.pathname === '/leads')          return handleGetLeads(request, env, origin);
    if (method === 'PATCH'  && url.pathname.startsWith('/leads/')) return handleUpdateLead(request, env, url.pathname.split('/')[2], origin);
    if (method === 'DELETE' && url.pathname.startsWith('/leads/')) return handleDeleteLead(request, env, url.pathname.split('/')[2], origin);

    // ── Static Asset Serving ──────────────────────────────────────────────
    // FIX v5.1: Previously only served assets for '/' and '*.html' paths,
    // causing all directory-based pages (/education-loan-delhi/, /emi-calculator/,
    // /robots.txt, /sitemap.xml, etc.) to return a JSON 404. This was the root
    // cause of 35+ redirect errors and 404s in Google Search Console.
    //
    // Now ALL GET requests fall through to env.ASSETS, which correctly resolves
    // /path/ → /path/index.html, serves robots.txt, sitemap.xml, images, etc.
    // Google Maps API key is injected into every HTML response (not just '/').
    if (method === 'GET') {
      // API-only deployment: the static site is hosted separately (Cloudflare Pages),
      // so there is no ASSETS binding. Answer health checks instead of crashing (Error 1101).
      if (!env.ASSETS) {
        if (url.pathname === '/' || url.pathname === '/health')
          return json({ ok: true, service: 'Study LEAP form API', status: 'running' }, 200, origin);
        return json({ ok: false, error: 'Not found' }, 404, origin);
      }
      const response = await env.ASSETS.fetch(request);
      const contentType = response.headers.get('content-type') || '';

      // Inject Google Maps API key into all HTML responses
      if (contentType.includes('text/html') && env.GOOGLE_PLACES_KEY) {
        let html = await response.text();
        html = html.replace("var API_KEY  = '';", `var API_KEY  = '${env.GOOGLE_PLACES_KEY}';`);
        return new Response(html, { status: response.status, headers: response.headers });
      }

      // Inject Google Maps API key into reviews.js (loaded as external script)
      if (url.pathname === '/reviews.js' && env.GOOGLE_PLACES_KEY) {
        let js = await response.text();
        js = js.replace("var API_KEY  = '';", `var API_KEY  = '${env.GOOGLE_PLACES_KEY}';`);
        const newHeaders = new Headers(response.headers);
        newHeaders.set('Content-Type', 'application/javascript');
        return new Response(js, { status: response.status, headers: newHeaders });
      }

      return response;
    }

    return json({ error: 'Not found' }, 404, origin);
  },

  // ── Cron trigger — runs every 30 minutes ─────────────────────────────────
  // Add to wrangler.toml: [triggers]  crons = ["*/30 * * * *"]
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleFollowUpReminders(env));
  },
};

// ── Follow-up Reminder Cron ────────────────────────────────────────────────
// Finds leads in "New" status for 2+ hours → sends WhatsApp alert → marks lead.
async function handleFollowUpReminders(env) {
  const REMIND_AFTER_MS  = 2 * 60 * 60 * 1000;  // 2 hours
  const REMIND_CUTOFF_MS = 48 * 60 * 60 * 1000; // ignore leads older than 48h
  const REMINDER_MARKER  = '🔔 auto_reminder_sent';

  const now     = Date.now();
  const twoHAgo = new Date(now - REMIND_AFTER_MS).toISOString();
  const cutoff  = new Date(now - REMIND_CUTOFF_MS).toISOString();

  let stuckLeads = [];
  try {
    const result = await env.DB.prepare(`
      SELECT id, name, phone, city, loanType, loanAmount, course,
             destination, source, message, notes, createdAt
      FROM leads
      WHERE status     = 'New'
        AND createdAt <= ?
        AND createdAt >= ?
      ORDER BY createdAt ASC
    `).bind(twoHAgo, cutoff).all();
    stuckLeads = result.results || [];
  } catch (err) {
    console.error('[Cron] D1 query error:', err.message);
    return;
  }

  if (!stuckLeads.length) {
    console.log('[Cron] No uncontacted leads found.');
    return;
  }

  const reminded = [];

  for (const lead of stuckLeads) {
    let notes = [];
    try { notes = JSON.parse(lead.notes || '[]'); } catch { notes = []; }
    if (notes.some(n => n.text?.includes(REMINDER_MARKER))) continue;

    const waitMins = Math.round((now - new Date(lead.createdAt).getTime()) / 60000);
    const waitStr  = waitMins >= 60
      ? `${Math.floor(waitMins / 60)}h ${waitMins % 60}m`
      : `${waitMins} minutes`;

    const waMsg = [
      `🔔 *Uncontacted Lead Alert — Study LEAP*`,
      `━━━━━━━━━━━━━━━━━━━━`,
      `⚠️ Waiting *${waitStr}* with no contact.`,
      ``,
      `👤 *Name:* ${lead.name}`,
      `📱 *Phone:* ${lead.phone}`,
      lead.city        ? `🏙️ *City:* ${lead.city}`               : null,
      `💰 *Loan Type:* ${lead.loanType || 'Not specified'}`,
      lead.loanAmount  ? `💵 *Amount:* ${lead.loanAmount}`       : null,
      lead.course      ? `📚 *Course:* ${lead.course}`           : null,
      lead.destination ? `✈️ *Destination:* ${lead.destination}` : null,
      lead.message     ? `💬 *Message:* ${lead.message}`         : null,
      `━━━━━━━━━━━━━━━━━━━━`,
      `📅 *Received:* ${new Date(lead.createdAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`,
      `🆔 *Lead ID:* ${lead.id}`,
      ``,
      `👉 Please contact them immediately!`,
    ].filter(Boolean).join('\n');

    const waResult = await sendWhatsApp(env, waMsg, {
      name: env.WHATSAPP_REMINDER_TEMPLATE || 'studyleap_lead_reminde',
      params: [waitStr, lead.name, lead.phone, lead.city, lead.loanType || 'Not specified', lead.id],
    });
    if (!waResult.ok) {
      console.error(`[Cron] WhatsApp failed for ${lead.id}:`, waResult.error);
      continue;
    }

    notes.push({
      text: `${REMINDER_MARKER} — WhatsApp alert sent after ${waitStr} (${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })})`,
      date: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
    });

    try {
      await env.DB.prepare('UPDATE leads SET notes = ? WHERE id = ?')
        .bind(JSON.stringify(notes), lead.id).run();
    } catch (err) {
      console.error(`[Cron] Notes update failed for ${lead.id}:`, err.message);
    }

    reminded.push(lead.name);
    console.log(`[Cron] Reminded: ${lead.name} (${lead.id}) — waited ${waitStr}`);
  }

  // Telegram summary
  if (reminded.length) {
    const summary = [
      `🔔 *Follow-up Reminder Summary*`,
      `Sent *${reminded.length}* WhatsApp alert(s):`,
      ...reminded.map((n, i) => `${i + 1}. ${n}`),
      ``,
      `_Leads waiting 2+ hours in "New" status_`,
    ].join('\n');
    await sendTelegram(env, summary);
  }

  console.log(`[Cron] Done. Reminded: ${reminded.length}/${stuckLeads.length} leads.`);
}

// ── Form submission ────────────────────────────────────────────────────────
async function handleFormSubmit(request, env, origin) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (await isRateLimited(clientIP, env.DB))
    return json({ ok: false, errors: ['Too many submissions. Try again in 10 minutes.'] }, 429, origin);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, errors: ['Invalid JSON body'] }, 400, origin); }

  const {
    emailParams     = {},
    telegramMessage = '',
    honeypot        = '',
    turnstileToken  = '',
  } = body;

  // ── 1. Honeypot ───────────────────────────────────────────────────────────
  if (honeypot && honeypot.trim().length > 0)
    return json({ ok: true, id: uid(), errors: [] }, 200, origin);

  // 1b. Bot speed check: a form submitted within 1.5 s of the page loading was not filled by a person.
  //     (Only applied when the page sends formOpenedAt; older cached pages are unaffected.)
  if (Number(body.formOpenedAt) > 0 && Date.now() - Number(body.formOpenedAt) < 1500)
    return json({ ok: true, id: uid(), errors: [] }, 200, origin);

  // ── 2. Turnstile ──────────────────────────────────────────────────────────
  // Forms that show the Turnstile box always send a token, and it is verified.
  // Inner-page forms have no box yet, so a missing token is accepted unless the
  // Worker variable TURNSTILE_REQUIRED is set to "true" (strict mode).
  const ts = await checkTurnstile(env, turnstileToken, clientIP);
  if (!ts.ok)
    return json({ ok: false, errors: ['Security check failed. Please refresh and try again.'] }, 403, origin);

  // ── 3. Validation ─────────────────────────────────────────────────────────
  const validationErrors = validateLead(emailParams);
  if (validationErrors.length)
    return json({ ok: false, errors: validationErrors }, 400, origin);

  // ── 4. Build lead ─────────────────────────────────────────────────────────
  // Duplicate guard: same phone within 10 minutes -> acknowledge, do not re-notify.
  try {
    const recent = await env.DB.prepare('SELECT phone FROM leads WHERE createdAt >= ?')
      .bind(new Date(Date.now() - 10 * 60 * 1000).toISOString()).all();
    const me = phoneKey(emailParams['Phone']);
    if ((recent.results || []).some(r => phoneKey(r.phone) === me))
      return json({ ok: true, id: uid(), duplicate: true, errors: [] }, 200, origin);
  } catch (err) { console.warn('Duplicate check skipped:', err.message); }

  const lead = {
    id:          uid(),
    name:        emailParams['Full Name'].trim().slice(0, 100),
    phone:       emailParams['Phone'].trim().slice(0, 20),
    email:       (emailParams['Email']       || '').trim().slice(0, 200),
    city:        (emailParams['City']        || '').trim().slice(0, 100),
    loanType:    (emailParams['Loan Type']   || 'International').slice(0, 50),
    loanAmount:  (emailParams['Loan Amount'] || '').slice(0, 50),
    course:      (emailParams['Course']      || '').slice(0, 200),
    destination: emailParams['Loan Type']?.startsWith('Study in')
                   ? emailParams['Loan Type'].replace('Study in ', '').slice(0, 100)
                   : (emailParams['Destination'] || '').slice(0, 100),
    source:      'Website',
    status:      'New',
    assignedTo:  '',
    followup:    '',
    message:     (emailParams['Message'] || '').slice(0, 1000),
    notes:       '[]',
    createdAt:   new Date().toISOString(),
  };

  const errors = [];

  // ── 5. D1 insert ──────────────────────────────────────────────────────────
  try {
    await env.DB.prepare(`
      INSERT INTO leads
        (id, name, phone, email, city, loanType, loanAmount, course,
         destination, source, status, assignedTo, followup, message, notes, createdAt)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(
      lead.id, lead.name, lead.phone, lead.email, lead.city,
      lead.loanType, lead.loanAmount, lead.course, lead.destination,
      lead.source, lead.status, lead.assignedTo, lead.followup,
      lead.message, lead.notes, lead.createdAt
    ).run();
  } catch (err) {
    console.error('D1 insert error:', err.message);
    errors.push('db_error: ' + err.message);
  }

  // ── 6/7. WhatsApp + Telegram — sent independently, in parallel ───────────
  // CHANGED: Telegram used to fire ONLY when WhatsApp failed (a fallback,
  // not a second channel). That meant if WhatsApp was misconfigured, Telegram
  // was your only signal — and if Telegram was *also* misconfigured, both
  // silently produced nothing while EmailJS (below) kept working, since it
  // was never gated on the other two. Now both always fire, and both log
  // their result to Cloudflare's real-time logs (Worker → Logs) so a failure
  // is visible immediately instead of only inside this response's `errors`.
  const waMessage = buildWhatsAppMessage(lead);
  const tgMessage = telegramMessage || waMessage;

  const [waResult, tgResult] = await Promise.all([
    sendWhatsApp(env, waMessage, {
      name: env.WHATSAPP_LEAD_TEMPLATE || 'studyleap_new_lead',
      params: [lead.name, lead.phone, lead.city, lead.loanType, lead.loanAmount, lead.course,
               lead.destination, lead.message, lead.source, lead.id],
    }),
    sendTelegram(env, tgMessage),
  ]);

  if (!waResult.ok) {
    console.error(`[Lead ${lead.id}] WhatsApp FAILED:`, waResult.error);
    errors.push('whatsapp_error: ' + waResult.error);
  } else {
    console.log(`[Lead ${lead.id}] WhatsApp sent OK:`, JSON.stringify(waResult.results));
  }

  if (!tgResult.ok) {
    console.error(`[Lead ${lead.id}] Telegram FAILED:`, tgResult.error);
    errors.push('telegram_error: ' + tgResult.error);
  } else {
    console.log(`[Lead ${lead.id}] Telegram sent OK`);
  }

  // ── 8. EmailJS — admin notification ──────────────────────────────────────
  if (env.EMAILJS_SERVICE_ID && env.EMAILJS_TEMPLATE_ID && env.EMAILJS_PUBLIC_KEY) {
    try {
      const eRes = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id:      env.EMAILJS_SERVICE_ID,
          template_id:     env.EMAILJS_TEMPLATE_ID,
          user_id:         env.EMAILJS_PUBLIC_KEY,
          accessToken:     env.EMAILJS_PRIVATE_KEY || undefined,
          template_params: emailParams,
        }),
      });
      if (!eRes.ok) {
        const errText = await eRes.text();
        console.error(`[Lead ${lead.id}] EmailJS admin notification FAILED:`, errText);
        errors.push("emailjs_error: " + errText);
      } else {
        console.log(`[Lead ${lead.id}] EmailJS admin notification sent OK`);
      }
    } catch (err) {
      console.error(`[Lead ${lead.id}] EmailJS admin fetch FAILED:`, err.message);
      errors.push('emailjs_fetch_error: ' + err.message);
    }
  } else {
    console.warn(`[Lead ${lead.id}] EmailJS admin notification SKIPPED — env vars not set`);
  }

  // ── 9. EmailJS — auto-reply to student ───────────────────────────────────
  const studentEmail = emailParams['Email'];
  if (
    env.EMAILJS_SERVICE_ID &&
    env.EMAILJS_AUTOREPLY_TEMPLATE_ID &&
    env.EMAILJS_PUBLIC_KEY &&
    studentEmail &&
    studentEmail !== 'Not provided' &&
    EMAIL_RE.test(studentEmail) &&
    !(await hitLimit(env.DB, 'ar:' + await sha256Hex(studentEmail.toLowerCase()), 1, 24 * 3600 * 1000))
  ) {
    try {
      const arRes = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id:  env.EMAILJS_SERVICE_ID,
          template_id: env.EMAILJS_AUTOREPLY_TEMPLATE_ID,
          user_id:     env.EMAILJS_PUBLIC_KEY,
          accessToken: env.EMAILJS_PRIVATE_KEY || undefined,
          template_params: {
            student_name:  emailParams['Full Name'],
            student_email: studentEmail,
            loan_type:     emailParams['Loan Type']    || 'Education Loan',
            loan_amount:   emailParams['Loan Amount']  || 'As required',
            course:        emailParams['Course']       || 'Your course',
            submitted_at:  emailParams['Submitted At'] || new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
            reply_to:      'support@studyleap.in',
          },
        }),
      });
      if (!arRes.ok) errors.push('autoreply_error: ' + await arRes.text());
    } catch (err) {
      errors.push('autoreply_fetch_error: ' + err.message);
    }
  }

  return json({ ok: true, id: lead.id, errors, whatsapp: waResult.results || null }, 200, origin);
}

// ── IndexNow ping ─────────────────────────────────────────────────────────
async function handleIndexNow(request, env, origin) {
  if (!authOk(request, env))
    return json({ ok: false, error: 'Unauthorized' }, 401, origin);

  if (!env.INDEXNOW_KEY)
    return json({ ok: false, error: 'INDEXNOW_KEY secret not configured' }, 500, origin);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'Invalid JSON body' }, 400, origin); }

  const urls = Array.isArray(body.urls) ? body.urls.slice(0, 10000) : [];
  if (!urls.length)
    return json({ ok: false, error: 'Provide at least one URL in the "urls" array' }, 400, origin);

  const invalidUrls = urls.filter(u => {
    try { return !ALLOWED_ORIGINS.some(o => u.startsWith(o)); }
    catch { return true; }
  });
  if (invalidUrls.length)
    return json({ ok: false, error: 'All URLs must be on studyleap.in', invalidUrls }, 400, origin);

  try {
    const res = await fetch('https://api.indexnow.org/indexnow', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        host:        'www.studyleap.in',
        key:         env.INDEXNOW_KEY,
        keyLocation: `https://www.studyleap.in/${env.INDEXNOW_KEY}.txt`,
        urlList:     urls,
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok || res.status === 202)
      return json({ ok: true, submitted: urls.length, status: res.status }, 200, origin);
    const text = await res.text().catch(() => '');
    return json({ ok: false, error: `IndexNow responded ${res.status}`, detail: text }, 502, origin);
  } catch (err) {
    return json({ ok: false, error: err.message }, 500, origin);
  }
}

// ── Get leads ──────────────────────────────────────────────────────────────
async function handleGetLeads(request, env, origin) {
  if (!authOk(request, env))
    return json({ ok: false, error: 'Unauthorized' }, 401, origin);
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM leads ORDER BY createdAt DESC'
    ).all();
    const leads = (result.results || []).map(l => ({
      ...l,
      notes: (() => { try { return JSON.parse(l.notes || '[]'); } catch { return []; } })(),
    }));
    return json({ ok: true, leads }, 200, origin);
  } catch (err) {
    return json({ ok: false, error: err.message }, 500, origin);
  }
}

// ── Update lead ────────────────────────────────────────────────────────────
async function handleUpdateLead(request, env, id, origin) {
  if (!authOk(request, env))
    return json({ ok: false, error: 'Unauthorized' }, 401, origin);
  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'Invalid JSON' }, 400, origin); }

  if (body.notes && Array.isArray(body.notes))
    body.notes = JSON.stringify(body.notes);

  const allowed = [
    'name', 'phone', 'email', 'city', 'loanType', 'loanAmount',
    'course', 'destination', 'source', 'status', 'assignedTo',
    'followup', 'message', 'notes',
  ];
  const fields = Object.keys(body).filter(k => allowed.includes(k));
  if (!fields.length) return json({ ok: false, error: 'No valid fields' }, 400, origin);

  try {
    await env.DB.prepare(
      `UPDATE leads SET ${fields.map(f => `${f} = ?`).join(', ')} WHERE id = ?`
    ).bind(...fields.map(f => body[f]), id).run();
    return json({ ok: true }, 200, origin);
  } catch (err) {
    return json({ ok: false, error: err.message }, 500, origin);
  }
}

// ── Delete lead ────────────────────────────────────────────────────────────
async function handleDeleteLead(request, env, id, origin) {
  if (!authOk(request, env))
    return json({ ok: false, error: 'Unauthorized' }, 401, origin);
  try {
    await env.DB.prepare('DELETE FROM leads WHERE id = ?').bind(id).run();
    return json({ ok: true }, 200, origin);
  } catch (err) {
    return json({ ok: false, error: err.message }, 500, origin);
  }
}


// -- Server-side OTP (document-upload page) -----------------------------------
let _otpTableReady = false;
async function ensureOtpTable(db) {
  if (_otpTableReady) return;
  await db.prepare(`CREATE TABLE IF NOT EXISTS otp_codes (
    phone TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, sent_at INTEGER NOT NULL,
    send_count INTEGER NOT NULL DEFAULT 1, window_start INTEGER NOT NULL)`).run();
  _otpTableReady = true;
}

async function handleOtpSend(request, env, origin) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!env.OTP_SECRET) {
    console.error('[OTP] OTP_SECRET is not set - OTP disabled');
    return json({ ok: false, error: 'OTP service not configured' }, 503, origin);
  }
  if (await hitLimit(env.DB, 'otp-ip:' + ip, 10, 15 * 60 * 1000))
    return json({ ok: false, error: 'Too many requests. Please try again later.' }, 429, origin);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'Invalid JSON' }, 400, origin); }

  const ts = await checkTurnstile(env, body.turnstileToken, ip);
  if (!ts.ok) return json({ ok: false, error: 'Security check failed. Please refresh and try again.' }, 403, origin);

  const phone = String(body.phone || '').replace(/\D/g, '');
  if (!/^[6-9]\d{9}$/.test(phone) || isJunkNumber(phone))
    return json({ ok: false, error: 'Enter a valid 10-digit mobile number' }, 400, origin);

  await ensureOtpTable(env.DB);
  const now = Date.now();
  const row = await env.DB.prepare('SELECT * FROM otp_codes WHERE phone = ?').bind(phone).first();
  let sendCount = 1, windowStart = now;
  if (row) {
    const since = now - row.sent_at;
    if (since < 30000)
      return json({ ok: false, error: 'Please wait before requesting another OTP.', retryAfter: Math.ceil((30000 - since) / 1000) }, 429, origin);
    if (now - row.window_start < 15 * 60 * 1000) {
      if (row.send_count >= 3)
        return json({ ok: false, error: 'Too many OTP requests for this number. Try again in 15 minutes.' }, 429, origin);
      sendCount = row.send_count + 1;
      windowStart = row.window_start;
    }
  }

  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  const hash = await sha256Hex(`${env.OTP_SECRET}:${phone}:${code}`);
  await env.DB.prepare(`INSERT INTO otp_codes (phone, code_hash, expires_at, attempts, sent_at, send_count, window_start)
    VALUES (?,?,?,0,?,?,?)
    ON CONFLICT(phone) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
      attempts = 0, sent_at = excluded.sent_at, send_count = excluded.send_count, window_start = excluded.window_start`)
    .bind(phone, hash, now + 10 * 60 * 1000, now, sendCount, windowStart).run();

  const sent = await sendWhatsAppOtp(env, phone, code);
  if (!sent.ok) {
    console.error(`[OTP] WhatsApp send failed for ******${phone.slice(-4)}: ${sent.error}`);
    return json({ ok: false, error: 'Could not send OTP. Please try again.' }, 502, origin);
  }
  return json({ ok: true, expiresIn: 600, resendIn: 30 }, 200, origin);
}

async function handleOtpVerify(request, env, origin) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!env.OTP_SECRET) return json({ ok: false, error: 'OTP service not configured' }, 503, origin);
  if (await hitLimit(env.DB, 'otp-v-ip:' + ip, 30, 15 * 60 * 1000))
    return json({ ok: false, error: 'Too many requests. Please try again later.' }, 429, origin);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'Invalid JSON' }, 400, origin); }

  const phone = String(body.phone || '').replace(/\D/g, '');
  const code  = String(body.code  || '').trim();
  if (!/^[6-9]\d{9}$/.test(phone) || !/^\d{6}$/.test(code))
    return json({ ok: false, error: 'Enter the 6-digit OTP' }, 400, origin);

  await ensureOtpTable(env.DB);
  const row = await env.DB.prepare('SELECT * FROM otp_codes WHERE phone = ?').bind(phone).first();
  if (!row) return json({ ok: false, error: 'No active OTP. Please request a new one.' }, 400, origin);

  const now = Date.now();
  if (now > row.expires_at) {
    await env.DB.prepare('DELETE FROM otp_codes WHERE phone = ?').bind(phone).run();
    return json({ ok: false, error: 'OTP expired. Please request a new one.' }, 400, origin);
  }
  if (row.attempts >= 5) {
    await env.DB.prepare('DELETE FROM otp_codes WHERE phone = ?').bind(phone).run();
    return json({ ok: false, error: 'Too many wrong attempts. Please request a new OTP.' }, 429, origin);
  }

  const hash = await sha256Hex(`${env.OTP_SECRET}:${phone}:${code}`);
  if (!safeEqual(hash, row.code_hash)) {
    const attempts = row.attempts + 1;
    if (attempts >= 5) await env.DB.prepare('DELETE FROM otp_codes WHERE phone = ?').bind(phone).run();
    else await env.DB.prepare('UPDATE otp_codes SET attempts = ? WHERE phone = ?').bind(attempts, phone).run();
    return json({ ok: false, error: 'Incorrect OTP', attemptsLeft: Math.max(0, 5 - attempts) }, 400, origin);
  }

  await env.DB.prepare('DELETE FROM otp_codes WHERE phone = ?').bind(phone).run();
  const exp   = now + 60 * 60 * 1000;                       // token valid for 60 minutes
  const sig   = await hmacHex(env.OTP_SECRET, `${phone}.${exp}`);
  return json({ ok: true, token: `${phone}.${exp}.${sig}`, expiresAt: exp }, 200, origin);
}
