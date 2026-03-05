/**
 * HOCS Till Payments Middleware  v1.0.0
 * ─────────────────────────────────────
 * Node.js / Express gateway between Shopify and Till Payments (PayNuts).
 *
 * Implements recommendations:
 *   #1  Callback signature verification (HMAC-SHA512)
 *   #2  3DS MANDATORY enforcement on all debit requests
 *   #3  Full customer data population from Shopify order
 *   #4  Idempotent merchantTransactionId (Shopify order number)
 *   #6  Amount / currency validation on callback
 *   #7  Server-side rate limiting on payment initiation
 *   #8  Webhook retry handling (idempotent processing)
 *   #9  Structured logging with error-code alerting
 *
 * Endpoints:
 *   POST /api/shopify-webhook   — Shopify orders/create webhook → creates Till debit
 *   POST /api/till-callback     — Till async payment callback → marks Shopify order paid
 *   GET  /health                — Health check
 *
 * This middleware is designed to run EXTERNALLY — NOT on Shopify.
 * Deploy to any Node.js host (Railway, Render, Fly.io, Azure, etc.).
 */

'use strict';

require('dotenv').config();  // Load .env for local development

const express    = require('express');
const crypto     = require('crypto');
const path       = require('path');
const fetch      = require('node-fetch');   // node-fetch@2 for CJS compatibility
const rateLimit  = require('express-rate-limit');
const Database   = require('better-sqlite3');
const nodemailer = require('nodemailer');

// ─── Configuration ──────────────────────────────────────────────────────────

const {
  PORT                  = 3000,
  NODE_ENV              = 'development',

  // Till Payments credentials
  TILL_API_KEY,
  TILL_SHARED_SECRET,
  TILL_API_USER,
  TILL_API_PASS,

  // Shopify credentials (Custom App — 2026 Dev Dashboard)
  SHOPIFY_STORE_DOMAIN,            // e.g. "highonchapel.myshopify.com"
  SHOPIFY_CLIENT_ID,               // Client ID from Dev Dashboard → Settings
  SHOPIFY_CLIENT_SECRET,           // Client Secret from Dev Dashboard → Settings
  SHOPIFY_WEBHOOK_SECRET,          // HMAC secret for verifying Shopify webhooks
  SHOPIFY_STORE_WEBHOOK_SECRET,    // Optional: store-level webhook signing key (Admin → Settings → Notifications)

  // URLs
  TILL_BASE_URL         = 'https://test-gateway.tillpayments.com', // Sandbox (default safe)
  // TILL_BASE_URL      = 'https://gateway.tillpayments.com',      // Production — set via env
  SUCCESS_URL           = 'https://highonchapel.com/pages/payment-success',
  CANCEL_URL            = 'https://highonchapel.com/pages/payment-cancelled',
  ERROR_URL             = 'https://highonchapel.com/pages/payment-error',
  CALLBACK_URL,                    // Must be this server's public URL + /api/till-callback
  DB_PATH          = path.join(__dirname, 'hocs-middleware.db'),  // SQLite persistence

  // Email / SMTP (for sending payment link emails)
  SMTP_HOST        = '',           // e.g. smtp.gmail.com, smtp.sendgrid.net
  SMTP_PORT        = '587',
  SMTP_USER        = '',
  SMTP_PASS        = '',
  SMTP_FROM        = 'High on Chapel <noreply@highonchapel.com>',

  // Store URL
  STORE_URL        = 'https://highonchapel.com',
} = process.env;

// ─── Validate required env vars ─────────────────────────────────────────────

const REQUIRED_ENV = [
  'TILL_API_KEY', 'TILL_SHARED_SECRET', 'TILL_API_USER', 'TILL_API_PASS',
  'SHOPIFY_STORE_DOMAIN', 'SHOPIFY_CLIENT_ID', 'SHOPIFY_CLIENT_SECRET',
  'SHOPIFY_WEBHOOK_SECRET', 'CALLBACK_URL'
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[FATAL] Missing required env var: ${key}`);
    process.exit(1);
  }
}

// ─── Diagnostic: log env var presence at startup (not values) ───────────────
console.log('[BOOT] Webhook secret configured:', {
  SHOPIFY_WEBHOOK_SECRET: SHOPIFY_WEBHOOK_SECRET ? `${SHOPIFY_WEBHOOK_SECRET.substring(0, 6)}...(${SHOPIFY_WEBHOOK_SECRET.length} chars)` : 'UNSET',
  SHOPIFY_CLIENT_SECRET: SHOPIFY_CLIENT_SECRET ? `${SHOPIFY_CLIENT_SECRET.substring(0, 6)}...(${SHOPIFY_CLIENT_SECRET.length} chars)` : 'UNSET',
  SHOPIFY_STORE_WEBHOOK_SECRET: SHOPIFY_STORE_WEBHOOK_SECRET ? `${SHOPIFY_STORE_WEBHOOK_SECRET.substring(0, 6)}...(${SHOPIFY_STORE_WEBHOOK_SECRET.length} chars)` : 'UNSET',
  secretsMatch: SHOPIFY_WEBHOOK_SECRET === SHOPIFY_CLIENT_SECRET,
  uniqueSecrets: [...new Set([SHOPIFY_WEBHOOK_SECRET, SHOPIFY_CLIENT_SECRET, SHOPIFY_STORE_WEBHOOK_SECRET].filter(Boolean))].length,
});

// ─── Structured Logger (Rec #9) ─────────────────────────────────────────────

const logger = {
  _format(level, message, data) {
    return JSON.stringify({
      timestamp: new Date().toISOString(),
      level,
      service: 'hocs-till-middleware',
      message,
      ...data
    });
  },
  info(msg, data = {})  { console.log(this._format('INFO',  msg, data)); },
  warn(msg, data = {})  { console.warn(this._format('WARN',  msg, data)); },
  error(msg, data = {}) { console.error(this._format('ERROR', msg, data)); },
  alert(msg, data = {}) {
    // High-severity — in production pipe to PagerDuty / Slack / email
    console.error(this._format('ALERT', msg, data));
    // TODO: Integrate with alerting service (e.g., Slack webhook, PagerDuty)
  }
};

// ─── Till Payments API Signing ──────────────────────────────────────────────
// Message format per Till API v3 spec:
//   METHOD\nSHA512_HEX(body)\nContent-Type\nDate\nRequestURI
// Body hash = lowercase hex SHA-512.  HMAC output = binary → Base64.

function makeTillSignature(method, body, contentType, date, uri) {
  const bodyHash = crypto.createHash('sha512').update(body || '', 'utf8').digest('hex');
  const message  = [method, bodyHash, contentType, date, uri].join('\n');
  const hmac     = crypto.createHmac('sha512', TILL_SHARED_SECRET).update(message, 'utf8').digest('base64');
  return hmac;
}

// Verify an incoming Till callback signature (Rec #1)
function verifyTillSignature(method, body, contentType, date, uri, receivedSig) {
  const expected = makeTillSignature(method, body, contentType, date, uri);
  // Timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(receivedSig));
  } catch {
    return false;
  }
}

// ─── Till API HTTP Client ───────────────────────────────────────────────────

const TILL_BASIC_AUTH = Buffer.from(`${TILL_API_USER}:${TILL_API_PASS}`).toString('base64');

async function callTillAPI(method, relativeUri, body = null) {
  const date        = new Date().toUTCString();
  const contentType = 'application/json';
  const bodyStr     = body ? JSON.stringify(body) : '';
  const signature   = makeTillSignature(method, bodyStr, contentType, date, relativeUri);
  const url         = `${TILL_BASE_URL}${relativeUri}`;

  const headers = {
    'Authorization': `Basic ${TILL_BASIC_AUTH}`,
    'Content-Type':  contentType,
    'Date':          date,
    'X-Signature':   signature
  };

  const opts = { method, headers };
  if (body) opts.body = bodyStr;

  logger.info('Till API request', { method, uri: relativeUri });

  const res  = await fetch(url, opts);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }

  logger.info('Till API response', { status: res.status, uri: relativeUri });

  if (!res.ok) {
    logger.error('Till API error', { status: res.status, body: text.substring(0, 500) });
  }

  return { status: res.status, body: json, rawBody: text };
}

// ─── Shopify Admin API Client (2026 Client Credentials Grant) ───────────────
// Tokens are short-lived (24 hrs). We cache and auto-refresh before expiry.

const SHOPIFY_API_VERSION = '2025-01';

let _shopifyToken = null;
let _shopifyTokenExpiresAt = 0;

async function getShopifyAccessToken() {
  // Return cached token if still valid (refresh 60s before expiry)
  if (_shopifyToken && Date.now() < _shopifyTokenExpiresAt - 60_000) {
    return _shopifyToken;
  }

  logger.info('Requesting new Shopify access token via client credentials grant');

  const { URLSearchParams } = require('url');
  const response = await fetch(
    `https://${SHOPIFY_STORE_DOMAIN}/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'client_credentials',
        client_id:     SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
      }),
    }
  );

  if (!response.ok) {
    const errText = await response.text().catch(() => 'no body');
    logger.alert('Failed to obtain Shopify access token', {
      status: response.status,
      error: errText.substring(0, 500)
    });
    throw new Error(`Shopify token request failed: ${response.status}`);
  }

  const data = await response.json();
  _shopifyToken = data.access_token;
  // Default to 24hr expiry if not provided
  const expiresIn = data.expires_in || 86400;
  _shopifyTokenExpiresAt = Date.now() + (expiresIn * 1000);

  logger.info('Shopify access token obtained', { expiresInSeconds: expiresIn });
  return _shopifyToken;
}

async function shopifyAdminAPI(method, path, body = null) {
  const token = await getShopifyAccessToken();
  const url = `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}${path}`;
  const opts = {
    method,
    headers: {
      'Content-Type':             'application/json',
      'X-Shopify-Access-Token':   token
    }
  };
  if (body) opts.body = JSON.stringify(body);

  const res  = await fetch(url, opts);
  const json = await res.json().catch(() => null);

  if (!res.ok) {
    // If 401, token may have expired early — force refresh on next call
    if (res.status === 401) {
      _shopifyToken = null;
      _shopifyTokenExpiresAt = 0;
      logger.warn('Shopify token appears expired, cleared cache for retry');
    }
    logger.error('Shopify Admin API error', { status: res.status, path, body: JSON.stringify(json).substring(0, 500) });
  }
  return { status: res.status, body: json };
}

// ─── Email Transport (Payment Link Emails) ──────────────────────────────────
// Sends the customer a direct link to complete their payment.
// If SMTP not configured, logs a warning and continues (non-blocking).

let mailTransport = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailTransport = nodemailer.createTransport({
    host:   SMTP_HOST,
    port:   parseInt(SMTP_PORT, 10),
    secure: parseInt(SMTP_PORT, 10) === 465,
    auth:   { user: SMTP_USER, pass: SMTP_PASS }
  });
  logger.info('SMTP email transport configured', { host: SMTP_HOST });
} else {
  logger.warn('SMTP not configured — payment link emails will NOT be sent. Set SMTP_HOST/USER/PASS.');
}

async function sendPaymentEmail(customerEmail, orderNumber, redirectUrl, amount, currency) {
  if (!mailTransport || !customerEmail) {
    logger.warn('Skipping payment email — no transport or no email', { orderNumber, hasEmail: !!customerEmail });
    return;
  }

  // Build a backup link via the Complete Payment page (in case the direct link expires)
  const completePaymentUrl = `${STORE_URL}/pages/complete-payment?order=${encodeURIComponent(orderNumber)}&email=${encodeURIComponent(customerEmail)}`;

  const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:500px;margin:40px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
    <div style="background:#0f1b2d;padding:30px 24px;text-align:center;">
      <h1 style="color:#ffffff;margin:0;font-size:20px;">Complete Your Payment</h1>
      <p style="color:#8899aa;margin:8px 0 0;font-size:14px;">High on Chapel &mdash; Order #${orderNumber}</p>
    </div>
    <div style="padding:30px 24px;">
      <p style="color:#333;font-size:15px;line-height:1.6;margin:0 0 16px;">
        Thank you for your order! To complete your payment of <strong>$${amount} ${currency}</strong>,
        please click the button below:
      </p>
      <div style="text-align:center;margin:24px 0;">
        <a href="${redirectUrl}" style="display:inline-block;background:#2563eb;color:#ffffff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;">
          Pay Now &rarr;
        </a>
      </div>
      <p style="color:#666;font-size:13px;line-height:1.5;margin:0;">
        If the button above doesn't work, you can also complete your payment at:<br>
        <a href="${completePaymentUrl}" style="color:#2563eb;">${STORE_URL}/pages/complete-payment</a>
      </p>
    </div>
    <div style="background:#f9fafb;padding:16px 24px;text-align:center;border-top:1px solid #eee;">
      <p style="color:#999;font-size:11px;margin:0;">
        Secured by Till Payments &bull; 256-bit SSL encrypted
      </p>
    </div>
  </div>
</body>
</html>`;

  try {
    await mailTransport.sendMail({
      from:    SMTP_FROM,
      to:      customerEmail,
      subject: `Complete your payment — Order #${orderNumber}`,
      html:    htmlBody
    });
    logger.info('Payment link email sent', { orderNumber, to: customerEmail });
  } catch (err) {
    logger.error('Failed to send payment email', { orderNumber, error: err.message });
    // Non-blocking — customer can still use the Complete Payment page
  }
}

// ─── Persistent Idempotency Store (Rec #4 + #8) ────────────────────────────
// SQLite-backed — survives server restarts. Zero external dependencies.
// For multi-instance deployments, replace with Redis or Postgres.

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');           // Write-Ahead Logging for concurrent reads
db.pragma('busy_timeout = 5000');          // Wait up to 5s if DB is locked

db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    txn_id            TEXT PRIMARY KEY,
    status            TEXT NOT NULL DEFAULT 'pending',
    shopify_order_id  TEXT,
    order_number      TEXT,
    amount            TEXT,
    currency          TEXT,
    till_uuid         TEXT,
    purchase_id       TEXT,
    redirect_url      TEXT,
    till_error        TEXT,
    customer_email    TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS webhooks (
    order_id   TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Migrate: add customer_email column if missing (safe to run multiple times)
try {
  db.exec('ALTER TABLE transactions ADD COLUMN customer_email TEXT');
} catch (_) { /* column already exists — ignore */ }

// Prepared statements for performance
const stmts = {
  getTxn:        db.prepare('SELECT * FROM transactions WHERE txn_id = ?'),
  getTxnByOrder: db.prepare('SELECT * FROM transactions WHERE order_number = ?'),
  getTxnByShopifyId: db.prepare('SELECT * FROM transactions WHERE shopify_order_id = ?'),
  upsertTxn:     db.prepare(`
    INSERT INTO transactions (txn_id, status, shopify_order_id, order_number, amount, currency, till_uuid, purchase_id, redirect_url, till_error, customer_email, updated_at)
    VALUES (@txn_id, @status, @shopify_order_id, @order_number, @amount, @currency, @till_uuid, @purchase_id, @redirect_url, @till_error, @customer_email, datetime('now'))
    ON CONFLICT(txn_id) DO UPDATE SET
      status         = excluded.status,
      till_uuid      = COALESCE(excluded.till_uuid, transactions.till_uuid),
      purchase_id    = COALESCE(excluded.purchase_id, transactions.purchase_id),
      redirect_url   = COALESCE(excluded.redirect_url, transactions.redirect_url),
      till_error     = COALESCE(excluded.till_error, transactions.till_error),
      customer_email = COALESCE(excluded.customer_email, transactions.customer_email),
      updated_at     = datetime('now')
  `),
  hasWebhook:    db.prepare('SELECT 1 FROM webhooks WHERE order_id = ?'),
  insertWebhook: db.prepare('INSERT OR IGNORE INTO webhooks (order_id) VALUES (?)')
};

// Helper: read a transaction row as a plain object (or null)
function getTransaction(txnId) {
  const row = stmts.getTxn.get(txnId);
  if (!row) return null;
  return {
    txnId:          row.txn_id,
    status:         row.status,
    shopifyOrderId: row.shopify_order_id,
    orderNumber:    row.order_number,
    amount:         row.amount,
    currency:       row.currency,
    tillUuid:       row.till_uuid,
    purchaseId:     row.purchase_id,
    redirectUrl:    row.redirect_url,
    tillError:      row.till_error,
    customerEmail:  row.customer_email,
    createdAt:      row.created_at,
    updatedAt:      row.updated_at
  };
}

// Helper: look up transaction by Shopify order_number (for redirect page)
function getTransactionByOrderNumber(orderNumber) {
  const row = stmts.getTxnByOrder.get(String(orderNumber));
  if (!row) return null;
  return {
    txnId:          row.txn_id,
    status:         row.status,
    shopifyOrderId: row.shopify_order_id,
    orderNumber:    row.order_number,
    amount:         row.amount,
    currency:       row.currency,
    tillUuid:       row.till_uuid,
    purchaseId:     row.purchase_id,
    redirectUrl:    row.redirect_url,
    tillError:      row.till_error,
    customerEmail:  row.customer_email,
    createdAt:      row.created_at,
    updatedAt:      row.updated_at
  };
}

// Helper: look up transaction by Shopify order ID (for checkout extension)
function getTransactionByShopifyOrderId(shopifyOrderId) {
  const row = stmts.getTxnByShopifyId.get(String(shopifyOrderId));
  if (!row) return null;
  return {
    txnId:          row.txn_id,
    status:         row.status,
    shopifyOrderId: row.shopify_order_id,
    orderNumber:    row.order_number,
    amount:         row.amount,
    currency:       row.currency,
    tillUuid:       row.till_uuid,
    purchaseId:     row.purchase_id,
    redirectUrl:    row.redirect_url,
    tillError:      row.till_error,
    customerEmail:  row.customer_email,
    createdAt:      row.created_at,
    updatedAt:      row.updated_at
  };
}

// Helper: upsert a transaction
function saveTransaction(data) {
  stmts.upsertTxn.run({
    txn_id:           data.txnId           || null,
    status:           data.status          || 'pending',
    shopify_order_id: data.shopifyOrderId  || null,
    order_number:     data.orderNumber     || null,
    amount:           data.amount          || null,
    currency:         data.currency        || null,
    till_uuid:        data.tillUuid        || null,
    purchase_id:      data.purchaseId      || null,
    redirect_url:     data.redirectUrl     || null,
    till_error:       data.tillError       || null,
    customer_email:   data.customerEmail   || null
  });
}

function hasWebhook(orderId)    { return !!stmts.hasWebhook.get(String(orderId)); }
function markWebhook(orderId)   { stmts.insertWebhook.run(String(orderId)); }

// Graceful shutdown — close DB
process.on('SIGINT',  () => { db.close(); process.exit(0); });
process.on('SIGTERM', () => { db.close(); process.exit(0); });

// ─── Express App ────────────────────────────────────────────────────────────

const app = express();

// ── Raw body capture for signature verification ─────────────────────────────
// We need the raw body for both Shopify HMAC and Till X-Signature verification,
// so we capture it before JSON parsing.

app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

// ── Server-side rate limiter for payment initiation (Rec #7) ────────────────

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,      // 1 minute
  max: 5,                   // 5 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many payment requests. Please try again in a minute.' },
  keyGenerator: (req) => req.ip
});

// ── CORS for Complete Payment page ───────────────────────────────────────────
// The /pages/complete-payment theme page calls this endpoint from the browser.

const ALLOWED_ORIGINS = [
  'https://highonchapel.com',
  'https://www.highonchapel.com',
  'https://highonchapel.myshopify.com'
];

app.use('/api/payment-redirect', (req, res, next) => {
  const origin = req.get('Origin');
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Checkout UI Extensions run on Shopify's CDN — allow any origin for this
// email-verified endpoint so the Thank You page extension can poll it.
app.use('/api/payment-redirect-by-shopify-id', (req, res, next) => {
  const origin = req.get('Origin');
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Health check ────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.1.0',
    env: NODE_ENV,
    till_base: TILL_BASE_URL.includes('test-gateway') ? 'sandbox' : 'production'
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/payment-redirect/:orderNumber
// ═════════════════════════════════════════════════════════════════════════════
// Called from /pages/complete-payment theme page.
// Customer provides order number + email → we look up the Till redirect URL.
// Email verification prevents order number enumeration.
//
// Query params:
//   ?email=customer@example.com   (required — must match order email)
//
// Responses:
//   200 { status: "ready",     redirectUrl: "https://..." }  — redirect now
//   200 { status: "pending" }                                — still processing, poll again
//   200 { status: "paid" }                                   — already paid, no redirect needed
//   200 { status: "failed",    error: "..." }                — payment initiation failed
//   200 { status: "not_found" }                              — order not found or email mismatch

app.get('/api/payment-redirect/:orderNumber', (req, res) => {
  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const email       = (req.query.email || '').trim().toLowerCase();

  if (!email) {
    return res.json({ status: 'not_found' });
  }

  // Look up by txn_id (HOC-<orderNumber>) first, fall back to order_number column
  const txnId = `HOC-${orderNumber}`;
  let txn = getTransaction(txnId);
  if (!txn) {
    txn = getTransactionByOrderNumber(orderNumber);
  }

  logger.info('Payment redirect lookup', { orderNumber, txnId, hasEmail: !!email, found: !!txn });

  if (!txn) {
    // Webhook may not have arrived yet — tell client to poll
    return res.json({ status: 'pending' });
  }

  // ── Email verification ────────────────────────────────────────────────
  // Compare stored email against provided email (case-insensitive)
  if (txn.customerEmail && email !== txn.customerEmail.trim().toLowerCase()) {
    // Don't reveal whether the order exists — return not_found
    logger.warn('Payment redirect email mismatch', { orderNumber, provided: email });
    return res.json({ status: 'not_found' });
  }

  logger.info('Payment redirect — returning status', {
    orderNumber,
    txnId,
    txnStatus: txn.status,
    hasRedirectUrl: !!txn.redirectUrl,
    redirectUrlPrefix: txn.redirectUrl ? txn.redirectUrl.substring(0, 100) : null,
  });

  switch (txn.status) {
    case 'initiated':
      if (txn.redirectUrl) {
        return res.json({ status: 'ready', redirectUrl: txn.redirectUrl });
      }
      return res.json({ status: 'pending' });

    case 'pending':
      return res.json({ status: 'pending' });

    case 'paid':
      return res.json({ status: 'paid' });

    case 'failed':
    case 'amount_mismatch':
    case 'currency_mismatch':
      return res.json({ status: 'failed', error: txn.tillError || txn.status });

    default:
      return res.json({ status: 'pending' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/payment-redirect-by-shopify-id/:shopifyOrderId
// ═════════════════════════════════════════════════════════════════════════════
// Same as payment-redirect but looks up by Shopify order ID instead of order number.
// Used by the checkout extension which only has access to the Shopify GID.
//
// Query params:
//   ?email=customer@example.com   (required — must match order email)

app.get('/api/payment-redirect-by-shopify-id/:shopifyOrderId', (req, res) => {
  const shopifyOrderId = req.params.shopifyOrderId.trim();
  const email = (req.query.email || '').trim().toLowerCase();

  if (!email) {
    return res.json({ status: 'not_found' });
  }

  const txn = getTransactionByShopifyOrderId(shopifyOrderId);

  logger.info('Payment redirect by Shopify ID lookup', { shopifyOrderId, hasEmail: !!email, found: !!txn });

  if (!txn) {
    return res.json({ status: 'pending' });
  }

  // Email verification
  if (txn.customerEmail && email !== txn.customerEmail.trim().toLowerCase()) {
    logger.warn('Payment redirect email mismatch (by Shopify ID)', { shopifyOrderId, provided: email });
    return res.json({ status: 'not_found' });
  }

  switch (txn.status) {
    case 'initiated':
      if (txn.redirectUrl) {
        return res.json({ status: 'ready', redirectUrl: txn.redirectUrl });
      }
      return res.json({ status: 'pending' });

    case 'pending':
      return res.json({ status: 'pending' });

    case 'paid':
      return res.json({ status: 'paid' });

    case 'failed':
    case 'amount_mismatch':
    case 'currency_mismatch':
      return res.json({ status: 'failed', error: txn.tillError || txn.status });

    default:
      return res.json({ status: 'pending' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/shopify-webhook
// ═════════════════════════════════════════════════════════════════════════════
// Receives Shopify orders/create webhook, validates HMAC, then sends a
// Till Debit request with 3DS MANDATORY + full customer data.

app.post('/api/shopify-webhook', paymentLimiter, async (req, res) => {
  const requestId = crypto.randomUUID();
  logger.info('Shopify webhook received', { requestId });

  try {
    // ── 1. Verify Shopify webhook HMAC ────────────────────────────────────
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    if (!hmacHeader) {
      logger.warn('Shopify webhook missing HMAC header', { requestId });
      return res.status(401).json({ error: 'Missing HMAC' });
    }

    // Try all configured secrets:
    // 1. SHOPIFY_WEBHOOK_SECRET (explicit webhook secret)
    // 2. SHOPIFY_CLIENT_SECRET (app-managed webhooks use client secret)
    // 3. SHOPIFY_STORE_WEBHOOK_SECRET (store-level admin webhooks use a different key)
    const secrets = [SHOPIFY_WEBHOOK_SECRET, SHOPIFY_CLIENT_SECRET, SHOPIFY_STORE_WEBHOOK_SECRET].filter(Boolean);
    const uniqueSecrets = [...new Set(secrets)];
    let verified = false;

    for (const secret of uniqueSecrets) {
      const computedHmac = crypto
        .createHmac('sha256', secret)
        .update(req.rawBody)
        .digest('base64');

      if (computedHmac.length === hmacHeader.length &&
          crypto.timingSafeEqual(Buffer.from(computedHmac), Buffer.from(hmacHeader))) {
        verified = true;
        break;
      }
    }

    if (!verified) {
      logger.alert('Shopify webhook HMAC verification FAILED', {
        requestId,
        shopifyWebhookId: req.get('X-Shopify-Webhook-Id') || 'missing',
        shopifyTopic: req.get('X-Shopify-Topic') || 'missing',
        shopifyApiVersion: req.get('X-Shopify-Api-Version') || 'missing',
        shopifyTriggeredAt: req.get('X-Shopify-Triggered-At') || 'missing',
        secretLen: SHOPIFY_WEBHOOK_SECRET?.length || 0,
        secretPrefix: SHOPIFY_WEBHOOK_SECRET?.substring(0, 6) || 'UNSET',
        clientSecretLen: SHOPIFY_CLIENT_SECRET?.length || 0,
        clientSecretPrefix: SHOPIFY_CLIENT_SECRET?.substring(0, 6) || 'UNSET',
        storeSecretLen: SHOPIFY_STORE_WEBHOOK_SECRET?.length || 0,
        storeSecretPrefix: SHOPIFY_STORE_WEBHOOK_SECRET?.substring(0, 6) || 'UNSET',
        secretsTriedCount: uniqueSecrets.length,
        rawBodyLen: req.rawBody?.length || 0,
        hmacHeaderLen: hmacHeader?.length || 0,
      });
      return res.status(401).json({ error: 'HMAC verification failed' });
    }

    logger.info('Shopify webhook HMAC verified', { requestId });

    // ── 2. Parse order ────────────────────────────────────────────────────
    const order = req.body;
    const orderId     = order.id;
    const orderNumber = order.order_number || order.name;
    const totalPrice  = order.total_price;     // e.g. "42.50"
    const currency    = order.currency || 'AUD';

    logger.info('Processing order', { requestId, orderId, orderNumber, totalPrice, currency });

    // ── 3. Idempotency: skip if already processed (Rec #8) ───────────────
    const txnId = `HOC-${orderNumber}`;  // Deterministic, idempotent ID (Rec #4)
    if (hasWebhook(orderId)) {
      logger.info('Duplicate webhook — skipping', { requestId, orderId });
      return res.status(200).json({ status: 'already_processed' });
    }
    markWebhook(orderId);

    if (getTransaction(txnId)) {
      logger.info('Transaction already initiated — skipping', { requestId, txnId });
      return res.status(200).json({ status: 'already_initiated', txnId });
    }

    // ── 4. Build customer data from Shopify order (Rec #3) ───────────────
    const billing  = order.billing_address || {};
    const customer = order.customer || {};
    const ip       = order.browser_ip || order.client_details?.browser_ip || '0.0.0.0';

    const tillCustomer = {
      firstName:       billing.first_name || customer.first_name || '',
      lastName:        billing.last_name  || customer.last_name  || '',
      email:           order.email || customer.email || '',
      ipAddress:       ip,
      billingAddress1: billing.address1 || '',
      billingAddress2: billing.address2 || '',
      billingCity:     billing.city || '',
      billingState:    billing.province_code || '',
      billingPostcode: billing.zip || '',
      billingCountry:  billing.country_code || 'AU',
      billingPhone:    billing.phone || customer.phone || ''
    };

    // ── 5. Build debit request with 3DS MANDATORY (Rec #2) ───────────────
    const debitPayload = {
      merchantTransactionId: txnId,
      amount:      totalPrice,
      currency:    currency,
      successUrl:  SUCCESS_URL,
      cancelUrl:   CANCEL_URL,
      errorUrl:    ERROR_URL,
      callbackUrl: CALLBACK_URL,
      description: `High on Chapel Order #${orderNumber}`,
      customer:    tillCustomer,
      language:    'en',
      transactionIndicator: 'SINGLE',
      // extraData is Till's primary flag for enforcing 3DS at the gateway level.
      // Without this, Till may not mandate 3DS even if threeDSecureData is present.
      extraData: {
        '3dsecure': 'MANDATORY'
      },
      threeDSecureData: {
        '3dsecure':                      'MANDATORY',
        channel:                         '02',       // Browser-based (BRW)
        authenticationIndicator:         '01',       // Payment transaction
        cardholderAuthenticationMethod:  '01',       // No cardholder authentication
        challengeIndicator:              '02'        // Challenge requested
      }
    };

    // Store transaction intent before calling Till
    saveTransaction({
      txnId,
      status: 'pending',
      shopifyOrderId: String(orderId),
      orderNumber: String(orderNumber),
      amount: totalPrice,
      currency,
      customerEmail: tillCustomer.email
    });

    // ── 6. Call Till Debit API ────────────────────────────────────────────
    const tillRes = await callTillAPI(
      'POST',
      `/api/v3/transaction/${TILL_API_KEY}/debit`,
      debitPayload
    );

    if (tillRes.body && tillRes.body.success) {
      const tillUuid    = tillRes.body.uuid;
      const purchaseId = tillRes.body.purchaseId;
      const redirectUrl = tillRes.body.redirectUrl;
      const returnType  = tillRes.body.returnType;

      logger.info('Till debit response details', {
        requestId, txnId, tillUuid, purchaseId,
        returnType,
        hasRedirectUrl: !!redirectUrl,
        redirectUrlPrefix: redirectUrl ? redirectUrl.substring(0, 100) : null,
        successUrl: SUCCESS_URL,
      });

      saveTransaction({
        txnId,
        status: 'initiated',
        tillUuid,
        purchaseId,
        redirectUrl
      });

      logger.info('Till debit initiated', { requestId, txnId, tillUuid });

      // ── 7. Send payment link email to customer ─────────────────────────
      // Non-blocking — don't await in the critical path; fire and log errors
      sendPaymentEmail(
        tillCustomer.email,
        orderNumber,
        redirectUrl,
        totalPrice,
        currency
      ).catch(err => logger.error('Payment email error (async)', { txnId, error: err.message }));

      return res.status(200).json({
        status: 'initiated',
        txnId,
        tillUuid,
        redirectUrl
      });
    }

    // Till returned an error
    const tillError = tillRes.body?.errors?.[0] || {};
    saveTransaction({
      txnId,
      status: 'failed',
      tillError: tillRes.rawBody?.substring(0, 500)
    });

    // Alert on specific error codes (Rec #9)
    const ec = tillError.errorCode;
    if (ec === 1004) {
      logger.alert('Till error 1004 — possible configuration issue', { requestId, txnId, error: tillError });
    } else if (ec === 2003) {
      logger.alert('Till error 2003 — payment declined', { requestId, txnId, error: tillError });
    } else if (ec === 2005) {
      logger.warn('Till error 2005 — card expired', { requestId, txnId, error: tillError });
    } else if (ec === 2021) {
      logger.alert('Till error 2021 — 3DS verification failed', { requestId, txnId, error: tillError });
    } else if (ec === 3004) {
      logger.alert('Till error 3004 — duplicate transaction ID', { requestId, txnId, error: tillError });
    } else {
      logger.error('Till debit failed', { requestId, txnId, tillStatus: tillRes.status, error: tillError });
    }

    return res.status(502).json({ error: 'Till debit failed', details: tillError });

  } catch (err) {
    logger.error('Shopify webhook handler error', { requestId, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/till-callback
// ═════════════════════════════════════════════════════════════════════════════
// Receives Till async payment notification. Must:
//   - Verify X-Signature (Rec #1)
//   - Validate amount/currency against original order (Rec #6)
//   - Mark Shopify order as paid via Admin API
//   - Respond HTTP 200 + body "OK"

app.post('/api/till-callback', async (req, res) => {
  const requestId = crypto.randomUUID();
  logger.info('Till callback received', { requestId });

  try {
    // ── 1. Verify Till callback signature (Rec #1) ───────────────────────
    const receivedSig = req.get('X-Signature');
    const date        = req.get('Date') || '';
    const contentType = req.get('Content-Type') || 'application/json';
    const method      = 'POST';
    // Till callbacks POST to our callbackUrl — the URI is our endpoint path
    const uri         = '/api/till-callback';
    const rawBody     = req.rawBody ? req.rawBody.toString('utf8') : JSON.stringify(req.body);

    if (!receivedSig) {
      logger.alert('Till callback missing X-Signature', { requestId });
      // Still respond 200 OK to prevent retries, but log alert
      return res.status(200).send('OK');
    }

    const sigValid = verifyTillSignature(method, rawBody, contentType, date, uri, receivedSig);
    if (!sigValid) {
      logger.alert('Till callback SIGNATURE VERIFICATION FAILED — possible tampering!', {
        requestId,
        receivedSig: receivedSig.substring(0, 20) + '...'
      });
      // Respond 200 to prevent retries but do NOT process
      return res.status(200).send('OK');
    }

    logger.info('Till callback signature verified', { requestId });

    // ── 2. Parse callback data ───────────────────────────────────────────
    const cb = req.body;
    const txnId     = cb.merchantTransactionId;
    const tillUuid  = cb.uuid || cb.referenceUuid;
    const result    = cb.result;       // e.g. "OK", "ERROR"
    const cbAmount  = cb.amount;       // e.g. "42.50"
    const cbCurrency = cb.currency;    // e.g. "AUD"
    const returnType = cb.returnType;  // e.g. "FINISHED", "REDIRECT", "ERROR"

    logger.info('Callback details', { requestId, txnId, tillUuid, result, returnType, cbAmount, cbCurrency });

    // ── 3. Look up original transaction for amount validation (Rec #6) ───
    const original = getTransaction(txnId);
    if (!original) {
      logger.warn('Callback for unknown transaction — may be a replay or test', { requestId, txnId });
      return res.status(200).send('OK');
    }

    // Prevent duplicate processing (Rec #8)
    if (original.status === 'paid') {
      logger.info('Callback for already-paid transaction — skipping', { requestId, txnId });
      return res.status(200).send('OK');
    }

    // ── 4. Validate amount and currency (Rec #6) ─────────────────────────
    if (cbAmount && original.amount) {
      const callbackCents  = Math.round(parseFloat(cbAmount) * 100);
      const originalCents  = Math.round(parseFloat(original.amount) * 100);

      if (callbackCents !== originalCents) {
        logger.alert('AMOUNT MISMATCH — callback amount differs from order!', {
          requestId, txnId,
          expected: original.amount,
          received: cbAmount
        });
        // Do NOT mark as paid — this is suspicious
        saveTransaction({ txnId, status: 'amount_mismatch' });
        return res.status(200).send('OK');
      }
    }

    if (cbCurrency && original.currency && cbCurrency !== original.currency) {
      logger.alert('CURRENCY MISMATCH on callback', {
        requestId, txnId,
        expected: original.currency,
        received: cbCurrency
      });
      saveTransaction({ txnId, status: 'currency_mismatch' });
      return res.status(200).send('OK');
    }

    // ── 5. Process based on result ───────────────────────────────────────
    //
    // returnType values from Till:
    //   'FINISHED' = payment complete, card was charged — mark order paid
    //   'REDIRECT' = hosted payment page is ready; customer still needs to pay — do NOT mark paid
    //   'ERROR'    = payment failed
    //
    // IMPORTANT: 'REDIRECT' must NOT trigger markShopifyOrderPaid.
    // Till sends a REDIRECT callback when the debit is initiated and a hosted
    // payment page URL is generated. The redirect URL is already saved to the
    // DB during the Shopify webhook handler. There is nothing to do here.
    if (returnType === 'REDIRECT') {
      logger.info('Till REDIRECT callback received — hosted payment page ready, awaiting customer payment', {
        requestId, txnId, tillUuid
      });
      // No action needed — redirectUrl already stored; customer will complete payment on Till's page.
      return res.status(200).send('OK');
    }

    if (result === 'OK' && returnType === 'FINISHED') {
      // Payment succeeded — mark Shopify order as paid
      logger.info('Payment successful — marking Shopify order paid', { requestId, txnId });

      const markResult = await markShopifyOrderPaid(original.shopifyOrderId, tillUuid, txnId, original.amount);

      if (markResult.success) {
        saveTransaction({ txnId, status: 'paid', tillUuid });
        logger.info('Shopify order marked as paid', { requestId, txnId, shopifyOrderId: original.shopifyOrderId });
      } else {
        logger.error('Failed to mark Shopify order as paid', {
          requestId, txnId,
          shopifyOrderId: original.shopifyOrderId,
          error: markResult.error
        });
        // Don't update status — retry will catch it
      }

    } else if (result === 'ERROR') {
      saveTransaction({ txnId, status: 'failed', tillUuid });
      const errorCode = cb.errors?.[0]?.errorCode;
      const errorMsg  = cb.errors?.[0]?.errorMessage || cb.errors?.[0]?.message || 'unknown';
      const adapterCode = cb.errors?.[0]?.adapterCode || '';
      const adapterMsg  = cb.errors?.[0]?.adapterMessage || '';

      logger.error('PAYMENT FAILED DETAILS', {
        requestId, txnId, tillUuid,
        errorCode, errorMsg, adapterCode, adapterMsg,
        fullErrors: JSON.stringify(cb.errors),
        fullBody: JSON.stringify(cb).substring(0, 1000)
      });

      if (errorCode === 1004) {
        logger.alert('Till payment error 1004 — check connector/config', { requestId, txnId, errorMsg, adapterMsg });
      } else if (errorCode === 2003) {
        logger.alert('Till payment declined (2003)', { requestId, txnId, errorMsg, adapterMsg });
      } else if (errorCode === 2021) {
        logger.alert('Till 3DS verification failed (2021)', { requestId, txnId, errorMsg, adapterMsg });
      } else if (errorCode === 3004) {
        logger.alert('Till duplicate transaction ID (3004)', { requestId, txnId, errorMsg, adapterMsg });
      } else {
        logger.error('Payment failed — unhandled error code', { requestId, txnId, errorCode, errorMsg, adapterCode, adapterMsg });
      }

    } else {
      logger.warn('Unhandled callback result', { requestId, txnId, result, returnType });
    }

    // ── 6. Always respond HTTP 200 + "OK" (per Till spec) ────────────────
    return res.status(200).send('OK');

  } catch (err) {
    logger.error('Till callback handler error', { requestId, error: err.message, stack: err.stack });
    // Still return 200 to prevent infinite retries
    return res.status(200).send('OK');
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /
// ═════════════════════════════════════════════════════════════════════════════
// Till Developer Certification Test Dashboard
// Provides a UI to drive all 10 test categories without external tooling.

app.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HOCS · Till Certification Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1b2d;color:#e2e8f0;min-height:100vh;padding:24px}
h1{font-size:22px;font-weight:700;color:#60a5fa;margin-bottom:4px}
.sub{color:#94a3b8;font-size:13px;margin-bottom:24px}
.env-badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:700;margin-left:8px;background:${TILL_BASE_URL.includes('test-gateway') ? '#15803d' : '#b91c1c'};color:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:16px}
.card{background:#1e2d42;border:1px solid #2d3f56;border-radius:12px;padding:20px}
.card h2{font-size:14px;font-weight:700;color:#93c5fd;margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:3px;margin-top:10px}
input,select,textarea{width:100%;padding:7px 10px;background:#0f1b2d;border:1px solid #2d3f56;border-radius:6px;color:#e2e8f0;font-size:13px;outline:none}
input:focus,select:focus{border-color:#60a5fa}
button{margin-top:14px;width:100%;padding:9px;background:#2563eb;color:#fff;border:none;border-radius:7px;font-size:13px;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}
button.danger{background:#dc2626}
button.danger:hover{background:#b91c1c}
.response{margin-top:12px;padding:10px;background:#0a1422;border:1px solid #2d3f56;border-radius:6px;font-size:11px;font-family:monospace;white-space:pre-wrap;max-height:200px;overflow-y:auto;display:none}
.response.ok{border-color:#15803d;color:#86efac}
.response.err{border-color:#dc2626;color:#fca5a5}
.tip{font-size:11px;color:#64748b;margin-top:6px}
.cards-tip{color:#fbbf24;font-size:11px;font-weight:600;margin-bottom:8px}
</style>
</head>
<body>
<h1>HOCS Till Certification Dashboard <span class="env-badge">${TILL_BASE_URL.includes('test-gateway') ? 'SANDBOX' : 'PRODUCTION ⚠️'}</span></h1>
<p class="sub">Till Developer Certification · 10 Test Categories · Gateway: ${TILL_BASE_URL}</p>
<p class="cards-tip">Test cards: 4111 1111 1111 1111 (Visa) &nbsp;|&nbsp; 4000 0020 0000 0008 (Visa 3DS) &nbsp;|&nbsp; Decline: 4111 1111 1111 1119</p>

<div class="grid">

<!-- ── CARD 1: Debit ─────────────────────────────────── -->
<div class="card">
  <h2>Tests 1.a–1.h · Debit</h2>
  <p class="tip" style="margin-bottom:8px;color:#fbbf24">Till returns a <strong>redirectUrl</strong> — open it to enter your test card on Till's hosted page.</p>
  <label>Amount</label><input id="d-amount" value="1.00">
  <label>Currency</label><input id="d-cur" value="AUD">
  <label>Transaction Indicator</label>
  <select id="d-indicator">
    <option value="SINGLE">1.e – Single</option>
    <option value="INITIAL">1.a – Initial (with Register)</option>
    <option value="RECURRING">1.b – Recurring</option>
    <option value="CARDONFILE">1.c – Card on File</option>
    <option value="CARDONFILE-MERCHANT-INITIATED">1.d – Card on File Merchant Init</option>
  </select>
  <label>3DS Mode</label>
  <select id="d-3ds">
    <option value="MANDATORY">1.g – 3DS Mandatory</option>
    <option value="OPTIONAL">1.h – 3DS Optional</option>
    <option value="NONE">No 3DS</option>
  </select>
  <label>Dynamic Descriptor (leave blank to skip — Test 1.f)</label>
  <input id="d-descriptor" placeholder="High on Chapel 13-Feb">
  <label>Registration ID (for 1.b/1.c/1.d)</label>
  <input id="d-regid" placeholder="registration UUID from 1.a">
  <label>Merchant Txn ID (auto-filled if blank)</label>
  <input id="d-txnid" placeholder="auto">
  <button onclick="runDebit()">Run Debit</button>
  <div class="response" id="d-resp"></div>
</div>

<!-- ── CARD 2: Preauth ──────────────────────────────── -->
<div class="card">
  <h2>Tests 2.a–2.h · Preauth</h2>
  <p class="tip" style="margin-bottom:8px;color:#fbbf24">Till returns a <strong>redirectUrl</strong> — open it to enter your test card on Till's hosted page.</p>
  <label>Amount</label><input id="p-amount" value="1.00">
  <label>Currency</label><input id="p-cur" value="AUD">
  <label>Transaction Indicator</label>
  <select id="p-indicator">
    <option value="SINGLE">2.e – Single</option>
    <option value="INITIAL">2.a – Initial (with Register)</option>
    <option value="RECURRING">2.b – Recurring</option>
    <option value="CARDONFILE">2.c – Card on File</option>
    <option value="CARDONFILE-MERCHANT-INITIATED">2.d – Card on File Merchant Init</option>
  </select>
  <label>3DS Mode</label>
  <select id="p-3ds">
    <option value="MANDATORY">2.g – 3DS Mandatory</option>
    <option value="OPTIONAL">2.h – 3DS Optional</option>
    <option value="NONE">No 3DS</option>
  </select>
  <label>Dynamic Descriptor (Test 2.f)</label>
  <input id="p-descriptor" placeholder="High on Chapel 13-Feb">
  <label>Registration ID (for 2.b/2.c/2.d)</label>
  <input id="p-regid" placeholder="registration UUID">
  <label>Merchant Txn ID (auto-filled if blank)</label>
  <input id="p-txnid" placeholder="auto">
  <button onclick="runPreauth()">Run Preauth</button>
  <div class="response" id="p-resp"></div>
</div>

<!-- ── CARD 3+4: Capture & Void ─────────────────────── -->
<div class="card">
  <h2>Tests 3 / 3.a · Capture &nbsp;&nbsp; Test 4 · Void</h2>
  <label>Preauth UUID (from Test 2 response)</label>
  <input id="cv-uuid" placeholder="paste uuid here">
  <label>Capture Amount (Test 3.a: less than original)</label>
  <input id="cv-amount" value="1.00">
  <label>Currency</label>
  <input id="cv-cur" value="AUD">
  <label>Merchant Txn ID for Capture (auto if blank)</label>
  <input id="cv-txnid" placeholder="auto">
  <button onclick="runCapture()">Capture (Test 3 / 3.a)</button>
  <button class="danger" onclick="runVoid()">Void Preauth (Test 4)</button>
  <div class="response" id="cv-resp"></div>
</div>

<!-- ── CARD 5: Register & Deregister ─────────────────── -->
<div class="card">
  <h2>Test 5 · Register &nbsp;&nbsp; Test 5.a · Deregister</h2>
  <p class="tip" style="margin-bottom:8px;color:#fbbf24">Till returns a <strong>redirectUrl</strong> — open it to enter your test card on Till's hosted page.</p>
  <label>Customer Email</label><input id="r-email" value="test@highonchapel.com">
  <label>Merchant Txn ID (auto if blank)</label>
  <input id="r-txnid" placeholder="auto">
  <button onclick="runRegister()">Register Card (Test 5)</button>
  <hr style="border-color:#2d3f56;margin:14px 0">
  <label>Registration UUID (from Register response above)</label>
  <input id="r-regid" placeholder="paste registrationId here">
  <button class="danger" onclick="runDeregister()">Deregister (Test 5.a)</button>
  <div class="response" id="r-resp"></div>
</div>

<!-- ── CARD 6+7: Refund ──────────────────────────────── -->
<div class="card">
  <h2>Test 6 · Full Refund &nbsp;&nbsp; Test 7 · Partial Refund</h2>
  <label>Original Transaction UUID (from Debit response)</label>
  <input id="rf-uuid" placeholder="paste uuid here">
  <label>Refund Amount (Test 7: enter less than original)</label>
  <input id="rf-amount" value="1.00">
  <label>Currency</label>
  <input id="rf-cur" value="AUD">
  <label>Reason</label>
  <input id="rf-reason" value="Customer refund request">
  <button onclick="runRefund()">Refund (Test 6 / 7)</button>
  <div class="response" id="rf-resp"></div>
  <p class="tip">Test 6: enter the full original amount. Test 7: enter a partial amount.</p>
</div>

<!-- ── CARD 8+9: Reversal & Incremental ──────────────── -->
<div class="card">
  <h2>Test 8 · Reversal &nbsp;&nbsp; Test 9 · Incremental Auth</h2>
  <label>Original UUID (from Debit/Preauth response)</label>
  <input id="ri-uuid" placeholder="paste uuid here">
  <label>Incremental Amount (Test 9)</label>
  <input id="ri-amount" value="0.50">
  <label>Currency</label>
  <input id="ri-cur" value="AUD">
  <button onclick="runReversal()">Debit Reversal (Test 8)</button>
  <button onclick="runIncremental()">Incremental Auth (Test 9)</button>
  <div class="response" id="ri-resp"></div>
</div>

<!-- ── CARD 10: Negative Tests ───────────────────────── -->
<div class="card">
  <h2>Test 10 · Negative (Declined) Transactions</h2>
  <p class="tip" style="margin-bottom:8px">Click run — Till returns a redirectUrl. On Till's hosted page, use decline card: <strong style="color:#fbbf24">4111 1111 1111 1119</strong></p>
  <label>Amount</label><input id="neg-amount" value="1.00">
  <label>Currency</label><input id="neg-cur" value="AUD">
  <label>Test type</label>
  <select id="neg-type">
    <option value="debit">10.a – Failed Debit</option>
    <option value="preauth">10.b – Failed Preauth</option>
    <option value="register">10.c – Failed Register</option>
  </select>
  <button class="danger" onclick="runNegative()">Run Negative Test</button>
  <div class="response" id="neg-resp"></div>
</div>

</div><!-- /grid -->

<script>
function uid(){ return 'HOC-TEST-' + Date.now() + '-' + Math.floor(Math.random()*10000); }
function show(id, data){
  const el = document.getElementById(id);
  el.style.display='block';
  const ok = data.success !== false && !data.error;
  el.className = 'response ' + (ok ? 'ok' : 'err');
  // Show redirect URL as a prominent clickable link
  let extra = '';
  if (data.redirectUrl) {
    extra = '<div style="margin-bottom:8px"><a href="'+data.redirectUrl+'" target="_blank" style="display:inline-block;background:#15803d;color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none;font-weight:700;font-size:12px">🔗 Open Payment Page →</a><br><span style="font-size:10px;color:#94a3b8;word-break:break-all">'+data.redirectUrl+'</span></div>';
  }
  el.innerHTML = extra + '<pre style="margin:0">'+JSON.stringify(data, null, 2)+'</pre>';
}
async function post(url, body){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  return r.json();
}

async function runDebit(){
  const ind = d('d-indicator'), ds = d('d-3ds'), desc = d('d-descriptor'), regId = d('d-regid');
  const body = { amount: d('d-amount'), currency: d('d-cur'), transactionIndicator: ind,
    threeDSMode: ds, merchantTransactionId: d('d-txnid') || uid(),
    descriptor: desc || undefined, registrationId: regId || undefined };
  show('d-resp', await post('/api/till/debit', body));
}

async function runPreauth(){
  const ind = d('p-indicator'), ds = d('p-3ds'), desc = d('p-descriptor'), regId = d('p-regid');
  const body = { amount: d('p-amount'), currency: d('p-cur'), transactionIndicator: ind,
    threeDSMode: ds, merchantTransactionId: d('p-txnid') || uid(),
    descriptor: desc || undefined, registrationId: regId || undefined };
  show('p-resp', await post('/api/till/preauth', body));
}

async function runCapture(){
  show('cv-resp', await post('/api/till/capture/' + d('cv-uuid'), {
    amount: d('cv-amount'), currency: d('cv-cur'),
    merchantTransactionId: d('cv-txnid') || uid()
  }));
}

async function runVoid(){
  show('cv-resp', await post('/api/till/void/' + d('cv-uuid'), {}));
}

async function runRegister(){
  show('r-resp', await post('/api/till/register', {
    email: d('r-email'), merchantTransactionId: d('r-txnid') || uid()
  }));
}

async function runDeregister(){
  show('r-resp', await post('/api/till/deregister', { registrationId: d('r-regid') }));
}

async function runRefund(){
  show('rf-resp', await post('/api/till/refund/' + d('rf-uuid'), {
    amount: d('rf-amount'), currency: d('rf-cur'), reason: d('rf-reason')
  }));
}

async function runReversal(){
  show('ri-resp', await post('/api/till/reversal/' + d('ri-uuid'), {}));
}

async function runIncremental(){
  show('ri-resp', await post('/api/till/incremental/' + d('ri-uuid'), {
    amount: d('ri-amount'), currency: d('ri-cur')
  }));
}

async function runNegative(){
  const type = d('neg-type');
  const body = { amount: d('neg-amount'), currency: d('neg-cur'),
    transactionIndicator: 'SINGLE', threeDSMode: 'NONE',
    merchantTransactionId: uid(), email: 'test@highonchapel.com' };
  let url = type === 'debit' ? '/api/till/debit' : type === 'preauth' ? '/api/till/preauth' : '/api/till/register';
  show('neg-resp', await post(url, body));
}

function d(id){ return (document.getElementById(id).value||'').trim(); }
</script>
</body>
</html>`);
});

// ═════════════════════════════════════════════════════════════════════════════
// TILL CERTIFICATION TEST ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════
// These endpoints drive the full Till developer certification test matrix.
// They accept card data directly (sandbox only — never use with production cards).

// CORS — allow the dashboard (served from same origin) to call these
app.use('/api/till', (req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── Helper: build 3DS block ─────────────────────────────────────────────────
function build3DSBlock(mode) {
  if (!mode || mode === 'NONE') return {};
  return {
    extraData: { '3dsecure': mode },
    threeDSecureData: {
      '3dsecure': mode,
      channel: '02',
      authenticationIndicator: '01',
      cardholderAuthenticationMethod: '01',
      challengeIndicator: mode === 'MANDATORY' ? '02' : '03'
    }
  };
}

// ─── Helper: build common payment payload from request body ─────────────────
function buildPayload(body, extra = {}) {
  const { pan, expiryMonth, expiryYear, cvv, amount, currency,
          transactionIndicator = 'SINGLE', merchantTransactionId,
          descriptor, registrationId, email, threeDSMode } = body;

  const payload = {
    merchantTransactionId: merchantTransactionId || `HOC-TEST-${Date.now()}`,
    amount,
    currency: currency || 'AUD',
    successUrl: SUCCESS_URL,
    cancelUrl:  CANCEL_URL,
    errorUrl:   ERROR_URL,
    callbackUrl: CALLBACK_URL,
    description: descriptor || 'High on Chapel Certification Test',
    customer: {
      firstName:      'Test',
      lastName:       'Customer',
      email:          email || 'cert@highonchapel.com',
      ipAddress:      '127.0.0.1',
      billingCountry: 'AU'
    },
    transactionIndicator,
    ...build3DSBlock(threeDSMode),
    ...extra
  };

  // NOTE: Till sandbox uses a hosted payment page (HPP) — raw card data is NOT sent via API.
  // Cards are entered by the user on Till's hosted page after following the redirectUrl.
  // Test 1.i (PCI Direct API) requires separate PCI DSS certification and is excluded here.

  // Include registrationId for recurring / card-on-file tests
  if (registrationId) {
    payload.registrationId = registrationId;
  }

  if (descriptor) {
    payload.descriptor = descriptor;
  }

  return payload;
}

// ── POST /api/till/debit ─────────────────────────────────────────────────────
// Tests 1.a – 1.h (and 10.a negative test)

app.post('/api/till/debit', paymentLimiter, async (req, res) => {
  try {
    const payload = buildPayload(req.body);
    const result  = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/debit`, payload);
    logger.info('[CERT] Debit', { txnId: payload.merchantTransactionId, indicator: payload.transactionIndicator, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Debit error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/preauth ───────────────────────────────────────────────────
// Tests 2.a – 2.h (and 10.b negative test)

app.post('/api/till/preauth', paymentLimiter, async (req, res) => {
  try {
    const payload = buildPayload(req.body);
    const result  = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/preauthorize`, payload);
    logger.info('[CERT] Preauth', { txnId: payload.merchantTransactionId, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Preauth error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/capture/:referenceUuid ────────────────────────────────────
// Tests 3 (full) and 3.a (partial)

app.post('/api/till/capture/:referenceUuid', async (req, res) => {
  try {
    const { referenceUuid } = req.params;
    const { amount, currency = 'AUD', merchantTransactionId } = req.body;
    const payload = {
      merchantTransactionId: merchantTransactionId || `HOC-CAP-${Date.now()}`,
      referenceUuid,
      amount,
      currency
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/capture`, payload);
    logger.info('[CERT] Capture', { referenceUuid, amount, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Capture error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/void/:referenceUuid ──────────────────────────────────────
// Test 4 — void a preauth

app.post('/api/till/void/:referenceUuid', async (req, res) => {
  try {
    const { referenceUuid } = req.params;
    const payload = {
      merchantTransactionId: `HOC-VOID-${Date.now()}`,
      referenceUuid
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/void`, payload);
    logger.info('[CERT] Void', { referenceUuid, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Void error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/register ──────────────────────────────────────────────────
// Test 5 — register a card (also used for 1.a Initial / 2.a Initial)
// Returns registrationId for use in subsequent recurring/COF tests.

app.post('/api/till/register', paymentLimiter, async (req, res) => {
  try {
    const { pan, expiryMonth, expiryYear, cvv, email, merchantTransactionId } = req.body;
    const payload = {
      merchantTransactionId: merchantTransactionId || `HOC-REG-${Date.now()}`,
      customer: {
        firstName:      'Test',
        lastName:       'Customer',
        email:          email || 'cert@highonchapel.com',
        ipAddress:      '127.0.0.1',
        billingCountry: 'AU'
      },
      // No raw card data — Till sandbox uses hosted payment page flow
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/register`, payload);
    logger.info('[CERT] Register', { txnId: payload.merchantTransactionId, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Register error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/deregister ────────────────────────────────────────────────
// Test 5.a — deregister a previously registered card

app.post('/api/till/deregister', async (req, res) => {
  try {
    const { registrationId } = req.body;
    if (!registrationId) return res.status(400).json({ error: 'registrationId required' });
    const payload = {
      merchantTransactionId: `HOC-DEREG-${Date.now()}`,
      registrationId
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/deregister`, payload);
    logger.info('[CERT] Deregister', { registrationId, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Deregister error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/refund/:referenceUuid ─────────────────────────────────────
// Test 6 (full) and Test 7 (partial)

app.post('/api/till/refund/:referenceUuid', async (req, res) => {
  try {
    const { referenceUuid } = req.params;
    const { amount, currency = 'AUD', reason = 'Customer refund request' } = req.body;
    const payload = {
      merchantTransactionId: `HOC-REFUND-${Date.now()}`,
      referenceUuid,
      amount,
      currency,
      description: reason
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/refund`, payload);
    logger.info('[CERT] Refund', { referenceUuid, amount, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Refund error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/reversal/:referenceUuid ───────────────────────────────────
// Test 8 — debit reversal (must be called quickly after the original debit)

app.post('/api/till/reversal/:referenceUuid', async (req, res) => {
  try {
    const { referenceUuid } = req.params;
    const payload = {
      merchantTransactionId: `HOC-REV-${Date.now()}`,
      referenceUuid
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/reversal`, payload);
    logger.info('[CERT] Reversal', { referenceUuid, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Reversal error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/till/incremental/:referenceUuid ────────────────────────────────
// Test 9 — incremental authorisation (increase a preauth amount)

app.post('/api/till/incremental/:referenceUuid', async (req, res) => {
  try {
    const { referenceUuid } = req.params;
    const { amount, currency = 'AUD' } = req.body;
    const payload = {
      merchantTransactionId: `HOC-INC-${Date.now()}`,
      referenceUuid,
      amount,
      currency
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/incrementalAuthorization`, payload);
    logger.info('[CERT] Incremental auth', { referenceUuid, amount, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Incremental auth error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ─── Mark Shopify Order as Paid ─────────────────────────────────────────────
// Uses Shopify Admin API to create a transaction marking the order as paid.
// kind:'sale' is correct for externally-processed payments — 'capture' requires
// a prior Shopify authorization which doesn't exist here (Till handled payment).

async function markShopifyOrderPaid(shopifyOrderId, tillUuid, txnId, amount) {
  try {
    // Create a transaction to mark the order paid
    const transactionPayload = {
      transaction: {
        kind:      'sale',
        status:    'success',
        amount:    amount,           // Explicit amount from original order
        gateway:   'Till Payments (PayNuts)',
        authorization: tillUuid || txnId
      }
    };

    const result = await shopifyAdminAPI(
      'POST',
      `/orders/${shopifyOrderId}/transactions.json`,
      transactionPayload
    );

    if (result.status >= 200 && result.status < 300) {
      return { success: true };
    }
    return { success: false, error: JSON.stringify(result.body) };

  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(PORT, () => {
  logger.info('HOCS Till Middleware started', {
    port: PORT,
    env: NODE_ENV,
    tillEndpoint: TILL_BASE_URL,
    shopifyStore: SHOPIFY_STORE_DOMAIN,
    callbackUrl: CALLBACK_URL
  });
});

module.exports = app; // For testing
