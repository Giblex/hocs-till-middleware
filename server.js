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
  'https://highonchapel.myshopify.com',
  'https://hocdev.myshopify.com'
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
    version: '1.0.0',
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

    const computedHmac = crypto
      .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
      .update(req.rawBody)
      .digest('base64');

    if (!crypto.timingSafeEqual(Buffer.from(computedHmac), Buffer.from(hmacHeader))) {
      logger.alert('Shopify webhook HMAC verification FAILED', { requestId });
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
      threeDSecureData: {
        '3dsecure':                      'MANDATORY',
        channel:                         '02',       // Browser-based
        authenticationIndicator:         '01',       // Payment transaction
        cardholderAuthenticationMethod:  '01',       // No authentication
        challengeIndicator:              '02'        // Challenge requested (mandate for high-risk)
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
    if (result === 'OK' && (returnType === 'FINISHED' || returnType === 'REDIRECT')) {
      // Payment succeeded — mark Shopify order as paid
      logger.info('Payment successful — marking Shopify order paid', { requestId, txnId });

      const markResult = await markShopifyOrderPaid(original.shopifyOrderId, tillUuid, txnId);

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

      if (errorCode === 1004) {
        logger.alert('Till payment error 1004 — check connector/config', { requestId, txnId, errors: cb.errors });
      } else if (errorCode === 2003) {
        logger.alert('Till payment declined (2003)', { requestId, txnId, errors: cb.errors });
      } else if (errorCode === 2021) {
        logger.alert('Till 3DS verification failed (2021)', { requestId, txnId, errors: cb.errors });
      } else if (errorCode === 3004) {
        logger.alert('Till duplicate transaction ID (3004)', { requestId, txnId, errors: cb.errors });
      } else {
        logger.error('Payment failed', { requestId, txnId, result, errors: cb.errors });
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

// ─── Mark Shopify Order as Paid ─────────────────────────────────────────────
// Uses Shopify Admin API to create a transaction marking the order as paid.

async function markShopifyOrderPaid(shopifyOrderId, tillUuid, txnId) {
  try {
    // Create a transaction to mark the order paid
    const transactionPayload = {
      transaction: {
        kind:     'capture',
        status:   'success',
        // amount omitted — Shopify uses order total automatically
        gateway:  'Till Payments (PayNuts)',
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
