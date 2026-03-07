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

// Optional: Puppeteer for HPP auto-completion (cert testing)
let puppeteer;
try { puppeteer = require('puppeteer-core'); }
catch { puppeteer = null; console.warn('[BOOT] puppeteer-core not installed – HPP auto-completion disabled'); }

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

// Cert-test redirect URLs — hosted on this middleware server so they always work
// regardless of whether the Shopify storefront pages are configured correctly.
const CERT_ORIGIN      = new URL(CALLBACK_URL).origin;
const CERT_SUCCESS_URL = `${CERT_ORIGIN}/cert-paid`;
const CERT_CANCEL_URL  = `${CERT_ORIGIN}/cert-cancelled`;
const CERT_ERROR_URL   = `${CERT_ORIGIN}/cert-error`;

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

// ─── HPP Auto-Completion (Puppeteer headless Chrome) ────────────────────────
// Launches a real browser to navigate Till's hosted payment page, fill in test
// card data, and submit — works even when the HPP is a JS-rendered SPA.

const _delay = ms => new Promise(r => setTimeout(r, ms));
let _hppBrowser = null;

async function getHPPBrowser() {
  if (!puppeteer) throw new Error('puppeteer-core not available');
  if (_hppBrowser && _hppBrowser.isConnected()) return _hppBrowser;
  _hppBrowser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
           '--disable-gpu', '--single-process', '--no-zygote'],
    headless: 'new',
    timeout: 20000
  });
  return _hppBrowser;
}

async function closeHPPBrowser() {
  if (_hppBrowser) { await _hppBrowser.close().catch(() => {}); _hppBrowser = null; }
}

async function completeHPP(redirectUrl, cardNumber = '4111111111111111') {
  if (!redirectUrl) return { completed: false, error: 'No redirect URL' };
  if (!puppeteer)   return { completed: false, error: 'Puppeteer not available' };

  let page;
  try {
    const browser = await getHPPBrowser();
    page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    logger.info('[HPP] navigating', { url: redirectUrl });
    await page.goto(redirectUrl, { waitUntil: 'networkidle2', timeout: 30000 });

    // Already on terminal URL?
    if (/cert-paid|cert-error|cert-cancelled/.test(page.url()))
      return { completed: /cert-paid/.test(page.url()), url: page.url() };

    // Give JS / Ixopay vault iframes time to initialise
    await _delay(4000);

    // ── Fill main-frame fields: first name, last name, expiry selects ──
    const firstName = await page.$('#first_name');
    const lastName  = await page.$('#last_name');
    if (firstName) { await firstName.click({ clickCount: 3 }); await firstName.type('Test'); }
    if (lastName)  { await lastName.click({ clickCount: 3 }); await lastName.type('Customer'); }
    await page.select('#month', '12').catch(() => {});
    await page.select('#year', '2030').catch(() => {});

    // ── Card number: inside Ixopay secure vault iframe (pan.html) ──
    const panFrame = page.frames().find(f => /\/iframes\/pan/i.test(f.url()));
    if (panFrame) {
      const panInput = await panFrame.waitForSelector('input', { timeout: 5000 }).catch(() => null);
      if (panInput) { await panInput.click(); await panInput.type(cardNumber); }
      else logger.warn('[HPP] no input inside PAN iframe');
    } else {
      logger.warn('[HPP] PAN iframe not found', { frames: page.frames().map(f => f.url()) });
    }

    // ── CVV: inside a separate vault iframe (cvv.html) ──
    const cvvFrame = page.frames().find(f => /\/iframes\/cvv/i.test(f.url()));
    if (cvvFrame) {
      const cvvInput = await cvvFrame.waitForSelector('input', { timeout: 5000 }).catch(() => null);
      if (cvvInput) { await cvvInput.click(); await cvvInput.type('123'); }
      else logger.warn('[HPP] no input inside CVV iframe');
    } else {
      logger.warn('[HPP] CVV iframe not found', { frames: page.frames().map(f => f.url()) });
    }

    logger.info('[HPP] form filled, submitting');

    // ── Click Submit (triggers Ixopay.PaymentFormV2.submitPaymentForm) ──
    const clicked = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('button, input[type="submit"]')];
      const pay = btns.find(b => /submit|pay/i.test((b.textContent || b.value || '').trim()));
      if (pay) { pay.click(); return 'btn'; }
      const form = document.getElementById('payment-form');
      if (form) { form.requestSubmit ? form.requestSubmit() : form.submit(); return 'form'; }
      return false;
    });

    if (!clicked) {
      return { completed: false, error: 'No submit button found', url: page.url() };
    }

    // ── Wait for navigation / redirect ──
    await page.waitForNavigation({ timeout: 30000, waitUntil: 'networkidle2' }).catch(() => {});

    // ── Handle 3DS challenge or intermediate pages ──
    for (let i = 0; i < 4 && !/cert-paid|cert-error|cert-cancelled/.test(page.url()); i++) {
      logger.info('[HPP] intermediate page', { url: page.url(), attempt: i });
      await _delay(3000);

      const clickedChallenge = await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button, input[type="submit"]')];
        const btn = btns.find(b => { const s = window.getComputedStyle(b); return s.display !== 'none' && s.visibility !== 'hidden' && b.offsetWidth > 0; });
        if (btn) { btn.click(); return true; }
        const form = document.querySelector('form');
        if (form) { form.submit(); return true; }
        return false;
      }).catch(() => false);

      if (clickedChallenge) {
        await page.waitForNavigation({ timeout: 20000, waitUntil: 'networkidle2' }).catch(() => {});
      } else {
        await page.waitForFunction(
          'location.href.includes("cert-paid") || location.href.includes("cert-error") || location.href.includes("cert-cancelled")',
          { timeout: 15000 }
        ).catch(() => {});
      }
    }

    const finalUrl = page.url();
    const completed = /cert-paid/.test(finalUrl);
    logger.info('[HPP] done', { url: finalUrl, completed });
    return { completed, url: finalUrl };

  } catch (err) {
    logger.error('[HPP] error', { url: redirectUrl, err: err.message });
    return { completed: false, error: err.message };
  } finally {
    if (page) await page.close().catch(() => {});
  }
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
// CERT-TEST REDIRECT PAGES
// ═════════════════════════════════════════════════════════════════════════════
// Till redirects the browser here after the customer completes (or cancels/
// errors on) the Hosted Payment Page.  These pages are self-contained so they
// work regardless of the Shopify storefront theme configuration.

function certRedirectPage({ icon, colour, title, message, extra = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} – High on Chapel</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0a1628;min-height:100vh;display:flex;align-items:center;justify-content:center;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:20px}
    .card{background:#0f1b2d;border:1px solid rgba(255,255,255,.12);border-radius:16px;
          padding:48px 32px;max-width:460px;width:100%;text-align:center;color:#e8edf3;
          box-shadow:0 8px 32px rgba(0,0,0,.3)}
    svg{margin-bottom:20px}
    h1{font-size:1.4rem;font-weight:700;color:#fff;margin-bottom:12px}
    p{font-size:.95rem;color:#8899aa;line-height:1.6;margin-bottom:28px}
    a.btn{display:inline-block;padding:14px 32px;border-radius:8px;font-size:.9rem;font-weight:700;
          text-decoration:none;text-transform:uppercase;letter-spacing:.04em;
          background:linear-gradient(135deg,${colour} 0%,${colour}cc 100%);
          color:#fff;box-shadow:0 2px 8px ${colour}55}
    .note{font-size:.7rem;color:#556677;margin-top:24px}
  </style>
</head>
<body>
  <div class="card">
    ${icon}
    <h1>${title}</h1>
    <p>${message}</p>
    <a class="btn" href="/">← Back to Certification Dashboard</a>
    ${extra}
    <p class="note">Secured by Till Payments · 256-bit SSL Encrypted</p>
  </div>
</body>
</html>`;
}

app.get('/cert-paid', (_req, res) => {
  res.send(certRedirectPage({
    icon: `<svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    colour: '#16a34a',
    title:  'Payment Successful',
    message:'Your payment was processed successfully. Return to the certification dashboard to continue.'
  }));
});

app.get('/cert-cancelled', (_req, res) => {
  res.send(certRedirectPage({
    icon: `<svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    colour: '#d97706',
    title:  'Payment Cancelled',
    message:'The payment was cancelled. Return to the certification dashboard and try again.'
  }));
});

app.get('/cert-error', (_req, res) => {
  const qs = Object.entries(_req.query).map(([k,v])=>`${k}=${v}`).join(' · ') || '';
  res.send(certRedirectPage({
    icon: `<svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    colour: '#dc2626',
    title:  'Payment Error',
    message:'Something went wrong during payment processing. Return to the certification dashboard and try again.',
    extra: qs ? `<p class="note" style="margin-top:8px">${qs}</p>` : ''
  }));
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/cert/puppeteer-check
// Quick health check: can Puppeteer launch Chrome and load a page?
app.get('/api/cert/puppeteer-check', async (_req, res) => {
  const info = { puppeteerLoaded: !!puppeteer, chromiumPath: process.env.CHROMIUM_PATH || '/usr/bin/chromium' };
  try {
    const browser = await getHPPBrowser();
    info.browserConnected = browser.isConnected();
    const page = await browser.newPage();
    await page.goto('https://example.com', { waitUntil: 'networkidle2', timeout: 15000 });
    info.pageTitle = await page.title();
    info.pageUrl = page.url();
    await page.close();
    info.ok = true;
  } catch (e) {
    info.ok = false;
    info.error = e.message;
    info.stack = e.stack?.substring(0, 500);
  }
  res.json(info);
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/cert/hpp-debug
// ═════════════════════════════════════════════════════════════════════════════
// Diagnostic: create a throwaway debit, load the HPP in headless Chrome,
// return rendered HTML analysis (sees JS-rendered forms unlike plain fetch).
app.get('/api/cert/hpp-debug', async (_req, res) => {
  try {
    const ts = `HPP-DEBUG-${Date.now()}`;
    const BASE = `/api/v3/transaction/${TILL_API_KEY}`;
    const r = await callTillAPI('POST', BASE + '/debit', {
      merchantTransactionId: ts, amount: '1.00', currency: 'AUD',
      transactionIndicator: 'SINGLE', description: 'HPP Debug Test',
      customer: { firstName: 'Test', lastName: 'Debug', email: 'debug@test.com', ipAddress: '127.0.0.1', billingCountry: 'AU' },
      successUrl: CERT_SUCCESS_URL, cancelUrl: CERT_CANCEL_URL, errorUrl: CERT_ERROR_URL, callbackUrl: CALLBACK_URL
    });
    const d = r.body || {};
    if (!d.redirectUrl) return res.json({ error: 'No redirectUrl', raw: d });

    // Use Puppeteer to see the RENDERED page (not raw HTML)
    if (!puppeteer) return res.json({ error: 'Puppeteer not available', redirectUrl: d.redirectUrl });
    const browser = await getHPPBrowser();
    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120');
    await page.goto(d.redirectUrl, { waitUntil: 'networkidle2', timeout: 30000 });
    await _delay(3000); // Let JS render

    const debug = await page.evaluate(() => {
      const inputs = [...document.querySelectorAll('input, select, textarea')].map(el => ({
        tag: el.tagName, name: el.name, id: el.id, type: el.type,
        autocomplete: el.autocomplete || '', placeholder: el.placeholder || '',
        className: el.className, visible: el.offsetWidth > 0 && el.offsetHeight > 0
      }));
      const forms = [...document.querySelectorAll('form')].map(f => ({
        action: f.action, method: f.method, id: f.id, className: f.className,
        inputCount: f.querySelectorAll('input, select').length
      }));
      const iframes = [...document.querySelectorAll('iframe')].map(f => ({
        src: f.src, id: f.id, name: f.name, width: f.offsetWidth, height: f.offsetHeight
      }));
      return { title: document.title, inputs, forms, iframes, bodyText: document.body?.innerText?.substring(0, 2000) || '' };
    });

    const html = await page.content();
    await page.close().catch(() => {});

    res.json({
      redirectUrl: d.redirectUrl,
      landedUrl: page.url ? page.url() : 'closed',
      htmlLength: html.length,
      rendered: debug,
      htmlFirst3000: html.substring(0, 3000),
      htmlLast1000: html.substring(html.length - 1000)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/cert/run-all
// ═════════════════════════════════════════════════════════════════════════════
// Runs ALL certification API calls automatically and returns results as JSON.
// HPP-based tests return a redirectUrl the user must open once; all UUIDs and
// remarks are pre-generated here.

app.get('/api/cert/run-all', async (_req, res) => {
  const ts = () => `HOC-CERT-${Date.now()}-${Math.floor(Math.random()*9999)}`;
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  async function run(label, method, path, body = {}) {
    await sleep(12000);
    try {
      const r = await callTillAPI(method, path, body);
      const d = r.body || {};
      return { label, success: d.success !== false && !(d.errors && d.errors.length), uuid: d.uuid || d.registrationId || null, redirectUrl: d.redirectUrl || null, raw: d };
    } catch (e) {
      return { label, success: false, uuid: null, redirectUrl: null, raw: { error: e.message } };
    }
  }

  async function runHPP(label, method, path, body, cardNumber = '4111111111111111') {
    const r = await run(label, method, path, body);
    if (r.redirectUrl) {
      const hpp = await completeHPP(r.redirectUrl, cardNumber);
      r.hppCompleted = hpp.completed;
      r.hppError     = hpp.error;
      if (!hpp.completed) r.needsManual = true;
      logger.info('[CERT] HPP auto', { label, completed: hpp.completed, error: hpp.error });
    }
    return r;
  }

  const BASE  = `/api/v3/transaction/${TILL_API_KEY}`;
  const CUST  = { firstName:'Test', lastName:'Customer', email:'cert@highonchapel.com', ipAddress:'127.0.0.1', billingCountry:'AU' };
  const URLS  = { successUrl: CERT_SUCCESS_URL, cancelUrl: CERT_CANCEL_URL, errorUrl: CERT_ERROR_URL, callbackUrl: CALLBACK_URL };
  const FAIL  = (label, reason) => ({ label, success: false, uuid: null, redirectUrl: null, raw: { error: reason } });

  // ═══ Phase 1: HPP transactions — create + auto-complete payment pages ═══
  const d_1a = await runHPP('1.a – Debit INITIAL',               'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'INITIAL', description:'HOC Cert 1.a', customer:CUST, ...URLS });
  const d_1e = await runHPP('1.e – Debit SINGLE no 3DS',         'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.e', customer:CUST, ...URLS });
  const d_1f = await runHPP('1.f – Debit SINGLE Dynamic Desc',   'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'High on Chapel 13-Feb', customer:CUST, ...URLS });
  const d_1g = await runHPP('1.g – Debit SINGLE 3DS MANDATORY',  'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.g', customer:CUST, ...URLS, extraData:{'3dsecure':'MANDATORY'}, threeDSecureData:{'3dsecure':'MANDATORY',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'02'} }, '4000002000000008');
  const d_1h = await runHPP('1.h – Debit SINGLE 3DS OPTIONAL',   'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.h', customer:CUST, ...URLS, extraData:{'3dsecure':'OPTIONAL'}, threeDSecureData:{'3dsecure':'OPTIONAL',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'03'} });

  const p_2a = await runHPP('2.a – Preauth INITIAL',              'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'INITIAL', description:'HOC Cert 2.a', customer:CUST, ...URLS });
  const p_2e = await runHPP('2.e – Preauth SINGLE no 3DS',        'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.e', customer:CUST, ...URLS });
  const p_2f = await runHPP('2.f – Preauth SINGLE Dynamic Desc',  'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'High on Chapel 13-Feb', customer:CUST, ...URLS });
  const p_2g = await runHPP('2.g – Preauth SINGLE 3DS MANDATORY', 'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.g', customer:CUST, ...URLS, extraData:{'3dsecure':'MANDATORY'}, threeDSecureData:{'3dsecure':'MANDATORY',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'02'} }, '4000002000000008');
  const p_2h = await runHPP('2.h – Preauth SINGLE 3DS OPTIONAL',  'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.h', customer:CUST, ...URLS, extraData:{'3dsecure':'OPTIONAL'}, threeDSecureData:{'3dsecure':'OPTIONAL',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'03'} });

  const t5   = await runHPP('5 – Register card', 'POST', BASE+'/register', { merchantTransactionId:ts(), customer:CUST, ...URLS });

  // ═══ Phase 2: Settle wait — give Till time to process HPP completions ═══
  logger.info('[CERT] Waiting 15s for HPP settlements…');
  await sleep(15000);

  // ═══ Phase 3: RECURRING / CARDONFILE (server-to-server, need 1.a / 2.a HPP done) ═══
  const refD = d_1a.uuid, refPA = p_2a.uuid;
  const d_1b = await run('1.b – Debit RECURRING',                 'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'RECURRING',                    description:'HOC Cert 1.b', customer:CUST, callbackUrl: CALLBACK_URL, ...(refD ? {referenceUuid:refD}:{}) });
  const d_1c = await run('1.c – Debit CARDONFILE',                'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE',                   description:'HOC Cert 1.c', customer:CUST, callbackUrl: CALLBACK_URL, ...(refD ? {referenceUuid:refD}:{}) });
  const d_1d = await run('1.d – Debit CARDONFILE-MERCHANT-INIT',  'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', description:'HOC Cert 1.d', customer:CUST, callbackUrl: CALLBACK_URL, ...(refD ? {referenceUuid:refD}:{}) });
  const p_2b = await run('2.b – Preauth RECURRING',                'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'RECURRING',                    description:'HOC Cert 2.b', customer:CUST, callbackUrl: CALLBACK_URL, ...(refPA ? {referenceUuid:refPA}:{}) });
  const p_2c = await run('2.c – Preauth CARDONFILE',               'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE',                   description:'HOC Cert 2.c', customer:CUST, callbackUrl: CALLBACK_URL, ...(refPA ? {referenceUuid:refPA}:{}) });
  const p_2d = await run('2.d – Preauth CARDONFILE-MERCHANT-INIT', 'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', description:'HOC Cert 2.d', customer:CUST, callbackUrl: CALLBACK_URL, ...(refPA ? {referenceUuid:refPA}:{}) });

  // ═══ Phase 4: Downstream tests (need HPP completed on source transactions) ═══
  const cap  = p_2e.uuid && p_2e.hppCompleted ? await run('3 – Capture full',     'POST', BASE+'/capture',                  { merchantTransactionId:ts(), referenceUuid:p_2e.uuid, amount:'1.00', currency:'AUD' })                              : FAIL('3 – Capture full',     'Preauth 2.e HPP not completed');
  const capP = p_2f.uuid && p_2f.hppCompleted ? await run('3.a – Capture partial', 'POST', BASE+'/capture',                  { merchantTransactionId:ts(), referenceUuid:p_2f.uuid, amount:'0.50', currency:'AUD' })                              : FAIL('3.a – Capture partial', 'Preauth 2.f HPP not completed');
  const vd   = p_2g.uuid && p_2g.hppCompleted ? await run('4 – Void preauth',     'POST', BASE+'/void',                     { merchantTransactionId:ts(), referenceUuid:p_2g.uuid })                                                             : FAIL('4 – Void preauth',     'Preauth 2.g HPP not completed');
  const dereg= t5.uuid   && t5.hppCompleted   ? await run('5.a – Deregister',     'POST', BASE+'/deregister',               { merchantTransactionId:ts(), referenceUuid:t5.uuid })                                                               : FAIL('5.a – Deregister',     'Register (5) HPP not completed');
  const reful = d_1e.uuid && d_1e.hppCompleted ? await run('6 – Full refund',      'POST', BASE+'/refund',                   { merchantTransactionId:ts(), referenceUuid:d_1e.uuid, amount:'1.00', currency:'AUD', description:'Full refund' })    : FAIL('6 – Full refund',      'Debit 1.e HPP not completed');
  const refPa = d_1f.uuid && d_1f.hppCompleted ? await run('7 – Partial refund',   'POST', BASE+'/refund',                   { merchantTransactionId:ts(), referenceUuid:d_1f.uuid, amount:'0.50', currency:'AUD', description:'Partial refund' }) : FAIL('7 – Partial refund',   'Debit 1.f HPP not completed');
  const rev  = d_1g.uuid && d_1g.hppCompleted ? await run('8 – Reversal',         'POST', BASE+'/reversal',                 { merchantTransactionId:ts(), referenceUuid:d_1g.uuid })                                                             : FAIL('8 – Reversal',         'Debit 1.g HPP not completed');
  const inc  = p_2h.uuid && p_2h.hppCompleted ? await run('9 – Incremental auth', 'POST', BASE+'/incrementalAuthorization', { merchantTransactionId:ts(), referenceUuid:p_2h.uuid, amount:'0.25', currency:'AUD' })                              : FAIL('9 – Incremental auth', 'Preauth 2.h HPP not completed');

  // ═══ Phase 5: Negative tests (decline card — HPP auto-completed) ═══
  const t10a = await runHPP('10.a – Negative debit',    'POST', BASE+'/debit',        { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert 10.a Negative', customer:CUST, ...URLS }, '4111111111111119');
  const t10b = await runHPP('10.b – Negative preauth',  'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert 10.b Negative', customer:CUST, ...URLS }, '4111111111111119');
  const t10c = await runHPP('10.c – Negative register', 'POST', BASE+'/register',     { merchantTransactionId:ts(), customer:CUST, ...URLS }, '4111111111111119');

  // ═══ Assemble results in display order (must match dashboard sections) ═══
  const results = [
    d_1a, d_1b, d_1c, d_1d, d_1e, d_1f, d_1g, d_1h,   // 0-7   Debits
    p_2a, p_2b, p_2c, p_2d, p_2e, p_2f, p_2g, p_2h,   // 8-15  Preauths
    cap, capP, vd,                                       // 16-18 Capture/Void
    t5, dereg,                                           // 19-20 Register/Deregister
    reful, refPa,                                        // 21-22 Refunds
    rev,                                                 // 23    Reversal
    inc,                                                 // 24    Incremental
    t10a, t10b, t10c                                     // 25-27 Negatives
  ];

  // Clean up shared Puppeteer browser
  await closeHPPBrowser();

  const hppAuto   = results.filter(r => r.hppCompleted).length;
  const hppFailed = results.filter(r => r.needsManual).length;
  logger.info('[CERT] run-all done', { total: results.length, hppAuto, hppFailed });
  res.json({ ok: true, results, hppAuto, hppFailed });
});

// ENDPOINT: GET /
// ═════════════════════════════════════════════════════════════════════════════
// Till Developer Certification Test Dashboard — Auto-Run Edition
// Fires all tests automatically on button click. Shows UUID + remark per test.

app.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HOCS · Till Certification</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1b2d;color:#e2e8f0;min-height:100vh;padding:24px}
h1{font-size:22px;font-weight:700;color:#60a5fa;margin-bottom:4px}
.sub{color:#94a3b8;font-size:13px;margin-bottom:16px}
.env-badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:700;margin-left:8px;background:${TILL_BASE_URL.includes('test-gateway') ? '#15803d' : '#b91c1c'};color:#fff}
.cards-tip{color:#fbbf24;font-size:12px;font-weight:600;margin-bottom:20px;padding:10px 14px;background:#1a2a18;border:1px solid #365314;border-radius:8px}
#run-btn{padding:12px 32px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;margin-bottom:20px}
#run-btn:hover{background:#1d4ed8}
#run-btn:disabled{background:#374151;cursor:wait}
#status{font-size:13px;color:#94a3b8;margin-bottom:20px;display:none}
table{width:100%;border-collapse:collapse;font-size:12px}
thead tr{background:#1e2d42}
th{padding:10px 12px;text-align:left;color:#93c5fd;font-weight:700;border-bottom:2px solid #2d3f56;white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #1e2d42;vertical-align:top}
tr:hover td{background:#1a2636}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700}
.ok{background:#166534;color:#86efac}
.err{background:#7f1d1d;color:#fca5a5}
.hpptag{background:#1e3a5f;color:#93c5fd}
.pending{background:#3f2a00;color:#fbbf24}
.uuid-cell{font-family:monospace;font-size:11px;word-break:break-all;max-width:280px}
.remark-cell{font-family:monospace;font-size:11px;word-break:break-all;max-width:320px;color:#86efac}
.copy-btn{margin-left:6px;padding:2px 8px;background:#2d3f56;border:none;color:#93c5fd;border-radius:4px;cursor:pointer;font-size:10px}
.copy-btn:hover{background:#374f6a}
.hpp-link{display:inline-block;margin-top:4px;padding:4px 10px;background:#15803d;color:#fff;border-radius:5px;text-decoration:none;font-size:10px;font-weight:700}
.note{font-size:10px;color:#64748b;margin-top:3px}
#table-wrap{display:none}
.section-sep{background:#1a2d3f}
.section-sep td{padding:6px 12px;color:#60a5fa;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
/* ── Progress bar ──────────────────────────────────────────── */
#progress-wrap{display:none;margin-bottom:20px}
.progress-outer{height:12px;background:#1e2d42;border-radius:6px;overflow:hidden;position:relative}
.progress-inner{height:100%;width:0%;border-radius:6px;background:linear-gradient(90deg,#2563eb 0%,#60a5fa 50%,#2563eb 100%);background-size:200% 100%;animation:shimmer 1.5s ease-in-out infinite;transition:width .6s cubic-bezier(.25,.8,.25,1)}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.progress-info{display:flex;justify-content:space-between;align-items:center;margin-top:6px;font-size:11px;color:#94a3b8}
.progress-info .step{color:#60a5fa;font-weight:600}
.progress-info .elapsed{font-variant-numeric:tabular-nums}
</style>
</head>
<body>
<h1>HOCS Till Certification <span class="env-badge">${TILL_BASE_URL.includes('test-gateway') ? 'SANDBOX' : 'PRODUCTION ⚠️'}</span></h1>
<p class="sub">Gateway: ${TILL_BASE_URL}</p>
<div class="cards-tip">
  Test cards (enter on Till hosted page):<br>
  ✅ Success: <strong>4111 1111 1111 1111</strong> &nbsp;|&nbsp; ✅ 3DS: <strong>4000 0020 0000 0008</strong> &nbsp;|&nbsp; ❌ Decline: <strong>4111 1111 1111 1119</strong><br>
  Exp: any future date &nbsp;|&nbsp; CVV: any 3 digits
</div>
<button id="run-btn" onclick="runAll()">▶ Run All Certification Tests</button>
<div id="progress-wrap">
  <div class="progress-outer"><div class="progress-inner" id="progress-bar"></div></div>
  <div class="progress-info"><span class="step" id="progress-step"></span><span class="elapsed" id="progress-time">0:00</span></div>
</div>
<div id="status"></div>
<div id="table-wrap">
  <p style="font-size:12px;color:#fbbf24;margin-bottom:12px">
    ⚠️ HPP payment pages are auto-completed server-side. If any HPP tests fail, use the manual "Open Payment Page" links as fallback, then click <strong>↻ Re-run</strong>.
  </p>
  <table id="results-table">
    <thead><tr><th>#</th><th>Test</th><th>Status</th><th>UUID / Registration ID</th><th>HPP Link (open &amp; pay)</th><th>Remark (paste into Till form)</th></tr></thead>
    <tbody id="results-body"></tbody>
  </table>
  <button id="rerun-btn" onclick="rerunDependent()" style="margin-top:16px;padding:10px 24px;background:#7c3aed;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer">↻ Re-run After HPP (RECURRING/CARDONFILE + Capture/Void/Deregister/Refund/Reversal)</button>
</div>

<script>
let lastResults = [];
let debitUuid = null, debitUuid2 = null, debitUuid3 = null;
let preauthUuid = null, preauthUuid2 = null, preauthUuid3 = null, preauthUuid4 = null;
let regId5 = null;
let debitInitialUuid = null, preauthInitialUuid = null;

function uid(){ return 'HOC-CERT-'+Date.now()+'-'+Math.floor(Math.random()*9999); }
async function post(url, body){ const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); return r.json(); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

function copyText(txt){
  navigator.clipboard.writeText(txt).catch(()=>{
    const el=document.createElement('textarea');el.value=txt;document.body.appendChild(el);el.select();document.execCommand('copy');document.body.removeChild(el);
  });
}

function statusEl(){ return document.getElementById('status'); }
function setStatus(msg){ const el=statusEl(); el.style.display='block'; el.innerHTML=msg; }

/* ── Progress bar helpers ── */
let progressTimer = null;
function showProgress(stepText, pct){
  const w = document.getElementById('progress-wrap'); w.style.display='block';
  document.getElementById('progress-bar').style.width = Math.min(pct,100)+'%';
  document.getElementById('progress-step').textContent = stepText;
}
function hideProgress(){ document.getElementById('progress-wrap').style.display='none'; clearInterval(progressTimer); progressTimer=null; }
function startTimer(){
  const t0 = Date.now();
  const el = document.getElementById('progress-time');
  el.textContent = '0:00';
  clearInterval(progressTimer);
  progressTimer = setInterval(()=>{
    const s = Math.floor((Date.now()-t0)/1000);
    el.textContent = Math.floor(s/60)+':'+String(s%60).padStart(2,'0');
  }, 500);
}

function renderRow(r, idx){
  const uuid    = r.uuid || '';
  const redir   = r.redirectUrl || '';
  const success = r.success;
  const isHPP   = !!redir;
  const errInfo = r.raw?.errors?.[0]
    ? \`\${r.raw.errors[0].errorCode}: \${r.raw.errors[0].errorMessage||r.raw.errors[0].message||''}\`
    : (r.raw?.errorMessage ? \`\${r.raw.errorCode ? r.raw.errorCode+': ' : ''}\${r.raw.errorMessage}\` : (r.raw?.error || ''));
  const needsHPP = r.label.includes('needs HPP') || r.needsHPP === true;
  
  const rawSummary = JSON.stringify(r.raw || {}).substring(0, 300).replace(/'/g, '&apos;').replace(/"/g, '&quot;');
  let statusBadge;
  if (needsHPP && !success){ statusBadge = '<span class="badge pending">PENDING HPP</span>'; }
  else if (success){ statusBadge = '<span class="badge ok">OK</span>'; }
  else { statusBadge = \`<span class="badge err" title="\${rawSummary}">ERROR ⓘ</span>\`; }

  const uuidHtml = uuid
    ? \`<span>\${uuid}</span><button class="copy-btn" onclick="copyText('\${uuid}')">copy</button>\`
    : (needsHPP && !success) ? '<span style="color:#475569">—</span>'
    : (errInfo ? \`<span style="color:#f87171;font-size:10px">\${errInfo}</span>\` : '<span style="color:#475569">—</span>');

  const hppHtml = redir
    ? \`<a class="hpp-link" href="\${redir}" target="_blank">Open Payment Page →</a><div class="note" style="word-break:break-all;margin-top:2px;font-size:9px;color:#475569">\${redir.substring(0,60)}...</div>\`
    : '<span style="color:#475569">—</span>';

  // Remark: for HPP tests before payment, note UUID + "complete HPP to activate"
  // For tests that succeeded, just use UUID. For dependent (capture/void etc), use uuid from this call.
  let remark;
  if (needsHPP && !success){
    remark = uuid ? \`uuid=\${uuid} | Complete HPP first, then re-run\` : 'Run HPP first';
  } else if (uuid && success) {
    remark = \`uuid=\${uuid} | success=true\`;
  } else if (uuid && !success) {
    remark = \`uuid=\${uuid} | ERROR: \${errInfo || 'see raw'}\`;
  } else if (!success && errInfo){
    remark = \`error: \${errInfo}\`;
  } else {
    remark = 'See raw response';
  }

  const remarkHtml = \`<span class="remark-cell">\${remark}</span><button class="copy-btn" onclick="copyText(\\\`\${remark}\\\`)">copy</button>\`;

  return \`<tr id="row-\${idx}">
    <td>\${idx+1}</td>
    <td>\${r.label}</td>
    <td>\${statusBadge}</td>
    <td class="uuid-cell">\${uuidHtml}</td>
    <td>\${hppHtml}</td>
    <td>\${remarkHtml}</td>
  </tr>\`;
}

function renderSep(text){
  return \`<tr class="section-sep"><td colspan="6">\${text}</td></tr>\`;
}

function renderAll(results){
  const body = document.getElementById('results-body');
  const sections = [
    { label:'Tests 1.a–1.h · Debit', startIdx:0, count:8 },
    { label:'Tests 2.a–2.h · Preauth', startIdx:8, count:8 },
    { label:'Test 3 · Capture / Test 4 · Void', startIdx:16, count:3 },
    { label:'Test 5 · Register / Deregister', startIdx:19, count:2 },
    { label:'Tests 6–7 · Refund', startIdx:21, count:2 },
    { label:'Test 8 · Reversal', startIdx:23, count:1 },
    { label:'Test 9 · Incremental Auth', startIdx:24, count:1 },
    { label:'Test 10 · Negative (Declined)', startIdx:25, count:3 },
  ];

  let html='';
  for(const s of sections){
    html += renderSep(s.label);
    for(let i=s.startIdx; i<s.startIdx+s.count && i<results.length; i++){
      html += renderRow(results[i], i);
    }
  }
  body.innerHTML = html;
  document.getElementById('table-wrap').style.display='block';
}

async function runAll(){
  const btn = document.getElementById('run-btn');
  btn.disabled=true; btn.textContent='Running…';
  setStatus('Fully automated: creating transactions, auto-completing HPP pages, running downstream tests… ~7 minutes.');
  startTimer();
  showProgress('Running all 28 tests (HPP auto-completed)…', 0);
  const estMs = 450000; const t0 = Date.now();
  const pInt = setInterval(()=>{ const pct=Math.min(((Date.now()-t0)/estMs)*95,95); showProgress('Running all 28 tests (HPP auto-completed)…',pct); },400);
  try {
    const resp = await fetch('/api/cert/run-all');
    clearInterval(pInt); showProgress('Processing results…',100);
    const data = await resp.json();
    lastResults = data.results;
    // Extract key UUIDs for manual re-run fallback
    debitUuid          = lastResults.find(r=>r.label.includes('1.e'))?.uuid || null;
    debitUuid2         = lastResults.find(r=>r.label.includes('1.f'))?.uuid || null;
    debitUuid3         = lastResults.find(r=>r.label.includes('1.g'))?.uuid || null;
    preauthUuid        = lastResults.find(r=>r.label.includes('2.e'))?.uuid || null;
    preauthUuid2       = lastResults.find(r=>r.label.includes('2.f'))?.uuid || null;
    preauthUuid3       = lastResults.find(r=>r.label.includes('2.g'))?.uuid || null;
    preauthUuid4       = lastResults.find(r=>r.label.includes('2.h'))?.uuid || null;
    regId5             = lastResults.find(r=>r.label.includes('5 –'))?.uuid || null;
    debitInitialUuid   = lastResults.find(r=>r.label.includes('1.a'))?.uuid || null;
    preauthInitialUuid = lastResults.find(r=>r.label.includes('2.a'))?.uuid || null;
    renderAll(lastResults);
    const ok = lastResults.filter(r=>r.success).length;
    const hppAuto = data.hppAuto || 0;
    const hppFailed = data.hppFailed || 0;
    let msg = \`Done. \${ok}/\${lastResults.length} tests passed. HPP auto-completed: \${hppAuto}.\`;
    if (hppFailed > 0) msg += \` ⚠️ \${hppFailed} HPP failed — auto-retrying dependent tests…\`;
    setStatus(msg);
    hideProgress();
    btn.disabled=false; btn.textContent='▶ Run All Certification Tests';
    // Auto-trigger re-run if any HPP failed so downstream tests retry
    if (hppFailed > 0) {
      await sleep(2000);
      await rerunDependent();
    }
  } catch(e){
    setStatus('Error: '+e.message);
    hideProgress();
    btn.disabled=false; btn.textContent='▶ Run All Certification Tests';
  }
}

async function rerunDependent(){
  if(!debitUuid && !preauthUuid && !debitInitialUuid && !preauthInitialUuid){ alert('Run all tests first.'); return; }
  const t = ()=>'HOC-CERT-'+Date.now()+'-'+Math.floor(Math.random()*9999);
  const btn = document.getElementById('rerun-btn');
  btn.disabled = true;
  setStatus('Re-running RECURRING/CARDONFILE + Capture / Void / Refund / Reversal / Incremental… ~2 minutes.');
  startTimer();
  const totalSteps = 14; let curStep = 0;
  function stepProgress(label){ curStep++; showProgress(curStep+'/'+totalSteps+' · '+label, (curStep/totalSteps)*100); }

  // ── RECURRING / CARDONFILE (needs 1.a / 2.a HPP completed first)
  stepProgress('Debit RECURRING (1.b)');
  const rec1b = debitInitialUuid   ? await post('/api/till/debit',   {transactionIndicator:'RECURRING',                    referenceUuid:debitInitialUuid,   amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 1.b'}) : {success:false,raw:{error:'No initial debit uuid — complete HPP on row 1 (1.a) first'}};
  await sleep(10000);
  stepProgress('Debit CARDONFILE (1.c)');
  const cof1c = debitInitialUuid   ? await post('/api/till/debit',   {transactionIndicator:'CARDONFILE',                   referenceUuid:debitInitialUuid,   amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 1.c'}) : {success:false,raw:{error:'No initial debit uuid — complete HPP on row 1 (1.a) first'}};
  await sleep(10000);
  stepProgress('Debit CARDONFILE-MI (1.d)');
  const cof1d = debitInitialUuid   ? await post('/api/till/debit',   {transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', referenceUuid:debitInitialUuid,   amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 1.d'}) : {success:false,raw:{error:'No initial debit uuid — complete HPP on row 1 (1.a) first'}};
  await sleep(10000);
  stepProgress('Preauth RECURRING (2.b)');
  const rec2b = preauthInitialUuid ? await post('/api/till/preauth', {transactionIndicator:'RECURRING',                    referenceUuid:preauthInitialUuid, amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 2.b'}) : {success:false,raw:{error:'No initial preauth uuid — complete HPP on row 9 (2.a) first'}};
  await sleep(10000);
  stepProgress('Preauth CARDONFILE (2.c)');
  const cof2c = preauthInitialUuid ? await post('/api/till/preauth', {transactionIndicator:'CARDONFILE',                   referenceUuid:preauthInitialUuid, amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 2.c'}) : {success:false,raw:{error:'No initial preauth uuid — complete HPP on row 9 (2.a) first'}};
  await sleep(10000);
  stepProgress('Preauth CARDONFILE-MI (2.d)');
  const cof2d = preauthInitialUuid ? await post('/api/till/preauth', {transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', referenceUuid:preauthInitialUuid, amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 2.d'}) : {success:false,raw:{error:'No initial preauth uuid — complete HPP on row 9 (2.a) first'}};
  await sleep(10000);

  // ── Capture / Void / Refund / Reversal / Incremental (needs 1.e / 2.e HPP completed first)
  stepProgress('Capture full (3)');
  const cap  = preauthUuid ? await post('/api/till/capture/'+preauthUuid,  {amount:'1.00',currency:'AUD',merchantTransactionId:t()}) : {success:false,raw:{error:'No preauth uuid'}};
  await sleep(10000);
  stepProgress('Capture partial (3a)');
  const capP = (preauthUuid2||preauthUuid) ? await post('/api/till/capture/'+(preauthUuid2||preauthUuid),  {amount:'0.50',currency:'AUD',merchantTransactionId:t()}) : {success:false,raw:{error:'No preauth uuid (complete HPP on 2.f)'}};
  await sleep(10000);
  stepProgress('Void preauth (4)');
  const vd   = (preauthUuid3||preauthUuid) ? await post('/api/till/void/'+(preauthUuid3||preauthUuid),     {}) : {success:false,raw:{error:'No preauth uuid (complete HPP on 2.g)'}};
  await sleep(10000);
  stepProgress('Deregister (5.a)');
  const dereg = regId5 ? await post('/api/till/deregister', {referenceUuid:regId5, merchantTransactionId:t()}) : {success:false,raw:{error:'No register uuid — complete HPP on Register (5) first'}};
  await sleep(10000);
  stepProgress('Full refund (6)');
  const ref  = debitUuid   ? await post('/api/till/refund/'+debitUuid,     {amount:'1.00',currency:'AUD',reason:'Customer refund request'}) : {success:false,raw:{error:'No debit uuid'}};
  await sleep(10000);
  stepProgress('Partial refund (7)');
  const refP = (debitUuid2||debitUuid)   ? await post('/api/till/refund/'+(debitUuid2||debitUuid),     {amount:'0.50',currency:'AUD',reason:'Partial refund'}) : {success:false,raw:{error:'No debit uuid (complete HPP on 1.f)'}};
  await sleep(10000);
  stepProgress('Reversal (8)');
  const rev  = (debitUuid3||debitUuid)   ? await post('/api/till/reversal/'+(debitUuid3||debitUuid),   {}) : {success:false,raw:{error:'No debit uuid (complete HPP on 1.g)'}};
  await sleep(10000);
  stepProgress('Incremental auth (9)');
  const inc  = (preauthUuid4||preauthUuid) ? await post('/api/till/incremental/'+(preauthUuid4||preauthUuid), {amount:'0.25',currency:'AUD'}) : {success:false,raw:{error:'No preauth uuid (complete HPP on 2.h)'}};  

  const depResults = [
    {label:'1.b – Debit RECURRING',                  ...rec1b, uuid:rec1b.uuid||null},
    {label:'1.c – Debit CARDONFILE',                 ...cof1c, uuid:cof1c.uuid||null},
    {label:'1.d – Debit CARDONFILE-MERCHANT-INIT',   ...cof1d, uuid:cof1d.uuid||null},
    {label:'2.b – Preauth RECURRING',                ...rec2b, uuid:rec2b.uuid||null},
    {label:'2.c – Preauth CARDONFILE',               ...cof2c, uuid:cof2c.uuid||null},
    {label:'2.d – Preauth CARDONFILE-MERCHANT-INIT', ...cof2d, uuid:cof2d.uuid||null},
    {label:'3 – Capture full',     ...cap,  uuid:cap.uuid||null},
    {label:'3.a – Capture partial',...capP, uuid:capP.uuid||null},
    {label:'4 – Void preauth',     ...vd,   uuid:vd.uuid||null},
    {label:'5.a – Deregister (needs HPP done)', ...dereg, uuid:dereg.uuid||null},
    {label:'6 – Full refund',      ...ref,  uuid:ref.uuid||null},
    {label:'7 – Partial refund',   ...refP, uuid:refP.uuid||null},
    {label:'8 – Reversal',         ...rev,  uuid:rev.uuid||null},
    {label:'9 – Incremental auth', ...inc,  uuid:inc.uuid||null},
  ];

  // Patch lastResults at their positions and re-render
  const positions = {
    '1.b – Debit RECURRING': 1, '1.c – Debit CARDONFILE': 2, '1.d – Debit CARDONFILE-MERCHANT-INIT': 3,
    '2.b – Preauth RECURRING': 9, '2.c – Preauth CARDONFILE': 10, '2.d – Preauth CARDONFILE-MERCHANT-INIT': 11,
    '3 – Capture full': 16, '3.a – Capture partial': 17, '4 – Void preauth': 18,
    '5.a – Deregister': 20,
    '6 – Full refund': 21, '7 – Partial refund': 22, '8 – Reversal': 23, '9 – Incremental auth': 24
  };
  for(const dr of depResults){
    for(const [key, idx] of Object.entries(positions)){
      if(dr.label.startsWith(key.split(' –')[0]+' –') || dr.label===key){ lastResults[idx]=dr; break; }
    }
  }
  renderAll(lastResults);
  hideProgress();
  btn.disabled = false;
  const reOk = depResults.filter(r=>r.success).length;
  setStatus(\`Re-run complete. \${reOk}/\${depResults.length} downstream tests passed.\`);
}

// Auto-start all tests when page loads — fully hands-off
window.addEventListener('DOMContentLoaded', () => { runAll(); });
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
          descriptor, registrationId, referenceUuid, email, threeDSMode } = body;

  // Server-to-server calls (RECURRING/CARDONFILE with referenceUuid) must NOT include
  // HPP redirect URLs — Till rejects them with error 1002 (invalid properties).
  const isServerToServer = !!referenceUuid;

  const payload = {
    merchantTransactionId: merchantTransactionId || `HOC-TEST-${Date.now()}`,
    amount,
    currency: currency || 'AUD',
    ...(isServerToServer ? {} : { successUrl: CERT_SUCCESS_URL, cancelUrl: CERT_CANCEL_URL, errorUrl: CERT_ERROR_URL }),
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

  // Include referenceUuid for RECURRING / CARDONFILE server-to-server calls
  if (referenceUuid) {
    payload.referenceUuid = referenceUuid;
  }

  // descriptor is already mapped to payload.description above — do not also send as 'descriptor'

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
    const { referenceUuid } = req.body;
    if (!referenceUuid) return res.status(400).json({ error: 'referenceUuid required' });
    const payload = {
      merchantTransactionId: `HOC-DEREG-${Date.now()}`,
      referenceUuid
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/deregister`, payload);
    logger.info('[CERT] Deregister', { referenceUuid, status: result.status });
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
