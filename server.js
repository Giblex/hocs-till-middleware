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
const { Pool }   = require('pg');

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
  SHOPIFY_ACCESS_TOKEN,            // Admin API access token (shpat_...) from App → API credentials
  SHOPIFY_CLIENT_ID,               // Client ID from Dev Dashboard → Settings (used for webhook verification)
  SHOPIFY_CLIENT_SECRET,           // Client Secret from Dev Dashboard → Settings (used for webhook verification)
  SHOPIFY_WEBHOOK_SECRET,          // HMAC secret for verifying Shopify webhooks
  SHOPIFY_STORE_WEBHOOK_SECRET,    // Optional: store-level webhook signing key (Admin → Settings → Notifications)

  // URLs
  TILL_BASE_URL         = 'https://test-gateway.tillpayments.com', // Sandbox (default safe)
  // TILL_BASE_URL      = 'https://gateway.tillpayments.com',      // Production — set via env
  SUCCESS_URL           = 'https://highonchapel.com/pages/payment-success',
  CANCEL_URL            = 'https://highonchapel.com/pages/payment-cancelled',
  ERROR_URL             = 'https://highonchapel.com/pages/payment-error',
  CALLBACK_URL,                    // Must be this server's public URL + /api/till-callback
  DATABASE_URL,

  // Store URL
  STORE_URL        = 'https://highonchapel.com',

  // Admin dashboard — set a strong secret and visit /admin?secret=<value>
  DASHBOARD_SECRET = '',
} = process.env;

// ─── Validate required env vars ─────────────────────────────────────────────

const REQUIRED_ENV = [
  'TILL_API_KEY', 'TILL_SHARED_SECRET', 'TILL_API_USER', 'TILL_API_PASS',
  'SHOPIFY_STORE_DOMAIN', 'SHOPIFY_ACCESS_TOKEN', 'SHOPIFY_CLIENT_SECRET',
  'SHOPIFY_WEBHOOK_SECRET', 'CALLBACK_URL', 'DATABASE_URL'
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

async function completeHPP(redirectUrl, cardNumber = '4111111111111111', expectDecline = false) {
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
      return { completed: /cert-paid/.test(page.url()) || (expectDecline && /cert-error/.test(page.url())), url: page.url() };

    // Give JS / Ixopay vault iframes time to initialise
    await _delay(2000);

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

    // ── Wait for navigation / redirect (shorter timeout — redirects are fast) ──
    await page.waitForNavigation({ timeout: 15000, waitUntil: 'networkidle2' }).catch(() => {});

    // ── Already at terminal URL? ──
    if (/cert-paid|cert-error|cert-cancelled/.test(page.url())) {
      const finalUrl = page.url();
      const completed = /cert-paid/.test(finalUrl) || (expectDecline && /cert-error/.test(finalUrl));
      logger.info('[HPP] done', { url: finalUrl, completed, expectDecline });
      return { completed, url: finalUrl };
    }

    // ── Detect inline error on HPP (e.g. declined card — no redirect) ──
    const inlineError = await page.evaluate(() => {
      const text = (document.body?.innerText || '').toLowerCase();
      return /declined|do not hon|invalid card|transaction.{0,10}(failed|error)|not sufficient|card.{0,10}refused|error.{0,10}occurred/i.test(text)
        ? text.substring(0, 300) : null;
    }).catch(() => null);

    if (inlineError) {
      logger.info('[HPP] inline error detected (decline card)', { preview: inlineError.substring(0, 100), expectDecline });
      return { completed: expectDecline, url: page.url(), error: expectDecline ? null : 'HPP inline error (decline)' };
    }

    // ── Handle 3DS challenge or intermediate pages ──
    for (let i = 0; i < 6 && !/cert-paid|cert-error|cert-cancelled/.test(page.url()); i++) {
      const frameUrls = page.frames().map(f => { try { return f.url(); } catch { return '(detached)'; } });
      logger.info('[HPP] intermediate page', { url: page.url(), attempt: i, frames: frameUrls });
      await _delay(1500);

      // Check child frames for 3DS challenge forms — skip main frame (has payment
      // form Submit button that would re-trigger) and skip vault iframes.
      let clickedChallenge = false;
      const mainUrl = page.url();
      for (const frame of page.frames()) {
        try {
        const fUrl = frame.url();
        // Skip main frame if still on the payment page (has its own Submit btn)
        if (frame === page.mainFrame() && /tillpayments\.com\/payment\//i.test(fUrl)) continue;
        // Skip vault iframes — they hold PAN / CVV inputs, not 3DS
        if (/\/iframes\/(pan|cvv)\.html/i.test(fUrl)) continue;
        // Skip about:blank / empty frames
        if (!fUrl || fUrl === 'about:blank') continue;

        clickedChallenge = await frame.evaluate(() => {
          const btns = [...document.querySelectorAll('button, input[type="submit"], a.button')];
          const btn = btns.find(b => {
            const s = window.getComputedStyle(b);
            return s.display !== 'none' && s.visibility !== 'hidden' && b.offsetWidth > 0;
          });
          if (btn) { btn.click(); return true; }
          const form = document.querySelector('form');
          if (form) { form.submit(); return true; }
          return false;
        }).catch(() => false);
        if (clickedChallenge) {
          logger.info('[HPP] clicked 3DS challenge button', { frameUrl: fUrl });
          break;
        }
        } catch (frameErr) {
          logger.warn('[HPP] frame detached during iteration', { err: frameErr.message });
          continue;
        }
      }

      // If no child-frame button found, check main frame ONLY if URL changed from payment page
      if (!clickedChallenge && !/tillpayments\.com\/payment\//i.test(page.url())) {
        clickedChallenge = await page.evaluate(() => {
          const btns = [...document.querySelectorAll('button, input[type="submit"]')];
          const btn = btns.find(b => {
            const s = window.getComputedStyle(b);
            return s.display !== 'none' && s.visibility !== 'hidden' && b.offsetWidth > 0;
          });
          if (btn) { btn.click(); return true; }
          const form = document.querySelector('form');
          if (form) { form.submit(); return true; }
          return false;
        }).catch(() => false);
        if (clickedChallenge) logger.info('[HPP] clicked 3DS button in main frame (navigated)', { url: page.url() });
      }

      if (clickedChallenge) {
        await page.waitForNavigation({ timeout: 20000, waitUntil: 'networkidle2' }).catch(() => {});
      } else {
        // No button found — wait for auto-redirect
        logger.info('[HPP] no 3DS button found, waiting for redirect…', { url: page.url() });
        await page.waitForFunction(
          'location.href.includes("cert-paid") || location.href.includes("cert-error") || location.href.includes("cert-cancelled")',
          { timeout: 10000 }
        ).catch(() => {});
      }

      // Re-check for inline error after each attempt (payment might process mid-loop)
      const loopError = await page.evaluate(() => {
        const text = (document.body?.innerText || '').toLowerCase();
        return /declined|do not hon|invalid card|transaction.{0,10}(failed|error)|not sufficient|card.{0,10}refused/i.test(text);
      }).catch(() => false);
      if (loopError) {
        logger.info('[HPP] inline error detected in loop', { attempt: i, expectDecline });
        return { completed: expectDecline, url: page.url(), error: expectDecline ? null : 'HPP inline error (decline)' };
      }
    }

    const finalUrl = page.url();
    const completed = /cert-paid/.test(finalUrl) || (expectDecline && /cert-error/.test(finalUrl));
    logger.info('[HPP] done', { url: finalUrl, completed, expectDecline });
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

async function getShopifyAccessToken() {
  // Custom apps use a static Admin API access token (shpat_...) — no OAuth exchange needed.
  // Shopify does not support the client_credentials grant type.
  if (!SHOPIFY_ACCESS_TOKEN) {
    throw new Error('SHOPIFY_ACCESS_TOKEN env var is not set. Get it from Shopify Admin → Apps → Develop apps → [App] → API credentials.');
  }
  return SHOPIFY_ACCESS_TOKEN;
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
    if (res.status === 401) {
      logger.warn('Shopify Admin API returned 401 — check that SHOPIFY_ACCESS_TOKEN is valid and the app has write_orders scope');
    }
    logger.error('Shopify Admin API error', { status: res.status, path, body: JSON.stringify(json).substring(0, 500) });
  }
  return { status: res.status, body: json };
}

// ─── Persistent Idempotency Store (Rec #4 + #8) ────────────────────────────

// ─── Persistent Idempotency Store (Rec #4 + #8) ────────────────────────────
// PostgreSQL-backed — durable across Railway deploys and restarts.

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !/localhost|127\.0\.0\.1/i.test(DATABASE_URL)
    ? { rejectUnauthorized: false }
    : false
});

function mapTransactionRow(row) {
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

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      txn_id           TEXT PRIMARY KEY,
      status           TEXT NOT NULL DEFAULT 'pending',
      shopify_order_id TEXT,
      order_number     TEXT,
      amount           TEXT,
      currency         TEXT,
      till_uuid        TEXT,
      purchase_id      TEXT,
      redirect_url     TEXT,
      till_error       TEXT,
      customer_email   TEXT,
      created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS webhooks (
      order_id   TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_order_number ON transactions(order_number);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_shopify_order_id ON transactions(shopify_order_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_till_uuid ON transactions(till_uuid);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_purchase_id ON transactions(purchase_id);`);
}

async function getTransaction(txnId) {
  const { rows } = await pool.query('SELECT * FROM transactions WHERE txn_id = $1 LIMIT 1', [String(txnId)]);
  return mapTransactionRow(rows[0]);
}

async function getTransactionByOrderNumber(orderNumber) {
  const { rows } = await pool.query('SELECT * FROM transactions WHERE order_number = $1 LIMIT 1', [String(orderNumber)]);
  return mapTransactionRow(rows[0]);
}

async function getTransactionByShopifyOrderId(shopifyOrderId) {
  const { rows } = await pool.query('SELECT * FROM transactions WHERE shopify_order_id = $1 LIMIT 1', [String(shopifyOrderId)]);
  return mapTransactionRow(rows[0]);
}

async function saveTransaction(data) {
  await pool.query(`
    INSERT INTO transactions (
      txn_id, status, shopify_order_id, order_number, amount, currency,
      till_uuid, purchase_id, redirect_url, till_error, customer_email, updated_at
    )
    VALUES (
      $1, $2, $3, $4, $5, $6,
      $7, $8, $9, $10, $11, NOW()
    )
    ON CONFLICT (txn_id) DO UPDATE SET
      status = EXCLUDED.status,
      shopify_order_id = COALESCE(EXCLUDED.shopify_order_id, transactions.shopify_order_id),
      order_number = COALESCE(EXCLUDED.order_number, transactions.order_number),
      amount = COALESCE(EXCLUDED.amount, transactions.amount),
      currency = COALESCE(EXCLUDED.currency, transactions.currency),
      till_uuid = COALESCE(EXCLUDED.till_uuid, transactions.till_uuid),
      purchase_id = COALESCE(EXCLUDED.purchase_id, transactions.purchase_id),
      redirect_url = COALESCE(EXCLUDED.redirect_url, transactions.redirect_url),
      till_error = COALESCE(EXCLUDED.till_error, transactions.till_error),
      customer_email = COALESCE(EXCLUDED.customer_email, transactions.customer_email),
      updated_at = NOW()
  `, [
    data.txnId || null,
    data.status || 'pending',
    data.shopifyOrderId || null,
    data.orderNumber || null,
    data.amount || null,
    data.currency || null,
    data.tillUuid || null,
    data.purchaseId || null,
    data.redirectUrl || null,
    data.tillError || null,
    data.customerEmail || null
  ]);
}

async function getTransactionByTillUuid(tillUuid) {
  const { rows } = await pool.query('SELECT * FROM transactions WHERE till_uuid = $1 LIMIT 1', [String(tillUuid)]);
  return mapTransactionRow(rows[0]);
}

async function getTransactionByPurchaseId(purchaseId) {
  const { rows } = await pool.query('SELECT * FROM transactions WHERE purchase_id = $1 LIMIT 1', [String(purchaseId)]);
  return mapTransactionRow(rows[0]);
}

async function getAllTransactions({ limit = 200, offset = 0, status = null, search = null, excludeStatuses = null } = {}) {
  let where = 'WHERE 1=1';
  const params = [];
  let idx = 1;

  if (status) {
    where += ` AND status = $${idx++}`;
    params.push(status);
  } else if (Array.isArray(excludeStatuses) && excludeStatuses.length) {
    where += ` AND status NOT IN (${excludeStatuses.map(() => `$${idx++}`).join(',')})`;
    params.push(...excludeStatuses);
  }
  if (search) {
    const like = `%${search}%`;
    where += ` AND (txn_id ILIKE $${idx} OR order_number ILIKE $${idx} OR customer_email ILIKE $${idx} OR till_uuid ILIKE $${idx})`;
    params.push(like);
    idx++;
  }

  const dataParams = [...params, limit, offset];
  const { rows } = await pool.query(
    `SELECT * FROM transactions ${where} ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
    dataParams
  );
  const { rows: countRows } = await pool.query(
    `SELECT COUNT(*) AS total FROM transactions ${where}`,
    params
  );
  return { rows: rows.map(mapTransactionRow), total: parseInt(countRows[0].total, 10) };
}

async function resolveTransactionFromCallback(cb) {
  if (cb.merchantTransactionId) {
    const txn = await getTransaction(cb.merchantTransactionId);
    if (txn) return { txn, matchedBy: 'merchantTransactionId' };
  }

  const tillUuid = cb.uuid || cb.referenceUuid;
  if (tillUuid) {
    const txn = await getTransactionByTillUuid(tillUuid);
    if (txn) return { txn, matchedBy: 'tillUuid' };
  }

  if (cb.purchaseId) {
    const txn = await getTransactionByPurchaseId(cb.purchaseId);
    if (txn) return { txn, matchedBy: 'purchaseId' };
  }

  return { txn: null, matchedBy: null };
}

async function hasWebhook(orderId) {
  const { rowCount } = await pool.query('SELECT 1 FROM webhooks WHERE order_id = $1 LIMIT 1', [String(orderId)]);
  return rowCount > 0;
}

async function markWebhook(orderId) {
  await pool.query(
    'INSERT INTO webhooks (order_id, created_at) VALUES ($1, NOW()) ON CONFLICT (order_id) DO NOTHING',
    [String(orderId)]
  );
}

function normalizeTillValue(value) {
  return typeof value === 'string' ? value.trim().toUpperCase() : '';
}

function getTillErrorDetails(payload) {
  const firstError = payload?.errors?.[0] || {};
  return {
    errorCode: firstError.errorCode ?? payload?.errorCode ?? null,
    errorMessage: firstError.errorMessage || firstError.message || payload?.errorMessage || payload?.message || 'unknown',
    adapterCode: firstError.adapterCode || payload?.adapterCode || '',
    adapterMessage: firstError.adapterMessage || payload?.adapterMessage || ''
  };
}

// Graceful shutdown — close Postgres pool
process.on('SIGINT', async () => { await pool.end().catch(() => {}); process.exit(0); });
process.on('SIGTERM', async () => { await pool.end().catch(() => {}); process.exit(0); });

// ─── Express App ────────────────────────────────────────────────────────────

const app = express();

// ── Raw body capture for signature verification ─────────────────────────────
// We need the raw body for both Shopify HMAC and Till X-Signature verification,
// so we capture it before JSON parsing.

app.use(express.static(path.join(__dirname, 'public')));

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

// ── CORS for Payment Success page ───────────────────────────────────────────
// /pages/payment-success calls /api/payment-confirm from the browser after
// Till redirects the customer back, to confirm and trigger backend payment.
app.use('/api/payment-confirm', (req, res, next) => {
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

// ── Health check ────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.4.6',
    build: 'add-1.0-2.0-plain-tests',
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

app.get('/api/payment-redirect/:orderNumber', async (req, res) => {
  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const email       = (req.query.email || '').trim().toLowerCase();

  if (!email) {
    return res.json({ status: 'not_found' });
  }

  // Look up by txn_id (HOC-<orderNumber>) first, fall back to order_number column
  const txnId = `HOC-${orderNumber}`;
  let txn = await getTransaction(txnId);
  if (!txn) {
    txn = await getTransactionByOrderNumber(orderNumber);
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
//   ?email=customer@example.com   (optional — when present, must match order email)

app.get('/api/payment-redirect-by-shopify-id/:shopifyOrderId', async (req, res) => {
  const shopifyOrderId = req.params.shopifyOrderId.trim();
  const email = (req.query.email || '').trim().toLowerCase();

  const txn = await getTransactionByShopifyOrderId(shopifyOrderId);

  logger.info('Payment redirect by Shopify ID lookup', { shopifyOrderId, hasEmail: !!email, found: !!txn });

  if (!txn) {
    return res.json({ status: 'pending' });
  }

  // Email verification
  if (email && txn.customerEmail && email !== txn.customerEmail.trim().toLowerCase()) {
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
// ENDPOINT: GET /api/payment-confirm
// ═════════════════════════════════════════════════════════════════════════════
// Called by /pages/payment-success immediately after Till redirects the
// customer back. Till appends merchantTransactionId (= our txnId) as a query
// param. This endpoint:
//   1. Validates the txnId exists in our DB.
//   2. Fast-path: if already marked paid (Till callback already fired) → return.
//   3. If not yet paid and we have a Till UUID, queries Till's status API
//      server-side. If Till confirms success, calls markShopifyOrderPaid()
//      and updates the DB — handles the case where the async callback is late.
//   4. Returns { status, orderNumber } — no API key, rate-limited by IP.
//
// Query params:
//   ?txnId=HOC-1234   (the merchantTransactionId Till appended to SUCCESS_URL)
//
// Responses:
//   200 { status: 'paid',      orderNumber: '1234' }
//   200 { status: 'pending' }
//   200 { status: 'failed',    error: '...' }
//   200 { status: 'not_found' }
app.get('/api/payment-confirm', paymentLimiter, async (req, res) => {
  const txnId = (req.query.txnId || '').trim();

  // Validate format — must be HOC- followed by word chars / hyphens
  if (!txnId || !/^HOC-[\w-]+$/.test(txnId)) {
    return res.json({ status: 'not_found' });
  }

  const txn = await getTransaction(txnId).catch(() => null);
  if (!txn) {
    return res.json({ status: 'not_found' });
  }

  // Fast-path: already confirmed paid (Till callback fired before page loaded)
  if (txn.status === 'paid') {
    return res.json({ status: 'paid', orderNumber: txn.orderNumber });
  }

  // If we have a Till UUID, query Till server-side for the real status.
  // This handles the case where the async callback has not yet arrived.
  if (txn.tillUuid) {
    try {
      const tillRes = await callTillAPI(
        'GET',
        `/api/v3/status/${TILL_API_KEY}/${txn.tillUuid}`
      );
      const tillStatus = tillRes.body;

      logger.info('payment-confirm: Till status check', {
        txnId: txn.txnId,
        result: tillStatus?.result,
        status: tillStatus?.status
      });

      if (tillStatus && (tillStatus.result === 'OK' || tillStatus.status === 'SUCCESS')) {
        const markResult = await markShopifyOrderPaid(
          txn.shopifyOrderId, txn.tillUuid, txn.txnId, txn.amount
        );

        if (markResult.success) {
          await saveTransaction({ txnId: txn.txnId, status: 'paid', tillUuid: txn.tillUuid });
          logger.info('payment-confirm: order marked paid via proactive status check', { txnId: txn.txnId });
          return res.json({ status: 'paid', orderNumber: txn.orderNumber });
        }

        logger.error('payment-confirm: markShopifyOrderPaid failed', {
          txnId: txn.txnId,
          error: markResult.error
        });
      }
    } catch (err) {
      logger.error('payment-confirm: Till status check threw', { txnId: txn.txnId, error: err.message });
    }
  }

  switch (txn.status) {
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

      logger.info('HMAC debug', {
        requestId,
        rawBodyLen: req.rawBody?.length ?? 'undefined',
        receivedHmac: hmacHeader?.substring(0, 10),
        computedHmac: computedHmac?.substring(0, 10),
        secretPrefix: secret?.substring(0, 8),
        contentType: req.get('content-type'),
      });

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
    if (await hasWebhook(orderId)) {
      logger.info('Duplicate webhook — skipping', { requestId, orderId });
      return res.status(200).json({ status: 'already_processed' });
    }
    await markWebhook(orderId);

    if (await getTransaction(txnId)) {
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
    await saveTransaction({
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

      await saveTransaction({
        txnId,
        status: 'initiated',
        tillUuid,
        purchaseId,
        redirectUrl
      });

      logger.info('Till debit initiated', { requestId, txnId, tillUuid });

      return res.status(200).json({
        status: 'initiated',
        txnId,
        tillUuid,
        redirectUrl
      });
    }

    // Till returned an error
    const tillError = getTillErrorDetails(tillRes.body);
    const isDuplicateTxn = String(tillError.errorCode) === '3004';

    await saveTransaction({
      txnId,
      status: isDuplicateTxn ? 'pending' : 'failed',
      tillError: isDuplicateTxn
        ? 'duplicate_transaction_in_progress'
        : tillRes.rawBody?.substring(0, 500)
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
      return res.status(200).json({
        status: 'duplicate_in_progress',
        txnId,
        message: 'Till already has a payment session for this order'
      });
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
    const txnId      = cb.merchantTransactionId;
    const tillUuid   = cb.uuid || cb.referenceUuid;
    const result     = cb.result;       // e.g. "OK", "ERROR"
    const cbAmount   = cb.amount;       // e.g. "42.50"
    const cbCurrency = cb.currency;     // e.g. "AUD"
    const returnType = cb.returnType;   // e.g. "FINISHED", "REDIRECT", "ERROR"
    const cbStatus   = cb.status || cb.transactionStatus || '';
    const normalizedResult = normalizeTillValue(result);
    const normalizedReturnType = normalizeTillValue(returnType);
    const normalizedStatus = normalizeTillValue(cbStatus);
    const hasCallbackErrors = Array.isArray(cb.errors) && cb.errors.length > 0;

    // Log ALL identifiers from the callback for debugging correlation issues.
    // This is critical — previously "Callback for unknown transaction" gave no
    // visibility into what Till actually sent back.
    logger.info('Callback identifiers (full)', {
      requestId,
      merchantTransactionId: cb.merchantTransactionId || '(missing)',
      uuid: cb.uuid || '(missing)',
      referenceUuid: cb.referenceUuid || '(missing)',
      purchaseId: cb.purchaseId || '(missing)',
      transactionType: cb.transactionType || '(missing)',
      result,
      returnType,
      status: cbStatus || '(missing)',
      cbAmount,
      cbCurrency
    });

    // ── 3. Cascading transaction lookup (Rec #6) ─────────────────────────
    // Fix for "Callback for unknown transaction": if merchantTransactionId
    // is missing or doesn't match, fall back to Till's uuid or purchaseId.
    const { txn: original, matchedBy } = await resolveTransactionFromCallback(cb);
    if (!original) {
      logger.warn('Callback for unknown transaction — no match on any identifier', {
        requestId,
        merchantTransactionId: cb.merchantTransactionId || '(missing)',
        uuid: cb.uuid || '(missing)',
        referenceUuid: cb.referenceUuid || '(missing)',
        purchaseId: cb.purchaseId || '(missing)'
      });
      return res.status(200).send('OK');
    }

    if (matchedBy !== 'merchantTransactionId') {
      logger.warn('Callback matched by fallback identifier — merchantTransactionId may have drifted', {
        requestId,
        matchedBy,
        callbackMerchantTxnId: cb.merchantTransactionId || '(missing)',
        storedTxnId: original.txnId
      });
    }

    // Prevent duplicate processing (Rec #8)
    if (original.status === 'paid') {
      logger.info('Callback for already-paid transaction — skipping', { requestId, txnId: original.txnId });
      return res.status(200).send('OK');
    }

    // ── 4. Validate amount and currency (Rec #6) ─────────────────────────
    if (cbAmount && original.amount) {
      const callbackCents  = Math.round(parseFloat(cbAmount) * 100);
      const originalCents  = Math.round(parseFloat(original.amount) * 100);

      if (callbackCents !== originalCents) {
        logger.alert('AMOUNT MISMATCH — callback amount differs from order!', {
          requestId, txnId: original.txnId,
          expected: original.amount,
          received: cbAmount
        });
        // Do NOT mark as paid — this is suspicious
        await saveTransaction({ txnId: original.txnId, status: 'amount_mismatch' });
        return res.status(200).send('OK');
      }
    }

    if (cbCurrency && original.currency && cbCurrency !== original.currency) {
      logger.alert('CURRENCY MISMATCH on callback', {
        requestId, txnId: original.txnId,
        expected: original.currency,
        received: cbCurrency
      });
      await saveTransaction({ txnId: original.txnId, status: 'currency_mismatch' });
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
    if (normalizedReturnType === 'REDIRECT' || normalizedStatus === 'REDIRECT') {
      logger.info('Till REDIRECT callback received — hosted payment page ready, awaiting customer payment', {
        requestId, txnId: original.txnId, tillUuid
      });
      // No action needed — redirectUrl already stored; customer will complete payment on Till's page.
      return res.status(200).send('OK');
    }

    const isExplicitSuccess =
      normalizedResult === 'OK' &&
      (normalizedReturnType === 'FINISHED' || normalizedStatus === 'SUCCESS');

    const isImplicitSuccess =
      normalizedResult === 'OK' &&
      !normalizedReturnType &&
      !normalizedStatus &&
      !hasCallbackErrors;

    if (isImplicitSuccess) {
      logger.warn('Till callback missing returnType/status — treating signed result=OK callback as successful payment', {
        requestId,
        txnId: original.txnId,
        tillUuid,
        matchedBy
      });
    }

    if (isExplicitSuccess || isImplicitSuccess) {
      // Payment succeeded — mark Shopify order as paid
      logger.info('Payment successful — marking Shopify order paid', {
        requestId, txnId: original.txnId, matchedBy
      });

      const markResult = await markShopifyOrderPaid(original.shopifyOrderId, tillUuid, original.txnId, original.amount);

      if (markResult.success) {
        await saveTransaction({ txnId: original.txnId, status: 'paid', tillUuid });
        logger.info('Shopify order marked as paid', { requestId, txnId: original.txnId, shopifyOrderId: original.shopifyOrderId });
      } else {
        logger.error('Failed to mark Shopify order as paid', {
          requestId, txnId: original.txnId,
          shopifyOrderId: original.shopifyOrderId,
          error: markResult.error
        });
        // Don't update status — retry will catch it
      }

    } else if (normalizedResult === 'ERROR' || normalizedReturnType === 'ERROR' || normalizedStatus === 'ERROR' || hasCallbackErrors) {
      await saveTransaction({ txnId: original.txnId, status: 'failed', tillUuid });
      const errorCode = cb.errors?.[0]?.errorCode;
      const errorMsg  = cb.errors?.[0]?.errorMessage || cb.errors?.[0]?.message || 'unknown';
      const adapterCode = cb.errors?.[0]?.adapterCode || '';
      const adapterMsg  = cb.errors?.[0]?.adapterMessage || '';

      logger.error('PAYMENT FAILED DETAILS', {
        requestId, txnId: original.txnId, tillUuid,
        errorCode, errorMsg, adapterCode, adapterMsg,
        fullErrors: JSON.stringify(cb.errors),
        fullBody: JSON.stringify(cb).substring(0, 1000)
      });

      if (errorCode === 1004) {
        logger.alert('Till payment error 1004 — check connector/config', { requestId, txnId: original.txnId, errorMsg, adapterMsg });
      } else if (errorCode === 2003) {
        logger.alert('Till payment declined (2003)', { requestId, txnId: original.txnId, errorMsg, adapterMsg });
      } else if (errorCode === 2021) {
        logger.alert('Till 3DS verification failed (2021)', { requestId, txnId: original.txnId, errorMsg, adapterMsg });
      } else if (errorCode === 3004) {
        logger.alert('Till duplicate transaction ID (3004)', { requestId, txnId: original.txnId, errorMsg, adapterMsg });
      } else {
        logger.error('Payment failed — unhandled error code', { requestId, txnId: original.txnId, errorCode, errorMsg, adapterCode, adapterMsg });
      }

    } else {
      logger.warn('Unhandled callback result', {
        requestId,
        txnId: original.txnId,
        result,
        returnType,
        status: cbStatus || '(missing)',
        fullBody: JSON.stringify(cb).substring(0, 1000)
      });
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
// ENDPOINT: POST /api/reconcile/:orderNumber
// ═════════════════════════════════════════════════════════════════════════════
// Manual payment reconciliation — checks Till for a transaction's real status
// and updates Shopify if it was actually paid but the callback was lost.
// Requires API key auth to prevent abuse.
//
// Headers:
//   X-Api-Key: <TILL_SHARED_SECRET>
//
// This recovers orders like #1443 where the bank charged the customer
// but the callback couldn't be matched.

app.post('/api/reconcile/:orderNumber', async (req, res) => {
  const requestId = crypto.randomUUID();

  // Simple API key auth — use the shared secret
  const apiKey = req.get('X-Api-Key');
  if (!apiKey || apiKey !== TILL_SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const txnId = `HOC-${orderNumber}`;
  logger.info('Manual reconciliation requested', { requestId, orderNumber, txnId });

  // Look up the transaction
  let txn = await getTransaction(txnId);
  if (!txn) {
    txn = await getTransactionByOrderNumber(orderNumber);
  }
  if (!txn) {
    return res.status(404).json({ error: 'Transaction not found', orderNumber, txnId });
  }

  if (txn.status === 'paid') {
    return res.json({ status: 'already_paid', txnId: txn.txnId, orderNumber });
  }

  // If we have a Till UUID, query Till for the real status
  if (txn.tillUuid) {
    try {
      const tillRes = await callTillAPI(
        'GET',
        `/api/v3/status/${TILL_API_KEY}/${txn.tillUuid}`
      );

      const tillStatus = tillRes.body;
      logger.info('Till status check result', {
        requestId, txnId: txn.txnId,
        tillStatus: tillStatus?.status || tillStatus?.transactionStatus,
        result: tillStatus?.result,
        returnType: tillStatus?.returnType
      });

      // If Till says it was successful, mark Shopify as paid
      if (tillStatus && (tillStatus.result === 'OK' || tillStatus.status === 'SUCCESS')) {
        const markResult = await markShopifyOrderPaid(
          txn.shopifyOrderId, txn.tillUuid, txn.txnId, txn.amount
        );

        if (markResult.success) {
          await saveTransaction({ txnId: txn.txnId, status: 'paid', tillUuid: txn.tillUuid });
          logger.info('Manual reconciliation — order marked as paid', {
            requestId, txnId: txn.txnId, orderNumber
          });
          return res.json({
            status: 'reconciled',
            txnId: txn.txnId,
            orderNumber,
            message: 'Order has been marked as paid in Shopify'
          });
        } else {
          logger.error('Manual reconciliation — failed to mark Shopify order paid', {
            requestId, txnId: txn.txnId, error: markResult.error
          });
          return res.status(502).json({
            error: 'Till confirms payment but Shopify update failed',
            details: markResult.error
          });
        }
      }

      return res.json({
        status: 'not_paid_at_till',
        txnId: txn.txnId,
        currentStatus: txn.status,
        tillResponse: tillStatus
      });

    } catch (err) {
      logger.error('Manual reconciliation — Till status check failed', {
        requestId, txnId: txn.txnId, error: err.message
      });
      return res.status(502).json({ error: 'Failed to check Till status', details: err.message });
    }
  }

  // No Till UUID — can't check status
  return res.json({
    status: 'no_till_uuid',
    txnId: txn.txnId,
    currentStatus: txn.status,
    message: 'Transaction has no Till UUID — cannot verify payment status remotely'
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /api/transactions/:orderNumber
// ═════════════════════════════════════════════════════════════════════════════
// Debug endpoint — returns transaction state. Requires API key auth.

app.get('/api/transactions/:orderNumber', async (req, res) => {
  const apiKey = req.get('X-Api-Key');
  if (!apiKey || apiKey !== TILL_SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const txnId = `HOC-${orderNumber}`;
  let txn = await getTransaction(txnId);
  if (!txn) {
    txn = await getTransactionByOrderNumber(orderNumber);
  }
  if (!txn) {
    return res.status(404).json({ error: 'Transaction not found' });
  }

  return res.json(txn);
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/cancel/:orderNumber
// ═════════════════════════════════════════════════════════════════════════════
// Cancel a pending payment:
//   1. Void/refund the Till transaction (releases the bank hold)
//   2. Cancel the Shopify order
//   3. Update local transaction status to 'cancelled'
//
// Requires API key auth. Use this when a customer's bank shows a pending
// authorisation but the order needs to be abandoned.
//
// Headers:
//   X-Api-Key: <TILL_SHARED_SECRET>
// Body (optional):
//   { "reason": "Customer requested cancellation" }

app.post('/api/cancel/:orderNumber', async (req, res) => {
  const requestId = crypto.randomUUID();

  const apiKey = req.get('X-Api-Key');
  if (!apiKey || apiKey !== TILL_SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const reason = req.body?.reason || 'Payment cancelled via admin';
  const txnId = `HOC-${orderNumber}`;
  logger.info('Cancel payment requested', { requestId, orderNumber, txnId });

  // Look up the transaction
  let txn = await getTransaction(txnId);
  if (!txn) {
    txn = await getTransactionByOrderNumber(orderNumber);
  }
  if (!txn) {
    return res.status(404).json({ error: 'Transaction not found', orderNumber, txnId });
  }

  if (txn.status === 'cancelled') {
    return res.json({ status: 'already_cancelled', txnId: txn.txnId, orderNumber });
  }

  const results = { tillVoid: null, shopifyCancel: null };

  // ── Step 1: Void/refund at Till (releases the bank hold) ──────────────
  if (txn.tillUuid) {
    try {
      // For a debit, Till uses "void" to release un-captured funds.
      // If the debit was already captured/settled, "void" will fail —
      // in that case we fall back to a full refund.
      const voidPayload = {
        merchantTransactionId: `HOC-CANCEL-${orderNumber}-${Date.now()}`,
        referenceUuid: txn.tillUuid
      };

      let tillRes = await callTillAPI(
        'POST',
        `/api/v3/transaction/${TILL_API_KEY}/void`,
        voidPayload
      );

      if (tillRes.body?.success) {
        results.tillVoid = { success: true, method: 'void', uuid: tillRes.body.uuid };
        logger.info('Till void succeeded', { requestId, txnId: txn.txnId, voidUuid: tillRes.body.uuid });
      } else {
        // Void failed — try refund instead (for settled transactions)
        logger.info('Till void failed, attempting refund', {
          requestId, txnId: txn.txnId,
          voidError: tillRes.body?.errors?.[0]?.errorMessage || 'unknown'
        });

        const refundPayload = {
          merchantTransactionId: `HOC-REFUND-${orderNumber}-${Date.now()}`,
          referenceUuid: txn.tillUuid,
          amount: txn.amount,
          currency: txn.currency || 'AUD',
          description: reason
        };

        tillRes = await callTillAPI(
          'POST',
          `/api/v3/transaction/${TILL_API_KEY}/refund`,
          refundPayload
        );

        if (tillRes.body?.success) {
          results.tillVoid = { success: true, method: 'refund', uuid: tillRes.body.uuid };
          logger.info('Till refund succeeded', { requestId, txnId: txn.txnId, refundUuid: tillRes.body.uuid });
        } else {
          results.tillVoid = {
            success: false,
            error: tillRes.body?.errors?.[0]?.errorMessage || 'Void and refund both failed',
            tillResponse: tillRes.body
          };
          logger.error('Till void and refund both failed', {
            requestId, txnId: txn.txnId,
            errors: JSON.stringify(tillRes.body?.errors)
          });
        }
      }
    } catch (err) {
      results.tillVoid = { success: false, error: err.message };
      logger.error('Till cancel API error', { requestId, txnId: txn.txnId, error: err.message });
    }
  } else {
    results.tillVoid = { skipped: true, reason: 'No Till UUID — transaction may not have reached Till' };
    logger.info('No Till UUID to void', { requestId, txnId: txn.txnId });
  }

  // ── Step 2: Cancel the Shopify order ──────────────────────────────────
  if (txn.shopifyOrderId) {
    try {
      const cancelRes = await shopifyAdminAPI(
        'POST',
        `/orders/${txn.shopifyOrderId}/cancel.json`,
        { reason: 'other', email: true }
      );

      if (cancelRes.status >= 200 && cancelRes.status < 300) {
        results.shopifyCancel = { success: true };
        logger.info('Shopify order cancelled', { requestId, txnId: txn.txnId, shopifyOrderId: txn.shopifyOrderId });
      } else {
        // 422 often means "already cancelled" or "already fulfilled"
        const errorDetail = JSON.stringify(cancelRes.body).substring(0, 500);
        results.shopifyCancel = { success: false, status: cancelRes.status, error: errorDetail };
        logger.warn('Shopify cancel returned non-success', {
          requestId, txnId: txn.txnId, status: cancelRes.status, body: errorDetail
        });
      }
    } catch (err) {
      results.shopifyCancel = { success: false, error: err.message };
      logger.error('Shopify cancel API error', { requestId, txnId: txn.txnId, error: err.message });
    }
  } else {
    results.shopifyCancel = { skipped: true, reason: 'No Shopify order ID' };
  }

  // ── Step 3: Update local transaction status ───────────────────────────
  await saveTransaction({ txnId: txn.txnId, status: 'cancelled' });

  logger.info('Cancel payment completed', { requestId, txnId: txn.txnId, results });

  return res.json({
    status: 'cancelled',
    txnId: txn.txnId,
    orderNumber,
    tillVoid: results.tillVoid,
    shopifyCancel: results.shopifyCancel,
    message: 'Payment cancelled. Bank hold will release within 3-5 business days.'
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/cancel/:orderNumber
// ═════════════════════════════════════════════════════════════════════════════
// Cancel a pending payment:
//   1. Void/refund the Till transaction (releases the bank hold)
//   2. Cancel the Shopify order
//   3. Update local transaction status to 'cancelled'
//
// Requires API key auth. Use this when a customer's bank shows a pending
// authorisation but the order needs to be abandoned.
//
// Headers:
//   X-Api-Key: <TILL_SHARED_SECRET>
// Body (optional):
//   { "reason": "Customer requested cancellation" }

app.post('/api/cancel/:orderNumber', async (req, res) => {
  const requestId = crypto.randomUUID();

  const apiKey = req.get('X-Api-Key');
  if (!apiKey || apiKey !== TILL_SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const reason = req.body?.reason || 'Payment cancelled via admin';
  const txnId = `HOC-${orderNumber}`;
  logger.info('Cancel payment requested', { requestId, orderNumber, txnId });

  // Look up the transaction
  let txn = await getTransaction(txnId);
  if (!txn) {
    txn = await getTransactionByOrderNumber(orderNumber);
  }
  if (!txn) {
    return res.status(404).json({ error: 'Transaction not found', orderNumber, txnId });
  }

  if (txn.status === 'cancelled') {
    return res.json({ status: 'already_cancelled', txnId: txn.txnId, orderNumber });
  }

  const results = { tillVoid: null, shopifyCancel: null };

  // ── Step 1: Void/refund at Till (releases the bank hold) ──────────────
  if (txn.tillUuid) {
    try {
      // For a debit, Till uses "void" to release un-captured funds.
      // If the debit was already captured/settled, "void" will fail —
      // in that case we fall back to a full refund.
      const voidPayload = {
        merchantTransactionId: `HOC-CANCEL-${orderNumber}-${Date.now()}`,
        referenceUuid: txn.tillUuid
      };

      let tillRes = await callTillAPI(
        'POST',
        `/api/v3/transaction/${TILL_API_KEY}/void`,
        voidPayload
      );

      if (tillRes.body?.success) {
        results.tillVoid = { success: true, method: 'void', uuid: tillRes.body.uuid };
        logger.info('Till void succeeded', { requestId, txnId: txn.txnId, voidUuid: tillRes.body.uuid });
      } else {
        // Void failed — try refund instead (for settled transactions)
        logger.info('Till void failed, attempting refund', {
          requestId, txnId: txn.txnId,
          voidError: tillRes.body?.errors?.[0]?.errorMessage || 'unknown'
        });

        const refundPayload = {
          merchantTransactionId: `HOC-REFUND-${orderNumber}-${Date.now()}`,
          referenceUuid: txn.tillUuid,
          amount: txn.amount,
          currency: txn.currency || 'AUD',
          description: reason
        };

        tillRes = await callTillAPI(
          'POST',
          `/api/v3/transaction/${TILL_API_KEY}/refund`,
          refundPayload
        );

        if (tillRes.body?.success) {
          results.tillVoid = { success: true, method: 'refund', uuid: tillRes.body.uuid };
          logger.info('Till refund succeeded', { requestId, txnId: txn.txnId, refundUuid: tillRes.body.uuid });
        } else {
          results.tillVoid = {
            success: false,
            error: tillRes.body?.errors?.[0]?.errorMessage || 'Void and refund both failed',
            tillResponse: tillRes.body
          };
          logger.error('Till void and refund both failed', {
            requestId, txnId: txn.txnId,
            errors: JSON.stringify(tillRes.body?.errors)
          });
        }
      }
    } catch (err) {
      results.tillVoid = { success: false, error: err.message };
      logger.error('Till cancel API error', { requestId, txnId: txn.txnId, error: err.message });
    }
  } else {
    results.tillVoid = { skipped: true, reason: 'No Till UUID — transaction may not have reached Till' };
    logger.info('No Till UUID to void', { requestId, txnId: txn.txnId });
  }

  // ── Step 2: Cancel the Shopify order ──────────────────────────────────
  if (txn.shopifyOrderId) {
    try {
      const cancelRes = await shopifyAdminAPI(
        'POST',
        `/orders/${txn.shopifyOrderId}/cancel.json`,
        { reason: 'other', email: true }
      );

      if (cancelRes.status >= 200 && cancelRes.status < 300) {
        results.shopifyCancel = { success: true };
        logger.info('Shopify order cancelled', { requestId, txnId: txn.txnId, shopifyOrderId: txn.shopifyOrderId });
      } else {
        // 422 often means "already cancelled" or "already fulfilled"
        const errorDetail = JSON.stringify(cancelRes.body).substring(0, 500);
        results.shopifyCancel = { success: false, status: cancelRes.status, error: errorDetail };
        logger.warn('Shopify cancel returned non-success', {
          requestId, txnId: txn.txnId, status: cancelRes.status, body: errorDetail
        });
      }
    } catch (err) {
      results.shopifyCancel = { success: false, error: err.message };
      logger.error('Shopify cancel API error', { requestId, txnId: txn.txnId, error: err.message });
    }
  } else {
    results.shopifyCancel = { skipped: true, reason: 'No Shopify order ID' };
  }

  // ── Step 3: Update local transaction status ───────────────────────────
  await saveTransaction({ txnId: txn.txnId, status: 'cancelled' });

  logger.info('Cancel payment completed', { requestId, txnId: txn.txnId, results });

  return res.json({
    status: 'cancelled',
    txnId: txn.txnId,
    orderNumber,
    tillVoid: results.tillVoid,
    shopifyCancel: results.shopifyCancel,
    message: 'Payment cancelled. Bank hold will release within 3-5 business days.'
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/cancel/:orderNumber
// ═════════════════════════════════════════════════════════════════════════════
// Cancel a pending payment:
//   1. Void/refund the Till transaction (releases the bank hold)
//   2. Cancel the Shopify order
//   3. Update local transaction status to 'cancelled'
//
// Requires API key auth. Use this when a customer's bank shows a pending
// authorisation but the order needs to be abandoned.
//
// Headers:
//   X-Api-Key: <TILL_SHARED_SECRET>
// Body (optional):
//   { "reason": "Customer requested cancellation" }

app.post('/api/cancel/:orderNumber', async (req, res) => {
  const requestId = crypto.randomUUID();

  const apiKey = req.get('X-Api-Key');
  if (!apiKey || apiKey !== TILL_SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const orderNumber = req.params.orderNumber.replace(/^#/, '');
  const reason = req.body?.reason || 'Payment cancelled via admin';
  const txnId = `HOC-${orderNumber}`;
  logger.info('Cancel payment requested', { requestId, orderNumber, txnId });

  // Look up the transaction
  let txn = await getTransaction(txnId);
  if (!txn) {
    txn = await getTransactionByOrderNumber(orderNumber);
  }
  if (!txn) {
    return res.status(404).json({ error: 'Transaction not found', orderNumber, txnId });
  }

  if (txn.status === 'cancelled') {
    return res.json({ status: 'already_cancelled', txnId: txn.txnId, orderNumber });
  }

  const results = { tillVoid: null, shopifyCancel: null };

  // ── Step 1: Void/refund at Till (releases the bank hold) ──────────────
  if (txn.tillUuid) {
    try {
      // For a debit, Till uses "void" to release un-captured funds.
      // If the debit was already captured/settled, "void" will fail —
      // in that case we fall back to a full refund.
      const voidPayload = {
        merchantTransactionId: `HOC-CANCEL-${orderNumber}-${Date.now()}`,
        referenceUuid: txn.tillUuid
      };

      let tillRes = await callTillAPI(
        'POST',
        `/api/v3/transaction/${TILL_API_KEY}/void`,
        voidPayload
      );

      if (tillRes.body?.success) {
        results.tillVoid = { success: true, method: 'void', uuid: tillRes.body.uuid };
        logger.info('Till void succeeded', { requestId, txnId: txn.txnId, voidUuid: tillRes.body.uuid });
      } else {
        // Void failed — try refund instead (for settled transactions)
        logger.info('Till void failed, attempting refund', {
          requestId, txnId: txn.txnId,
          voidError: tillRes.body?.errors?.[0]?.errorMessage || 'unknown'
        });

        const refundPayload = {
          merchantTransactionId: `HOC-REFUND-${orderNumber}-${Date.now()}`,
          referenceUuid: txn.tillUuid,
          amount: txn.amount,
          currency: txn.currency || 'AUD',
          description: reason
        };

        tillRes = await callTillAPI(
          'POST',
          `/api/v3/transaction/${TILL_API_KEY}/refund`,
          refundPayload
        );

        if (tillRes.body?.success) {
          results.tillVoid = { success: true, method: 'refund', uuid: tillRes.body.uuid };
          logger.info('Till refund succeeded', { requestId, txnId: txn.txnId, refundUuid: tillRes.body.uuid });
        } else {
          results.tillVoid = {
            success: false,
            error: tillRes.body?.errors?.[0]?.errorMessage || 'Void and refund both failed',
            tillResponse: tillRes.body
          };
          logger.error('Till void and refund both failed', {
            requestId, txnId: txn.txnId,
            errors: JSON.stringify(tillRes.body?.errors)
          });
        }
      }
    } catch (err) {
      results.tillVoid = { success: false, error: err.message };
      logger.error('Till cancel API error', { requestId, txnId: txn.txnId, error: err.message });
    }
  } else {
    results.tillVoid = { skipped: true, reason: 'No Till UUID — transaction may not have reached Till' };
    logger.info('No Till UUID to void', { requestId, txnId: txn.txnId });
  }

  // ── Step 2: Cancel the Shopify order ──────────────────────────────────
  if (txn.shopifyOrderId) {
    try {
      const cancelRes = await shopifyAdminAPI(
        'POST',
        `/orders/${txn.shopifyOrderId}/cancel.json`,
        { reason: 'other', email: true }
      );

      if (cancelRes.status >= 200 && cancelRes.status < 300) {
        results.shopifyCancel = { success: true };
        logger.info('Shopify order cancelled', { requestId, txnId: txn.txnId, shopifyOrderId: txn.shopifyOrderId });
      } else {
        // 422 often means "already cancelled" or "already fulfilled"
        const errorDetail = JSON.stringify(cancelRes.body).substring(0, 500);
        results.shopifyCancel = { success: false, status: cancelRes.status, error: errorDetail };
        logger.warn('Shopify cancel returned non-success', {
          requestId, txnId: txn.txnId, status: cancelRes.status, body: errorDetail
        });
      }
    } catch (err) {
      results.shopifyCancel = { success: false, error: err.message };
      logger.error('Shopify cancel API error', { requestId, txnId: txn.txnId, error: err.message });
    }
  } else {
    results.shopifyCancel = { skipped: true, reason: 'No Shopify order ID' };
  }

  // ── Step 3: Update local transaction status ───────────────────────────
  await saveTransaction({ txnId: txn.txnId, status: 'cancelled' });

  logger.info('Cancel payment completed', { requestId, txnId: txn.txnId, results });

  return res.json({
    status: 'cancelled',
    txnId: txn.txnId,
    orderNumber,
    tillVoid: results.tillVoid,
    shopifyCancel: results.shopifyCancel,
    message: 'Payment cancelled. Bank hold will release within 3-5 business days.'
  });
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
// ENDPOINT: GET /api/cert/hpp-test
// ═════════════════════════════════════════════════════════════════════════════
// Creates a throwaway debit and runs the REAL completeHPP() flow on it.
app.get('/api/cert/hpp-test', async (_req, res) => {
  try {
    const ts = `HPP-TEST-${Date.now()}`;
    const BASE = `/api/v3/transaction/${TILL_API_KEY}`;
    const r = await callTillAPI('POST', BASE + '/debit', {
      merchantTransactionId: ts, amount: '1.00', currency: 'AUD',
      transactionIndicator: 'SINGLE', description: 'HPP Auto-Test',
      customer: { firstName: 'Test', lastName: 'Auto', email: 'auto@test.com', ipAddress: '127.0.0.1', billingCountry: 'AU' },
      successUrl: CERT_SUCCESS_URL, cancelUrl: CERT_CANCEL_URL, errorUrl: CERT_ERROR_URL, callbackUrl: CALLBACK_URL
    });
    const d = r.body || {};
    if (!d.redirectUrl) return res.json({ error: 'No redirectUrl from Till', raw: d });

    const hpp = await completeHPP(d.redirectUrl, '4111111111111111');
    res.json({ redirectUrl: d.redirectUrl, uuid: d.uuid, hppResult: hpp });
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack?.substring(0, 500) });
  }
});

// ENDPOINT: GET /api/cert/hpp-3ds-debug
// ═════════════════════════════════════════════════════════════════════════════
// Creates a 3DS-MANDATORY transaction, fills form with 3DS test card, submits,
// then captures the full state of all frames on the resulting page.
app.get('/api/cert/hpp-3ds-debug', async (_req, res) => {
  try {
    const ts = `HPP-3DS-DBG-${Date.now()}`;
    const BASE = `/api/v3/transaction/${TILL_API_KEY}`;
    const r = await callTillAPI('POST', BASE + '/debit', {
      merchantTransactionId: ts, amount: '1.00', currency: 'AUD',
      transactionIndicator: 'SINGLE', description: '3DS Debug',
      customer: { firstName: 'Test', lastName: '3DS', email: '3ds@test.com', ipAddress: '127.0.0.1', billingCountry: 'AU' },
      successUrl: CERT_SUCCESS_URL, cancelUrl: CERT_CANCEL_URL, errorUrl: CERT_ERROR_URL, callbackUrl: CALLBACK_URL,
      extraData: { '3dsecure': 'MANDATORY' },
      threeDSecureData: { '3dsecure': 'MANDATORY', channel: '02', authenticationIndicator: '01', cardholderAuthenticationMethod: '01', challengeIndicator: '02' }
    });
    const d = r.body || {};
    if (!d.redirectUrl) return res.json({ error: 'No redirectUrl', raw: d });

    if (!puppeteer) return res.json({ error: 'Puppeteer not available' });
    const browser = await getHPPBrowser();
    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120');
    
    // Step 1: Navigate to HPP
    await page.goto(d.redirectUrl, { waitUntil: 'networkidle2', timeout: 30000 });
    await _delay(4000);

    // Step 2: Fill form fields
    const firstName = await page.$('#first_name');
    const lastName  = await page.$('#last_name');
    if (firstName) { await firstName.click({ clickCount: 3 }); await firstName.type('Test'); }
    if (lastName)  { await lastName.click({ clickCount: 3 }); await lastName.type('ThreeDS'); }
    await page.select('#month', '12').catch(() => {});
    await page.select('#year', '2030').catch(() => {});

    // PAN iframe
    const panFrame = page.frames().find(f => /\/iframes\/pan/i.test(f.url()));
    if (panFrame) {
      const inp = await panFrame.waitForSelector('input', { timeout: 5000 }).catch(() => null);
      if (inp) { await inp.click(); await inp.type('4000002000000008'); }
    }
    // CVV iframe
    const cvvFrame = page.frames().find(f => /\/iframes\/cvv/i.test(f.url()));
    if (cvvFrame) {
      const inp = await cvvFrame.waitForSelector('input', { timeout: 5000 }).catch(() => null);
      if (inp) { await inp.click(); await inp.type('123'); }
    }

    // Step 3: Click Submit
    await page.evaluate(() => {
      const btns = [...document.querySelectorAll('button, input[type="submit"]')];
      const pay = btns.find(b => /submit|pay/i.test((b.textContent || b.value || '').trim()));
      if (pay) pay.click();
      else { const form = document.getElementById('payment-form'); if (form) form.submit(); }
    });

    // Step 4: Wait for something to happen
    await page.waitForNavigation({ timeout: 15000, waitUntil: 'networkidle2' }).catch(() => {});
    
    const afterSubmitUrl = page.url();
    
    // Wait a bit more for 3DS challenge to load
    await _delay(5000);

    // Step 5: Capture ALL frame contents
    const frameData = [];
    for (const frame of page.frames()) {
      const fUrl = frame.url();
      const isMain = frame === page.mainFrame();
      try {
        const data = await frame.evaluate(() => {
          const btns = [...document.querySelectorAll('button, input[type="submit"], a.button, input[type="button"]')].map(b => ({
            tag: b.tagName, type: b.type || '', text: (b.textContent || b.value || '').trim().substring(0, 100),
            id: b.id, className: b.className, name: b.name || '',
            visible: b.offsetWidth > 0 && b.offsetHeight > 0,
            display: window.getComputedStyle(b).display, visibility: window.getComputedStyle(b).visibility
          }));
          const forms = [...document.querySelectorAll('form')].map(f => ({
            action: f.action, method: f.method, id: f.id
          }));
          const inputs = [...document.querySelectorAll('input, select, textarea')].map(el => ({
            tag: el.tagName, type: el.type, name: el.name, id: el.id,
            visible: el.offsetWidth > 0 && el.offsetHeight > 0
          }));
          const iframes = [...document.querySelectorAll('iframe')].map(f => ({
            src: f.src, id: f.id, name: f.name
          }));
          return {
            bodyText: (document.body?.innerText || '').substring(0, 2000),
            html: document.documentElement?.outerHTML?.substring(0, 5000) || '',
            btns, forms, inputs, iframes
          };
        }).catch(() => ({ error: 'evaluate failed' }));
        frameData.push({ url: fUrl, isMain, ...data });
      } catch (e) {
        frameData.push({ url: fUrl, isMain, error: e.message });
      }
    }

    await page.close().catch(() => {});

    res.json({
      redirectUrl: d.redirectUrl,
      afterSubmitUrl,
      currentUrl: afterSubmitUrl,
      frameCount: frameData.length,
      frames: frameData
    });
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack?.substring(0, 500) });
  }
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

app.get('/api/cert/run-all', async (req, res) => {
  // Stream keepalive chunks to prevent Railway proxy / browser timeout (~5 min idle limit)
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no' });
  const _keepalive = setInterval(() => { if (!res.writableEnded) res.write(' '); }, 10000);
  req.on('close', () => clearInterval(_keepalive));
  try {
  const ts = () => `HOC-CERT-${Date.now()}-${Math.floor(Math.random()*9999)}`;
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  async function run(label, method, path, body = {}) {
    await sleep(5000);
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const r = await callTillAPI(method, path, body);
        const d = r.body || {};
        if (d.errorCode === 1009 && attempt < 2) {
          logger.warn('[CERT] rate limit, retrying', { label, attempt });
          await sleep(8000);
          continue;
        }
        const success = d.success !== false && !(d.errors && d.errors.length);
        if (!success) logger.warn('[CERT] test returned error', { label, status: r.status, errors: d.errors, returnType: d.returnType, code: d.code });
        return { label, success, uuid: d.uuid || d.registrationId || null, redirectUrl: d.redirectUrl || null, raw: d };
      } catch (e) {
        return { label, success: false, uuid: null, redirectUrl: null, raw: { error: e.message } };
      }
    }
  }

  async function runHPP(label, method, path, body, cardNumber = '4111111111111111') {
    const expectDecline = cardNumber === '4111111111111119';
    const r = await run(label, method, path, body);
    if (r.redirectUrl) {
      const hpp = await completeHPP(r.redirectUrl, cardNumber, expectDecline);
      r.hppCompleted = hpp.completed;
      r.hppError     = hpp.error;
      if (!hpp.completed) r.needsManual = true;
      logger.info('[CERT] HPP auto', { label, completed: hpp.completed, error: hpp.error, expectDecline });
    }
    return r;
  }

  const BASE  = `/api/v3/transaction/${TILL_API_KEY}`;
  const CUST  = { firstName:'Test', lastName:'Customer', email:'cert@highonchapel.com', ipAddress:'127.0.0.1', billingCountry:'AU' };
  const URLS  = { successUrl: CERT_SUCCESS_URL, cancelUrl: CERT_CANCEL_URL, errorUrl: CERT_ERROR_URL, callbackUrl: CALLBACK_URL };
  const FAIL  = (label, reason) => ({ label, success: false, uuid: null, redirectUrl: null, raw: { error: reason } });

  // ═══ Phase 1: HPP transactions — create + auto-complete payment pages ═══
  const d_1a = await runHPP('1.a – Debit INITIAL',               'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'INITIAL', description:'HOC Cert 1.a', customer:CUST, ...URLS, withRegister:true });
  const d_1e = await runHPP('1.e – Debit SINGLE no 3DS',         'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.e', customer:CUST, ...URLS });
  const d_1f = await runHPP('1.f – Debit SINGLE Dynamic Desc',   'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'High on Chapel 13-Feb', customer:CUST, ...URLS });
  const d_1g = await runHPP('1.g – Debit SINGLE 3DS MANDATORY',  'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.g', customer:CUST, ...URLS, extraData:{'3dsecure':'MANDATORY'}, threeDSecureData:{'3dsecure':'MANDATORY',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'02'} }, '4000002000000008');
  const d_1h = await runHPP('1.h – Debit SINGLE 3DS OPTIONAL',   'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.h', customer:CUST, ...URLS, extraData:{'3dsecure':'OPTIONAL'}, threeDSecureData:{'3dsecure':'OPTIONAL',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'03'} });
  const d_1_0  = await runHPP('1.0 – Debit (4111 card)',          'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.0 4111', customer:CUST, ...URLS });
  const d_1_4k = await runHPP('1.0 – Debit (4000 card)',          'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 1.0 4000', customer:CUST, ...URLS }, '4000002000000008');

  const p_2a = await runHPP('2.a – Preauth INITIAL',              'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'INITIAL', description:'HOC Cert 2.a', customer:CUST, ...URLS, withRegister:true });
  const p_2e = await runHPP('2.e – Preauth SINGLE no 3DS',        'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.e', customer:CUST, ...URLS });
  const p_2f = await runHPP('2.f – Preauth SINGLE Dynamic Desc',  'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'High on Chapel 13-Feb', customer:CUST, ...URLS });
  const p_2g = await runHPP('2.g – Preauth SINGLE 3DS MANDATORY', 'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.g', customer:CUST, ...URLS, extraData:{'3dsecure':'MANDATORY'}, threeDSecureData:{'3dsecure':'MANDATORY',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'02'} }, '4000002000000008');
  const p_2h = await runHPP('2.h – Preauth SINGLE 3DS OPTIONAL',  'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.h', customer:CUST, ...URLS, extraData:{'3dsecure':'OPTIONAL'}, threeDSecureData:{'3dsecure':'OPTIONAL',channel:'02',authenticationIndicator:'01',cardholderAuthenticationMethod:'01',challengeIndicator:'03'} });
  const p_2_0  = await runHPP('2.0 – Preauth (4111 card)',         'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.0 4111', customer:CUST, ...URLS });
  const p_2_4k = await runHPP('2.0 – Preauth (4000 card)',         'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE',  description:'HOC Cert 2.0 4000', customer:CUST, ...URLS }, '4000002000000008');

  const t5   = await runHPP('5 – Register card (4111)', 'POST', BASE+'/register', { merchantTransactionId:ts(), customer:CUST, ...URLS });
  const t5_3ds = await runHPP('5.b – Register card (4000 3DS)', 'POST', BASE+'/register', { merchantTransactionId:ts(), customer:CUST, ...URLS }, '4000002000000008');

  // ═══ Phase 2: Settle wait — give Till time to process HPP completions ═══
  logger.info('[CERT] Waiting 15s for HPP settlements…');
  await sleep(15000);

  // ═══ Phase 3: RECURRING / CARDONFILE (server-to-server, need 1.a / 2.a HPP done) ═══
  const refD = d_1a.uuid, refPA = p_2a.uuid;
  logger.info('[CERT] Phase 3 refs', { refD, refPA, d1aHPP: d_1a.hppCompleted, p2aHPP: p_2a.hppCompleted });
  const d_1b = (refD && d_1a.hppCompleted) ? await run('1.b – Debit RECURRING',                 'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'RECURRING',                    description:'HOC Cert 1.b', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:refD }) : FAIL('1.b – Debit RECURRING', 'Debit 1.a HPP not completed');
  const d_1c = (refD && d_1a.hppCompleted) ? await run('1.c – Debit CARDONFILE',                'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE',                   description:'HOC Cert 1.c', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:refD }) : FAIL('1.c – Debit CARDONFILE', 'Debit 1.a HPP not completed');
  const d_1d = (refD && d_1a.hppCompleted) ? await run('1.d – Debit CARDONFILE-MERCHANT-INIT',  'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', description:'HOC Cert 1.d', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:refD }) : FAIL('1.d – Debit CARDONFILE-MERCHANT-INIT', 'Debit 1.a HPP not completed');
  const p_2b = (refPA && p_2a.hppCompleted) ? await run('2.b – Preauth RECURRING',                'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'RECURRING',                    description:'HOC Cert 2.b', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:refPA }) : FAIL('2.b – Preauth RECURRING', 'Preauth 2.a HPP not completed');
  const p_2c = (refPA && p_2a.hppCompleted) ? await run('2.c – Preauth CARDONFILE',               'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE',                   description:'HOC Cert 2.c', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:refPA }) : FAIL('2.c – Preauth CARDONFILE', 'Preauth 2.a HPP not completed');
  const p_2d = (refPA && p_2a.hppCompleted) ? await run('2.d – Preauth CARDONFILE-MERCHANT-INIT', 'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', description:'HOC Cert 2.d', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:refPA }) : FAIL('2.d – Preauth CARDONFILE-MERCHANT-INIT', 'Preauth 2.a HPP not completed');

  // ═══ Phase 4: Downstream tests (need HPP completed on source transactions) ═══
  const cap  = p_2e.uuid && p_2e.hppCompleted ? await run('3 – Capture full',     'POST', BASE+'/capture',                  { merchantTransactionId:ts(), referenceUuid:p_2e.uuid, amount:'1.00', currency:'AUD' })                              : FAIL('3 – Capture full',     'Preauth 2.e HPP not completed');
  const capP = p_2f.uuid && p_2f.hppCompleted ? await run('3.a – Capture partial', 'POST', BASE+'/capture',                  { merchantTransactionId:ts(), referenceUuid:p_2f.uuid, amount:'0.50', currency:'AUD' })                              : FAIL('3.a – Capture partial', 'Preauth 2.f HPP not completed');
  const vd   = p_2g.uuid && p_2g.hppCompleted ? await run('4 – Void preauth',     'POST', BASE+'/void',                     { merchantTransactionId:ts(), referenceUuid:p_2g.uuid })                                                             : FAIL('4 – Void preauth',     'Preauth 2.g HPP not completed');
  // ── Debit using registered cards (use registrationId from register as referenceUuid) ──
  const d_reg1 = t5.uuid && t5.hppCompleted     ? await run('5.c – Debit registered (4111)', 'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert Debit from Register', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:t5.uuid }) : FAIL('5.c – Debit registered (4111)', 'Register (5) HPP not completed');
  const d_reg2 = t5_3ds.uuid && t5_3ds.hppCompleted ? await run('5.d – Debit registered (4000)', 'POST', BASE+'/debit', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert Debit from Register 3DS', customer:CUST, callbackUrl: CALLBACK_URL, referenceUuid:t5_3ds.uuid }) : FAIL('5.d – Debit registered (4000)', 'Register 3DS (5.b) HPP not completed');
  const dereg= t5.uuid   && t5.hppCompleted   ? await run('5.a – Deregister',     'POST', BASE+'/deregister',               { merchantTransactionId:ts(), referenceUuid:t5.uuid })                                                               : FAIL('5.a – Deregister',     'Register (5) HPP not completed');
  const reful = d_1e.uuid && d_1e.hppCompleted ? await run('6 – Full refund',      'POST', BASE+'/refund',                   { merchantTransactionId:ts(), referenceUuid:d_1e.uuid, amount:'1.00', currency:'AUD', description:'Full refund' })    : FAIL('6 – Full refund',      'Debit 1.e HPP not completed');
  const refPa = d_1f.uuid && d_1f.hppCompleted ? await run('7 – Partial refund',   'POST', BASE+'/refund',                   { merchantTransactionId:ts(), referenceUuid:d_1f.uuid, amount:'0.50', currency:'AUD', description:'Partial refund' }) : FAIL('7 – Partial refund',   'Debit 1.f HPP not completed');
  const rev  = d_1g.uuid && d_1g.hppCompleted ? await run('8 – Reversal',         'POST', BASE+'/refund',                   { merchantTransactionId:ts(), referenceUuid:d_1g.uuid, amount:'1.00', currency:'AUD', description:'Reversal (full refund)' }) : FAIL('8 – Reversal',         'Debit 1.g HPP not completed');
  const inc  = p_2h.uuid && p_2h.hppCompleted ? await run('9 – Incremental auth', 'POST', BASE+'/incrementalAuthorization', { merchantTransactionId:ts(), referenceUuid:p_2h.uuid, amount:'0.25', currency:'AUD' })                              : FAIL('9 – Incremental auth', 'Preauth 2.h HPP not completed');

  // PCI Direct (1.i / 2.i) — N/A: Till sandbox rejects cardData (error 1002 additionalProperties:false)

  // ═══ Phase 5: Negative tests (decline card — HPP auto-completed) ═══
  // Close & re-open browser between EACH negative test to avoid detached-frame errors
  await closeHPPBrowser();
  const t10  = await runHPP('10 – Negative debit (decline)',  'POST', BASE+'/debit',        { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert 10 Negative', customer:CUST, ...URLS }, '4111111111111119');
  await closeHPPBrowser();
  const t10a = await runHPP('10.a – Negative debit',    'POST', BASE+'/debit',        { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert 10.a Negative', customer:CUST, ...URLS }, '4111111111111119');
  await closeHPPBrowser();
  const t10b = await runHPP('10.b – Negative preauth',  'POST', BASE+'/preauthorize', { merchantTransactionId:ts(), amount:'1.00', currency:'AUD', transactionIndicator:'SINGLE', description:'HOC Cert 10.b Negative', customer:CUST, ...URLS }, '4111111111111119');
  await closeHPPBrowser();
  const t10c = await runHPP('10.c – Negative register', 'POST', BASE+'/register',     { merchantTransactionId:ts(), customer:CUST, ...URLS }, '4111111111111119');

  // ═══ Assemble results in display order (must match dashboard sections) ═══
  const results = [
    d_1a, d_1b, d_1c, d_1d, d_1e, d_1f, d_1g, d_1h, d_1_0, d_1_4k, // 0-9   Debits (incl 1.0 both cards)
    p_2a, p_2b, p_2c, p_2d, p_2e, p_2f, p_2g, p_2h, p_2_0, p_2_4k, // 10-19 Preauths (incl 2.0 both cards)
    cap, capP, vd,                                              // 20-22 Capture/Void
    t5, t5_3ds, d_reg1, d_reg2, dereg,                          // 23-27 Register/Deregister
    reful, refPa,                                                // 28-29 Refunds
    rev,                                                         // 30    Reversal
    inc,                                                         // 31    Incremental
    t10, t10a, t10b, t10c                                        // 32-35 Negatives
  ];

  // Clean up shared Puppeteer browser
  await closeHPPBrowser();

  const hppAuto   = results.filter(r => r.hppCompleted).length;
  const hppFailed = results.filter(r => r.needsManual && !/Negative/i.test(r.label)).length;
  logger.info('[CERT] run-all done', { total: results.length, hppAuto, hppFailed });
  clearInterval(_keepalive);
  res.end(JSON.stringify({ ok: true, results, hppAuto, hppFailed }));
  } catch(fatalErr) {
    clearInterval(_keepalive);
    logger.error('[CERT] run-all fatal', { error: fatalErr.message });
    if (!res.writableEnded) res.end(JSON.stringify({ ok: false, error: fatalErr.message }));
  }
});

// ENDPOINT: GET /
// ═════════════════════════════════════════════════════════════════════════════
// Till Developer Certification Test Dashboard — Auto-Run Edition
// Fires all tests automatically on button click. Shows UUID + remark per test.

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /admin/api/till/:tillUuid
// ═════════════════════════════════════════════════════════════════════════════
// Proxies Till status API for a single transaction. Used by the dashboard JS
// to show live Till payment details. Protected by DASHBOARD_SECRET.

app.get('/admin/api/till/:tillUuid', async (req, res) => {
  if (!DASHBOARD_SECRET || req.query.secret !== DASHBOARD_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { tillUuid } = req.params;
  if (!tillUuid || !/^[\w-]+$/.test(tillUuid)) {
    return res.status(400).json({ error: 'Invalid UUID' });
  }
  try {
    const tillRes = await callTillAPI('GET', `/api/v3/status/${TILL_API_KEY}/${tillUuid}`);
    return res.json(tillRes.body || {});
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /admin/api/mark-paid/:txnId
// ═════════════════════════════════════════════════════════════════════════════
// Manually marks an order as paid in Shopify and updates our DB.
// Use when Till's API can't confirm (expired session / Hike POS payment).
// Body: { amount: "84.55" }  — optional, defaults to stored order amount.
// Protected by DASHBOARD_SECRET.

app.post('/admin/api/mark-paid/:txnId', async (req, res) => {
  if (!DASHBOARD_SECRET || req.query.secret !== DASHBOARD_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { txnId } = req.params;
  const txn = await getTransaction(txnId).catch(() => null);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });
  if (txn.status === 'paid') return res.json({ status: 'already_paid' });

  const amount = (req.body && req.body.amount) ? String(req.body.amount) : txn.amount;
  const note   = (req.body && req.body.note)   ? String(req.body.note)   : 'Manually marked paid via HOCS admin dashboard';

  const markResult = await markShopifyOrderPaid(txn.shopifyOrderId, txn.tillUuid || txnId, txnId, amount);
  if (!markResult.success) {
    return res.status(502).json({ error: 'Shopify update failed', details: markResult.error });
  }

  await saveTransaction({ txnId, status: 'paid', tillUuid: txn.tillUuid });
  logger.info('Admin manually marked order paid', { txnId, shopifyOrderId: txn.shopifyOrderId, amount, note });
  return res.json({ status: 'paid', txnId, orderNumber: txn.orderNumber, amount });
});

// ENDPOINT: POST /admin/api/reconcile-all
// ═════════════════════════════════════════════════════════════════════════════
// Checks every non-paid transaction that has a Till UUID against Till's status
// API. Any that Till confirms as paid get marked paid in our DB + Shopify.
// Uses the actual Till charged amount (including surcharge) for the Shopify
// transaction record. Protected by DASHBOARD_SECRET.

app.post('/admin/api/reconcile-all', async (req, res) => {
  if (!DASHBOARD_SECRET || req.query.secret !== DASHBOARD_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const requestId = crypto.randomUUID();
  logger.info('Bulk reconcile started', { requestId });

  // Fetch all non-paid transactions that have a Till UUID
  const { rows: pending } = await pool.query(
    `SELECT * FROM transactions
     WHERE status NOT IN ('paid','reconciled','cancelled')
     AND till_uuid IS NOT NULL
     ORDER BY created_at DESC`
  );

  const results = [];
  let fixed = 0;

  for (const row of pending) {
    const txn = mapTransactionRow(row);
    try {
      const tillRes = await callTillAPI('GET', `/api/v3/status/${TILL_API_KEY}/${txn.tillUuid}`);
      const ts = tillRes.body || {};

      const isSuccess = ts.result === 'OK' ||
                        ts.status === 'SUCCESS' ||
                        ts.transactionStatus === 'SUCCESS';

      if (isSuccess) {
        // Use Till's actual charged amount (includes surcharge) if available,
        // otherwise fall back to our stored Shopify order amount.
        const tillAmount = ts.amount != null ? String(ts.amount) : txn.amount;

        const markResult = await markShopifyOrderPaid(
          txn.shopifyOrderId, txn.tillUuid, txn.txnId, tillAmount
        );

        if (markResult.success) {
          await saveTransaction({ txnId: txn.txnId, status: 'paid', tillUuid: txn.tillUuid });
          logger.info('Bulk reconcile — marked paid', { requestId, txnId: txn.txnId });
          fixed++;
          results.push({
            txnId: txn.txnId,
            orderNumber: txn.orderNumber,
            outcome: 'marked_paid',
            shopifyAmount: txn.amount,
            tillAmount,
            surcharge: tillAmount !== txn.amount ? (parseFloat(tillAmount) - parseFloat(txn.amount)).toFixed(2) : '0.00'
          });
        } else {
          results.push({
            txnId: txn.txnId,
            orderNumber: txn.orderNumber,
            outcome: 'shopify_update_failed',
            error: markResult.error
          });
        }
      } else {
        results.push({
          txnId: txn.txnId,
          orderNumber: txn.orderNumber,
          outcome: 'not_paid',
          tillResult: ts.result || ts.status || ts.returnType || 'unknown'
        });
      }
    } catch (err) {
      results.push({ txnId: txn.txnId, orderNumber: txn.orderNumber, outcome: 'error', error: err.message });
    }
  }

  logger.info('Bulk reconcile complete', { requestId, checked: pending.length, fixed });
  return res.json({ checked: pending.length, fixed, results });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /admin
// ═════════════════════════════════════════════════════════════════════════════
// Transaction dashboard. Protected by DASHBOARD_SECRET query param.
// Visit: /admin?secret=<DASHBOARD_SECRET>
// Optional filters: &status=paid|pending|failed|... &search=<text> &page=<n>

app.get('/admin', async (req, res) => {
  if (!DASHBOARD_SECRET || req.query.secret !== DASHBOARD_SECRET) {
    return res.status(401).send(`<!DOCTYPE html><html><head><title>401</title></head>
<body style="font-family:sans-serif;padding:40px;background:#0f1b2d;color:#e2e8f0">
<h2 style="color:#f87171">Unauthorized</h2>
<p>Set <code>DASHBOARD_SECRET</code> in your Railway env vars, then visit<br>
<code>/admin?secret=YOUR_SECRET</code></p></body></html>`);
  }

  const page   = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit  = 50;
  const offset = (page - 1) * limit;
  const search = req.query.search || null;
  const secret = req.query.secret;
  // status filter only applies to the bottom (unpaid) section
  const statusFilter = req.query.status || null;

  // ── Fetch paid transactions (all, no pagination) ──────────────────────────
  let paidData = { rows: [] };
  let unpaidData = { rows: [], total: 0 };
  let dbError = null;
  try {
    paidData   = await getAllTransactions({ limit: 500, offset: 0, status: 'paid', search });
    // unpaid = everything that isn't paid/reconciled, with optional status/search filter
    const unpaidStatus = statusFilter && statusFilter !== 'paid' && statusFilter !== 'reconciled'
      ? statusFilter : null;
    unpaidData = await getAllTransactions({
      limit, offset, search,
      status: unpaidStatus,
      excludeStatuses: unpaidStatus ? null : ['paid', 'reconciled']
    });
  } catch (err) {
    dbError = err.message;
  }

  // Paid totals
  let paidTotals = {};
  for (const t of paidData.rows) {
    const cur = t.currency || 'AUD';
    paidTotals[cur] = (paidTotals[cur] || 0) + (parseFloat(t.amount) || 0);
  }
  const pendingCount = (await pool.query("SELECT COUNT(*) FROM transactions WHERE status IN ('pending','initiated')").catch(()=>({rows:[{count:0}]}))).rows[0].count;
  const failedCount  = (await pool.query("SELECT COUNT(*) FROM transactions WHERE status = 'failed'").catch(()=>({rows:[{count:0}]}))).rows[0].count;

  const totalPages = Math.max(1, Math.ceil(unpaidData.total / limit));
  const isLive     = !TILL_BASE_URL.includes('test-gateway');

  const SC = {
    paid:             ['#c8e6d0','#1a4a28'],
    pending:          ['#e8dfc0','#4a3a08'],
    initiated:        ['#c8d8e8','#1a3050'],
    failed:           ['#e8c8c8','#4a1818'],
    amount_mismatch:  ['#ead4c0','#4a2808'],
    currency_mismatch:['#ead4c0','#4a2808'],
    cancelled:        ['#d8d8d8','#404040'],
    reconciled:       ['#c0e0d8','#0a3828'],
  };

  const esc   = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const badge = s => { const [bg,fg]=SC[s]||['#374151','#d1d5db']; return `<span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;background:${bg};color:${fg}">${s}</span>`; };
  const fmt   = iso => { if(!iso) return '—'; const d=new Date(iso); return d.toLocaleDateString('en-AU',{day:'2-digit',month:'short',year:'numeric'})+' '+d.toLocaleTimeString('en-AU',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); };
  const qs    = (o={}) => { const p=new URLSearchParams({secret,...(statusFilter?{status:statusFilter}:{}),...(search?{search}:{})}); Object.entries(o).forEach(([k,v])=>v!=null?p.set(k,v):p.delete(k)); return '?'+p.toString(); };

  const buildRows = (txns, prefix, showMarkPaid = false) => txns.map((t, i) => {
    const hasTill = !!t.tillUuid;
    const rowId   = `${prefix}-${i}`;
    const tillBtn = hasTill
      ? `<button onclick="loadTill('${esc(t.tillUuid)}','${rowId}')" id="${rowId}-btn" style="padding:4px 10px;background:#dde4ec;border:1px solid #a8b8cc;color:#2a3a58;border-radius:4px;font-size:11px;cursor:pointer;white-space:nowrap;font-family:inherit">Till Details</button>`
      : '';
    const markBtn = showMarkPaid
      ? `<button onclick="markPaid('${esc(t.txnId)}','${esc(t.amount||'')}','${rowId}')" id="${rowId}-markbtn" style="padding:4px 10px;background:#d0e8d4;border:1px solid #90c0a0;color:#1a4028;border-radius:4px;font-size:11px;cursor:pointer;white-space:nowrap;margin-top:4px;display:block;font-family:inherit">Mark Paid</button>`
      : '';
    const paidIndicator = !showMarkPaid
      ? `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;background:#d4ead8;border:1px solid #90c8a0;border-radius:4px;font-size:11px;color:#1a4a28;white-space:nowrap"><span style="width:6px;height:6px;border-radius:50%;background:#3a9060;display:inline-block;flex-shrink:0"></span>Payment successful</span>`
      : '';
    return `
  <tr id="${rowId}-main">
    <td><span style="font-family:monospace;font-size:11px;color:#1c1a17;white-space:nowrap">${esc(t.txnId)}</span></td>
    <td style="white-space:nowrap"><a href="https://${esc(SHOPIFY_STORE_DOMAIN)}/admin/orders/${esc(t.shopifyOrderId)}" target="_blank" style="color:#1a3a6a;text-decoration:none">#${esc(t.orderNumber)}</a></td>
    <td>${badge(t.status)}</td>
    <td style="white-space:nowrap;color:#1e2430">${t.amount ? `$${esc(t.amount)} <span style="color:#7a8090;font-size:11px">${esc(t.currency)}</span>` : '—'}</td>
    <td style="font-size:12px;color:#4a5568">${esc(t.customerEmail)}</td>
    <td style="font-size:11px;white-space:nowrap;color:#7a8090">${fmt(t.updatedAt)}</td>
    <td style="font-size:11px;color:#9a3a3a;max-width:160px;word-break:break-all">${esc(t.tillError)||''}</td>
    <td style="white-space:nowrap">${paidIndicator}${tillBtn}${markBtn}</td>
  </tr>
  <tr id="${rowId}-detail" style="display:none">
    <td colspan="8" style="padding:0">
      <div id="${rowId}-content" style="background:#d0d9e6;border-left:2px solid #8aa0be;padding:14px 18px;font-size:12px;color:#1e2430"></div>
    </td>
  </tr>`;
  }).join('');

  const paidRows   = buildRows(paidData.rows,   'p');
  const unpaidRows = buildRows(unpaidData.rows, 'u', true);

  const unpaidStatusOptions = ['','pending','initiated','failed','amount_mismatch','currency_mismatch','cancelled'];
  const filterSelect = unpaidStatusOptions.map(s =>
    `<option value="${s}" ${statusFilter===s||(!statusFilter&&s==='')?'selected':''}>${s||'All non-paid'}</option>`
  ).join('');

  const totalsHtml = Object.entries(paidTotals).map(([cur, amt]) =>
    `<div class="stat"><div class="stat-val">$${amt.toFixed(2)}</div><div class="stat-lbl">${cur} collected · ${paidData.rows.length} orders</div></div>`
  ).join('') || `<div class="stat"><div class="stat-val" style="color:#344155">$0.00</div><div class="stat-lbl">AUD collected</div></div>`;

  const prevDisabled = page <= 1;
  const nextDisabled = page >= totalPages;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HOCS · Payments</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Aptos','Segoe UI',Inter,system-ui,sans-serif;font-weight:400;background:#0e1118;color:#c8cdd6;min-height:100vh;padding:32px 24px;font-size:13px;line-height:1.5}
h1{font-size:18px;font-weight:500;color:#a8b8cc;margin-bottom:3px;letter-spacing:-0.01em}
.sub{color:#4a5568;font-size:12px;margin-bottom:0}
.env-badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:10px;font-weight:500;margin-left:8px;vertical-align:middle;background:${isLive?'#2e1515':'#132413'};color:${isLive?'#b87c7c':'#7aaa88'};border:1px solid ${isLive?'#5c2a2a':'#2a5234'}}
.section{margin-bottom:44px}
.section-hdr{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid}
.section-hdr.green{border-color:#2a4a35}.section-hdr.grey{border-color:#1e2a38}
.section-title{font-size:13px;font-weight:500}
.section-title.green{color:#7aaa88}.section-title.grey{color:#6b7a8d}
.section-count{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:400}
.section-count.green{background:#132413;color:#7aaa88;border:1px solid #2a5234}.section-count.grey{background:#161e29;color:#4a5b6d;border:1px solid #1e2d3d}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.stat{background:#141b24;border:1px solid #1e2a38;border-radius:12px;padding:14px 20px;min-width:130px}
.stat-val{font-size:20px;font-weight:500;color:#a8c0a0}.stat-lbl{font-size:11px;color:#4a5568;margin-top:3px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.toolbar input,.toolbar select{background:#141b24;border:1px solid #1e2a38;color:#c8cdd6;padding:7px 14px;border-radius:10px;font-size:12px;outline:none;font-family:inherit}
.toolbar input:focus,.toolbar select:focus{border-color:#3a5a7a}
.toolbar button{padding:7px 20px;background:#1a2d42;color:#7a9dbf;border:1px solid #253a52;border-radius:10px;font-size:12px;font-weight:400;cursor:pointer;font-family:inherit}
.toolbar button:hover{background:#1e3550;color:#9ab8d4}
.wrap{overflow-x:auto;border-radius:14px;border:1px solid #1a2436;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:12px}
thead tr{background:#13192a}
thead tr th:first-child{border-top-left-radius:14px}
thead tr th:last-child{border-top-right-radius:14px}
th{padding:10px 14px;text-align:left;color:#5a7090;font-weight:500;white-space:nowrap;border-bottom:1px solid #1a2436;font-size:11px;text-transform:uppercase;letter-spacing:0.04em}
tbody tr{background:#dce3ed}
td{padding:10px 14px;border-bottom:1px solid #c8d0dc;vertical-align:middle;color:#2a3040}
tbody tr:last-child td{border-bottom:none}
tbody tr:last-child td:first-child{border-bottom-left-radius:14px}
tbody tr:last-child td:last-child{border-bottom-right-radius:14px}
tbody tr:hover td{background:#d0d9e6}
.pagination{display:flex;gap:8px;align-items:center;margin-top:16px;font-size:12px;color:#4a5568}
.pagination a{padding:5px 14px;background:#141b24;color:#6a8aaa;border-radius:99px;text-decoration:none;border:1px solid #1e2a38}
.pagination a:hover{background:#1a2436}
.pagination .cur{padding:5px 14px;background:#1a2d42;color:#7a9dbf;border-radius:99px;border:1px solid #253a52}
.dberr{background:#1a1010;border:1px solid #4a2020;color:#b87c7c;padding:14px;border-radius:12px;margin-bottom:20px;font-size:12px}
.empty{text-align:center;padding:40px;color:#344155;font-size:13px}
.till-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:10px}
.till-field{background:#111820;border-radius:10px;padding:9px 13px;border:1px solid #1a2436}
.till-field-lbl{font-size:10px;color:#4a5568;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.till-field-val{font-size:12px;font-weight:400;color:#c8cdd6;word-break:break-all}
.till-ok{color:#7aaa88}.till-err{color:#b87c7c}
</style>
</head>
<body>
<div style="display:flex;align-items:center;gap:16px;margin-bottom:28px">
  <img src="/HOC.png"
       alt="High on Chapel"
       style="height:56px;width:56px;object-fit:contain;border-radius:6px;flex-shrink:0;mix-blend-mode:screen">
  <div>
    <h1>HOCS Payments <span class="env-badge">${isLive?'LIVE':'SANDBOX'}</span></h1>
    <div class="sub" style="margin-bottom:0">${esc(SHOPIFY_STORE_DOMAIN)}</div>
  </div>
</div>
${dbError?`<div class="dberr">Database error: ${esc(dbError)}</div>`:''}

<!-- ═══ SECTION 1: PAID ═══════════════════════════════════════════════════ -->
<div class="section">
  <div class="section-hdr grey">
    <span class="section-title grey">Confirmed Payments</span>
    <span class="section-count grey">${paidData.rows.length} orders</span>
  </div>
  <div class="stats">
    ${totalsHtml}
  </div>
  <div class="wrap">
  <table>
  <thead><tr>
    <th>Transaction ID</th><th>Order</th><th>Status</th><th>Amount</th>
    <th>Customer</th><th>Paid At</th><th>Error</th><th></th>
  </tr></thead>
  <tbody>
  ${paidRows || `<tr><td colspan="8" class="empty">No confirmed payments yet.</td></tr>`}
  </tbody>
  </table>
  </div>
</div>

<!-- ═══ SECTION 2: UNPAID / INCOMPLETE ══════════════════════════════════ -->
<div class="section">
  <div class="section-hdr grey" style="flex-wrap:wrap;gap:10px">
    <span class="section-title grey">Incomplete / Pending</span>
    <span class="section-count grey">${pendingCount} pending · ${failedCount} failed</span>
    <button onclick="reconcileAll()" id="reconcile-btn" style="margin-left:auto;padding:6px 16px;background:#1e1a2e;border:1px solid #362a52;color:#8a7abf;border-radius:5px;font-size:12px;font-weight:400;cursor:pointer;font-family:inherit">Reconcile All with Till</button>
  </div>
  <div id="reconcile-result" style="display:none;margin-bottom:16px;padding:14px;background:#111820;border:1px solid #1e2a38;border-radius:6px;font-size:12px"></div>
  <form class="toolbar" method="GET" action="/admin">
    <input type="hidden" name="secret" value="${esc(secret)}">
    <input type="text" name="search" placeholder="Search order, email, UUID…" value="${esc(search||'')}" style="min-width:220px">
    <select name="status">${filterSelect}</select>
    <button type="submit">Filter</button>
    ${(search||statusFilter)?`<a href="?secret=${esc(secret)}" style="color:#4a5568;font-size:12px;text-decoration:none">Clear</a>`:''}
  </form>
  <div class="wrap">
  <table>
  <thead><tr>
    <th>Transaction ID</th><th>Order</th><th>Status</th><th>Amount</th>
    <th>Customer</th><th>Created</th><th>Error</th><th></th>
  </tr></thead>
  <tbody>
  ${unpaidRows || `<tr><td colspan="8" class="empty">No incomplete transactions.</td></tr>`}
  </tbody>
  </table>
  </div>
  <div class="pagination">
    ${prevDisabled?`<span style="padding:5px 13px;color:#2a3a4a">← Prev</span>`:`<a href="${qs({page:page-1})}">← Prev</a>`}
    <span class="cur">Page ${page} of ${totalPages}</span>
    ${nextDisabled?`<span style="padding:5px 13px;color:#2a3a4a">Next →</span>`:`<a href="${qs({page:page+1})}">Next →</a>`}
    <span style="margin-left:8px;color:#344155">Showing ${offset+1}–${Math.min(offset+limit,unpaidData.total)} of ${unpaidData.total}</span>
  </div>
</div>

<script>
const SECRET = ${JSON.stringify(secret)};

async function reconcileAll() {
  const btn = document.getElementById('reconcile-btn');
  const out = document.getElementById('reconcile-result');
  btn.textContent = 'Checking Till…'; btn.disabled = true;
  out.style.display = 'block';
  out.innerHTML = '<span style="color:#6a8aaa">Querying Till for all pending transactions… this may take 10–30 seconds.</span>';
  try {
    const r = await fetch('/admin/api/reconcile-all?secret='+encodeURIComponent(SECRET), {method:'POST'});
    const d = await r.json();
    if (!r.ok) { out.innerHTML='<span style="color:#b87c7c">Error: '+escHtml(d.error||'Unknown')+'</span>'; return; }

    const fixed   = d.results.filter(x=>x.outcome==='marked_paid');
    const notPaid = d.results.filter(x=>x.outcome==='not_paid');
    const errors  = d.results.filter(x=>x.outcome==='error'||x.outcome==='shopify_update_failed');

    let html = \`<div style="margin-bottom:10px;font-size:12px">\`;
    html += fixed.length
      ? \`<span style="color:#7aaa88">\${fixed.length} payment\${fixed.length>1?'s':''} recovered and marked paid in Shopify.</span>\`
      : \`<span style="color:#8a7a5a">No new payments found — \${d.checked} transactions checked.</span>\`;
    html += \`</div>\`;

    if (fixed.length) {
      html += \`<div style="margin-bottom:8px;color:#5a8a6a;font-size:12px">Recovered orders:</div>\`;
      html += \`<table style="width:100%;font-size:12px;border-collapse:collapse">\`;
      html += \`<tr><th style="text-align:left;padding:4px 10px;color:#4a5568;font-weight:500">Order</th><th style="text-align:left;padding:4px 10px;color:#4a5568;font-weight:500">Shopify Amount</th><th style="text-align:left;padding:4px 10px;color:#4a5568;font-weight:500">Till Charged</th><th style="text-align:left;padding:4px 10px;color:#4a5568;font-weight:500">Surcharge</th></tr>\`;
      for (const x of fixed) {
        html += \`<tr>
          <td style="padding:4px 10px;color:#c8cdd6">#\${escHtml(x.orderNumber)}</td>
          <td style="padding:4px 10px;color:#6b7a8d">$\${escHtml(x.shopifyAmount)}</td>
          <td style="padding:4px 10px;color:#7aaa88">$\${escHtml(x.tillAmount)}</td>
          <td style="padding:4px 10px;color:#8a7a5a">+$\${escHtml(x.surcharge)}</td>
        </tr>\`;
      }
      html += \`</table>\`;
    }
    if (errors.length) {
      html += \`<div style="margin-top:8px;color:#b87c7c;font-size:12px">\${errors.length} error(s): \${errors.map(x=>x.txnId+': '+escHtml(x.error||x.outcome)).join(', ')}</div>\`;
    }
    if (fixed.length) {
      html += \`<div style="margin-top:10px;color:#344155;font-size:11px">Refresh the page to see the updated paid section.</div>\`;
    }
    out.innerHTML = html;
  } catch(e) {
    out.innerHTML = '<span style="color:#b87c7c">Request failed: '+escHtml(e.message)+'</span>';
  } finally {
    btn.textContent = 'Reconcile All with Till'; btn.disabled = false;
  }
}

async function loadTill(uuid, rowId) {
  const btn = document.getElementById(rowId+'-btn');
  const detailRow = document.getElementById(rowId+'-detail');
  const content   = document.getElementById(rowId+'-content');
  if (detailRow.style.display !== 'none') { detailRow.style.display='none'; btn.textContent='Till Details'; return; }

  btn.textContent='Loading…'; btn.disabled=true;
  try {
    const r = await fetch('/admin/api/till/'+encodeURIComponent(uuid)+'?secret='+encodeURIComponent(SECRET));
    const d = await r.json();
    content.innerHTML = (!r.ok||d.error) ? '<span style="color:#b87c7c">Error: '+escHtml(d.error||'Unknown')+'</span>' : renderTill(d);
  } catch(e) { content.innerHTML='<span style="color:#b87c7c">Fetch failed: '+escHtml(e.message)+'</span>'; }
  detailRow.style.display=''; btn.textContent='Hide Details'; btn.disabled=false;
}
function renderTill(d) {
  const result  = d.result||d.status||'—';
  const isOk    = result==='OK'||result==='SUCCESS';
  const card    = d.card||d.paymentInstrument||d.cardData||{};
  const cardNum = card.lastFourDigits||card.maskedPan||card.last4||'—';
  const fields  = [
    ['Till Result',    \`<span class="\${isOk?'till-ok':'till-err'}">\${escHtml(result)}</span>\`],
    ['Return Type',    escHtml(d.returnType||'—')],
    ['Till Charged (incl. surcharge)', d.amount!=null?\`<span style="color:#7aaa88">$\${parseFloat(d.amount).toFixed(2)} \${escHtml(d.currency||'')}</span>\`:'—'],
    ['Card Number',    cardNum!=='—'?\`•••• •••• •••• \${escHtml(cardNum)}\`:'—'],
    ['Card Type',      escHtml(card.type||card.brand||card.cardType||'—')],
    ['Card Holder',    escHtml(card.cardHolder||card.holderName||'—')],
    ['Card Expiry',    (card.expiryMonth&&card.expiryYear)?card.expiryMonth+'/'+card.expiryYear:'—'],
    ['Settlement Date',escHtml(d.settlementDate||d.settledAt||'—')],
    ['Transaction Date',escHtml(d.createdAt||d.timestamp||'—')],
    ['Descriptor',     escHtml(d.descriptor||d.description||'—')],
    ['Till UUID',      \`<span style="font-family:monospace;font-size:11px">\${escHtml(d.uuid||d.referenceUuid||'—')}</span>\`],
  ];
  const grid = fields.map(([l,v])=>\`<div class="till-field"><div class="till-field-lbl">\${l}</div><div class="till-field-val">\${v}</div></div>\`).join('');
  let errHtml='';
  if(Array.isArray(d.errors)&&d.errors.length){
    errHtml='<div style="margin-top:8px;padding:10px;background:#1a1010;border-radius:5px;border:1px solid #4a2020">'+d.errors.map(e=>\`<div style="color:#b87c7c;font-size:12px">[\${escHtml(e.errorCode||'')}] \${escHtml(e.errorMessage||e.message||'')} \${e.adapterMessage?'— '+escHtml(e.adapterMessage):''}</div>\`).join('')+'</div>';
  }
  const rt=(d.returnType||'').toUpperCase(), rs=(d.result||'').toUpperCase();
  const pending=(rt==='REDIRECT'||rs==='PENDING'||(!rs&&!rt))?'<div style="margin-bottom:10px;padding:10px;background:#131e10;border:1px solid #2a3a20;border-radius:5px;color:#7aaa88;font-size:12px">Payment not yet completed by customer.</div>':'';
  const raw=\`<details style="margin-top:10px"><summary style="cursor:pointer;font-size:11px;color:#344155">Raw Till response</summary><pre style="margin-top:6px;padding:10px;background:#0a0e14;border-radius:5px;font-size:10px;color:#4a5568;overflow-x:auto;white-space:pre-wrap;word-break:break-all">\${escHtml(JSON.stringify(d,null,2))}</pre></details>\`;
  return \`\${pending}<div class="till-grid">\${grid}</div>\${errHtml}\${raw}\`;
}
async function markPaid(txnId, storedAmount, rowId) {
  const input = prompt(
    'Enter the amount actually received (check your bank / Till merchant portal).\nStored amount: $' + (storedAmount || '?'),
    storedAmount || ''
  );
  if (input === null) return; // cancelled
  const amount = input.trim();
  if (!amount || isNaN(parseFloat(amount))) {
    alert('Invalid amount — please enter a number like 45.00');
    return;
  }
  const btn = document.getElementById(rowId + '-markbtn');
  if (btn) { btn.textContent = 'Marking…'; btn.disabled = true; }
  try {
    const r = await fetch('/admin/api/mark-paid/' + encodeURIComponent(txnId) + '?secret=' + encodeURIComponent(SECRET), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount })
    });
    const d = await r.json();
    if (!r.ok) {
      if (btn) { btn.textContent = 'Mark Paid'; btn.disabled = false; }
      alert('Error: ' + escHtml(d.error || 'Unknown error'));
      return;
    }
    // Success — update the row visually
    if (btn) {
      btn.textContent = 'Paid ✓';
      btn.disabled = true;
      btn.style.background = '#0e1c14';
      btn.style.color = '#5a8a6a';
      btn.style.borderColor = '#2a5234';
      btn.style.cursor = 'default';
    }
    // Also update status cell if present
    const row = document.getElementById(rowId);
    if (row) {
      const cells = row.querySelectorAll('td');
      if (cells[2]) cells[2].innerHTML = '<span style="color:#7aaa88">paid</span>';
    }
  } catch(e) {
    if (btn) { btn.textContent = 'Mark Paid'; btn.disabled = false; }
    alert('Request failed: ' + escHtml(e.message));
  }
}

function escHtml(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body>
</html>`);
});

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
  const hppTag = r.hppCompleted === true ? ' | hpp=done' : r.hppCompleted === false ? ' | hpp=FAILED' : '';
  let remark;
  if (needsHPP && !success){
    remark = uuid ? \`uuid=\${uuid} | Complete HPP first, then re-run\` : 'Run HPP first';
  } else if (uuid && success) {
    remark = \`uuid=\${uuid} | success=true\${hppTag}\`;
  } else if (uuid && !success) {
    remark = \`uuid=\${uuid} | ERROR: \${errInfo || 'see raw'}\${hppTag}\`;
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
    { label:'Tests 1.0–1.h · Debit', startIdx:0, count:10 },
    { label:'Tests 2.0–2.h · Preauth', startIdx:10, count:10 },
    { label:'Test 3 · Capture / Test 4 · Void', startIdx:20, count:3 },
    { label:'Test 5 · Register / Debit from Register / Deregister', startIdx:23, count:5 },
    { label:'Tests 6–7 · Refund', startIdx:28, count:2 },
    { label:'Test 8 · Reversal', startIdx:30, count:1 },
    { label:'Test 9 · Incremental Auth', startIdx:31, count:1 },
    { label:'Test 10 · Negative (Declined)', startIdx:32, count:4 },
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
  setStatus('Fully automated: creating transactions, auto-completing HPP pages, running downstream tests… ~5 minutes.');
  startTimer();
  showProgress('Running all 36 tests (HPP auto-completed)…', 0);
  const estMs = 260000; const t0 = Date.now();
  const pInt = setInterval(()=>{ const pct=Math.min(((Date.now()-t0)/estMs)*95,95); showProgress('Running all 36 tests (HPP auto-completed)…',pct); },400);
  try {
    const resp = await fetch('/api/cert/run-all');
    clearInterval(pInt); showProgress('Processing results…',100);
    const data = JSON.parse(await resp.text());
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
  await sleep(5000);
  stepProgress('Debit CARDONFILE (1.c)');
  const cof1c = debitInitialUuid   ? await post('/api/till/debit',   {transactionIndicator:'CARDONFILE',                   referenceUuid:debitInitialUuid,   amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 1.c'}) : {success:false,raw:{error:'No initial debit uuid — complete HPP on row 1 (1.a) first'}};
  await sleep(5000);
  stepProgress('Debit CARDONFILE-MI (1.d)');
  const cof1d = debitInitialUuid   ? await post('/api/till/debit',   {transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', referenceUuid:debitInitialUuid,   amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 1.d'}) : {success:false,raw:{error:'No initial debit uuid — complete HPP on row 1 (1.a) first'}};
  await sleep(5000);
  stepProgress('Preauth RECURRING (2.b)');
  const rec2b = preauthInitialUuid ? await post('/api/till/preauth', {transactionIndicator:'RECURRING',                    referenceUuid:preauthInitialUuid, amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 2.b'}) : {success:false,raw:{error:'No initial preauth uuid — complete HPP on row 9 (2.a) first'}};
  await sleep(5000);
  stepProgress('Preauth CARDONFILE (2.c)');
  const cof2c = preauthInitialUuid ? await post('/api/till/preauth', {transactionIndicator:'CARDONFILE',                   referenceUuid:preauthInitialUuid, amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 2.c'}) : {success:false,raw:{error:'No initial preauth uuid — complete HPP on row 9 (2.a) first'}};
  await sleep(5000);
  stepProgress('Preauth CARDONFILE-MI (2.d)');
  const cof2d = preauthInitialUuid ? await post('/api/till/preauth', {transactionIndicator:'CARDONFILE-MERCHANT-INITIATED', referenceUuid:preauthInitialUuid, amount:'1.00',currency:'AUD',merchantTransactionId:t(),descriptor:'HOC Cert 2.d'}) : {success:false,raw:{error:'No initial preauth uuid — complete HPP on row 9 (2.a) first'}};
  await sleep(5000);

  // ── Capture / Void / Refund / Reversal / Incremental (needs 1.e / 2.e HPP completed first)
  stepProgress('Capture full (3)');
  const cap  = preauthUuid ? await post('/api/till/capture/'+preauthUuid,  {amount:'1.00',currency:'AUD',merchantTransactionId:t()}) : {success:false,raw:{error:'No preauth uuid'}};
  await sleep(5000);
  stepProgress('Capture partial (3a)');
  const capP = (preauthUuid2||preauthUuid) ? await post('/api/till/capture/'+(preauthUuid2||preauthUuid),  {amount:'0.50',currency:'AUD',merchantTransactionId:t()}) : {success:false,raw:{error:'No preauth uuid (complete HPP on 2.f)'}};
  await sleep(5000);
  stepProgress('Void preauth (4)');
  const vd   = (preauthUuid3||preauthUuid) ? await post('/api/till/void/'+(preauthUuid3||preauthUuid),     {}) : {success:false,raw:{error:'No preauth uuid (complete HPP on 2.g)'}};
  await sleep(5000);
  stepProgress('Deregister (5.a)');
  const dereg = regId5 ? await post('/api/till/deregister', {referenceUuid:regId5, merchantTransactionId:t()}) : {success:false,raw:{error:'No register uuid — complete HPP on Register (5) first'}};
  await sleep(5000);
  stepProgress('Full refund (6)');
  const ref  = debitUuid   ? await post('/api/till/refund/'+debitUuid,     {amount:'1.00',currency:'AUD',reason:'Customer refund request'}) : {success:false,raw:{error:'No debit uuid'}};
  await sleep(5000);
  stepProgress('Partial refund (7)');
  const refP = (debitUuid2||debitUuid)   ? await post('/api/till/refund/'+(debitUuid2||debitUuid),     {amount:'0.50',currency:'AUD',reason:'Partial refund'}) : {success:false,raw:{error:'No debit uuid (complete HPP on 1.f)'}};
  await sleep(5000);
  stepProgress('Reversal (8)');
  const rev  = (debitUuid3||debitUuid)   ? await post('/api/till/refund/'+(debitUuid3||debitUuid),   {amount:'1.00',currency:'AUD',reason:'Reversal (full refund)',merchantTransactionId:t()}) : {success:false,raw:{error:'No debit uuid (complete HPP on 1.g)'}};
  await sleep(5000);
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
    '2.b – Preauth RECURRING': 11, '2.c – Preauth CARDONFILE': 12, '2.d – Preauth CARDONFILE-MERCHANT-INIT': 13,
    '3 – Capture full': 20, '3.a – Capture partial': 21, '4 – Void preauth': 22,
    '5.a – Deregister': 27,
    '6 – Full refund': 28, '7 – Partial refund': 29, '8 – Reversal': 30, '9 – Incremental auth': 31
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
// Test 8 — debit reversal via refund (void only works on preauthorize)

app.post('/api/till/reversal/:referenceUuid', async (req, res) => {
  try {
    const { referenceUuid } = req.params;
    const { amount = '1.00', currency = 'AUD', reason = 'Reversal (full refund)' } = req.body || {};
    const payload = {
      merchantTransactionId: `HOC-REV-${Date.now()}`,
      referenceUuid,
      amount,
      currency,
      description: reason
    };
    const result = await callTillAPI('POST', `/api/v3/transaction/${TILL_API_KEY}/refund`, payload);
    logger.info('[CERT] Reversal (refund)', { referenceUuid, amount, status: result.status });
    res.json({ success: result.body?.success ?? false, ...result.body, _httpStatus: result.status });
  } catch (err) {
    logger.error('[CERT] Reversal (refund) error', { error: err.message });
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

function renderPayPortalRecovery(res, shopifyOrderId, email) {
  const pollUrl = `/api/payment-redirect-by-shopify-id/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}`;
  const retryUrl = `/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}`;
  return res.status(200).send(payPortalHTML(
    'Finishing Your Payment',
    `<p>Your secure payment session has already been created and may still be processing.</p>
     <p>Please wait here while we reconnect you or confirm the payment result.</p>
     <div class="spinner"></div>
     <p class="small">If you already completed the payment in another tab or window, this page will update automatically.</p>`,
    true,
    pollUrl,
    retryUrl
  ));
}

// ═════════════════════════════════════════════════════════════════════════════
// ENDPOINT: GET /pay/:shopifyOrderId
// ═════════════════════════════════════════════════════════════════════════════
// Payment portal page — customers land here from the checkout extension.
// If a Till redirect URL already exists, immediately 302-redirects to it.
// If NOT (webhook hasn't fired yet), this route fetches the order from
// Shopify Admin API and initiates the Till debit itself, then redirects.
//
// This eliminates the race condition where the customer arrives before the
// webhook has been processed.
//
// Query params:
//   ?email=customer@example.com   (required — must match order email)

app.get('/pay/:shopifyOrderId', async (req, res) => {
  const shopifyOrderId = req.params.shopifyOrderId.trim();
  const email = (req.query.email || '').trim().toLowerCase();

  if (!shopifyOrderId) {
    return res.status(400).send(payPortalHTML(
      'Missing Information',
      '<p>Order details are missing. Please return to your order confirmation email and try again.</p>',
      false
    ));
  }

  logger.info('Pay portal accessed', { shopifyOrderId, hasEmail: !!email });

  let txn = await getTransactionByShopifyOrderId(shopifyOrderId);

  // ── Already paid ──
  if (txn && txn.status === 'paid') {
    return res.redirect(302, SUCCESS_URL);
  }

  // ── Email mismatch ──
  if (txn && email && txn.customerEmail && email !== txn.customerEmail.trim().toLowerCase()) {
    logger.warn('Pay portal email mismatch', { shopifyOrderId, provided: email });
    return res.status(403).send(payPortalHTML(
      'Access Denied',
      '<p>The email address does not match this order. Please use the link from your order confirmation.</p>',
      false
    ));
  }

  // ── Redirect URL ready — send them straight to Till ──
  if (txn && txn.status === 'initiated' && txn.redirectUrl) {
    logger.info('Pay portal redirecting to Till HPP (existing)', { shopifyOrderId, txnId: txn.txnId });
    return res.redirect(302, txn.redirectUrl);
  }

  if (txn && txn.status === 'pending' && txn.tillError === 'duplicate_transaction_in_progress') {
    logger.info('Pay portal — duplicate Till transaction already in progress, switching to recovery flow', {
      shopifyOrderId,
      txnId: txn.txnId
    });
    return renderPayPortalRecovery(res, shopifyOrderId, email);
  }

  // ── Fresh checkout race: give the webhook-created transaction a chance to land ──
  if (!txn) {
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      logger.info('Pay portal — waiting for webhook transaction', { shopifyOrderId, attempt });
      await new Promise((resolve) => setTimeout(resolve, 1000));
      txn = await getTransactionByShopifyOrderId(shopifyOrderId);

      if (txn && txn.status === 'paid') {
        return res.redirect(302, SUCCESS_URL);
      }

      if (txn && email && txn.customerEmail && email !== txn.customerEmail.trim().toLowerCase()) {
        logger.warn('Pay portal email mismatch after webhook wait', { shopifyOrderId, provided: email });
        return res.status(403).send(payPortalHTML(
          'Access Denied',
          '<p>The email address does not match this order. Please use the link from your order confirmation.</p>',
          false
        ));
      }

      if (txn && txn.status === 'initiated' && txn.redirectUrl) {
        logger.info('Pay portal redirecting to Till HPP after webhook wait', { shopifyOrderId, txnId: txn.txnId, attempt });
        return res.redirect(302, txn.redirectUrl);
      }

      if (txn && txn.status === 'pending' && txn.tillError === 'duplicate_transaction_in_progress') {
        logger.info('Pay portal — duplicate Till transaction detected after webhook wait, switching to recovery flow', {
          shopifyOrderId,
          txnId: txn.txnId,
          attempt
        });
        return renderPayPortalRecovery(res, shopifyOrderId, email);
      }
    }

    logger.info('Pay portal — webhook transaction still unavailable after wait, switching to recovery flow', {
      shopifyOrderId
    });
    return renderPayPortalRecovery(res, shopifyOrderId, email);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // No transaction yet (webhook hasn't fired). Initiate payment directly.
  // ═══════════════════════════════════════════════════════════════════════
  try {
    logger.info('Pay portal — no transaction found, initiating payment directly', { shopifyOrderId });

    // ── Fetch order from Shopify Admin API (retry once after 3s if first attempt fails) ──
    let orderRes = await shopifyAdminAPI('GET', `/orders/${shopifyOrderId}.json`);

    if ((!orderRes.body || !orderRes.body.order) && orderRes.status !== 401) {
      // Order may not be fully committed yet — wait and retry once
      logger.info('Pay portal — order not found on first attempt, retrying in 3s', {
        shopifyOrderId, status: orderRes.status, responseBody: JSON.stringify(orderRes.body).substring(0, 300)
      });
      await new Promise(r => setTimeout(r, 3000));

      // Check if webhook processed it while we waited
      const txnRetry = await getTransactionByShopifyOrderId(shopifyOrderId);
      if (txnRetry && txnRetry.status === 'initiated' && txnRetry.redirectUrl) {
        logger.info('Pay portal — webhook arrived during retry wait', { shopifyOrderId, txnId: txnRetry.txnId });
        return res.redirect(302, txnRetry.redirectUrl);
      }
      if (txnRetry && txnRetry.status === 'paid') {
        return res.redirect(302, SUCCESS_URL);
      }

      orderRes = await shopifyAdminAPI('GET', `/orders/${shopifyOrderId}.json`);
    }

    if (!orderRes.body || !orderRes.body.order) {
      logger.error('Pay portal — failed to fetch order from Shopify after retry', {
        shopifyOrderId, status: orderRes.status,
        responseBody: JSON.stringify(orderRes.body).substring(0, 500)
      });

      // Fall back to polling page — the webhook will eventually fire
      const pollUrl = `/api/payment-redirect-by-shopify-id/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}`;
      return res.status(200).send(payPortalHTML(
        'Preparing Your Payment',
        `<p>We&rsquo;re connecting you to our secure payment gateway.<br>This usually takes just a few seconds.</p>
         <div class="spinner"></div>
         <p class="small">If you are not redirected automatically, <a href="/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}">click here to retry</a>.</p>`,
        true,
        pollUrl,
        `/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}`
      ));
    }

    const order = orderRes.body.order;

    // ── Verify email matches the order ──
    const orderEmail = (order.email || '').trim().toLowerCase();
    if (email && orderEmail && email !== orderEmail) {
      logger.warn('Pay portal email mismatch (from Shopify)', { shopifyOrderId, provided: email, orderEmail });
      return res.status(403).send(payPortalHTML(
        'Access Denied',
        '<p>The email address does not match this order.</p>',
        false
      ));
    }

    // ── Skip if order is already paid in Shopify ──
    if (order.financial_status === 'paid' || order.financial_status === 'partially_paid') {
      logger.info('Pay portal — order already paid in Shopify', { shopifyOrderId, financialStatus: order.financial_status });
      return res.redirect(302, SUCCESS_URL);
    }

    const orderId     = order.id;
    const orderNumber = order.order_number || order.name;
    const totalPrice  = order.total_price;
    const currency    = order.currency || 'AUD';
    const txnId       = `HOC-${orderNumber}`;

    // ── Idempotency: check if transaction was created between our first check and now ──
    const existingTxn = await getTransaction(txnId);
    if (existingTxn && existingTxn.status === 'initiated' && existingTxn.redirectUrl) {
      logger.info('Pay portal — transaction appeared (race resolved)', { shopifyOrderId, txnId });
      return res.redirect(302, existingTxn.redirectUrl);
    }
    if (existingTxn && existingTxn.status === 'paid') {
      return res.redirect(302, SUCCESS_URL);
    }

    // ── Build customer data from Shopify order ──
    const billing  = order.billing_address || {};
    const customer = order.customer || {};
    const ip       = order.browser_ip || order.client_details?.browser_ip || req.ip || '0.0.0.0';

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

    // ── Build debit request with 3DS MANDATORY ──
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
      extraData: { '3dsecure': 'MANDATORY' },
      threeDSecureData: {
        '3dsecure':                      'MANDATORY',
        channel:                         '02',
        authenticationIndicator:         '01',
        cardholderAuthenticationMethod:  '01',
        challengeIndicator:              '02'
      }
    };

    // ── Save pending transaction ──
    await saveTransaction({
      txnId,
      status: 'pending',
      shopifyOrderId: String(orderId),
      orderNumber: String(orderNumber),
      amount: totalPrice,
      currency,
      customerEmail: tillCustomer.email
    });

    // ── Call Till Debit API ──
    const tillRes = await callTillAPI(
      'POST',
      `/api/v3/transaction/${TILL_API_KEY}/debit`,
      debitPayload
    );

    if (tillRes.body && tillRes.body.success) {
      const tillUuid    = tillRes.body.uuid;
      const purchaseId  = tillRes.body.purchaseId;
      const redirectUrl = tillRes.body.redirectUrl;

      logger.info('Pay portal — Till debit initiated directly', {
        shopifyOrderId, txnId, tillUuid,
        hasRedirectUrl: !!redirectUrl
      });

      await saveTransaction({
        txnId,
        status: 'initiated',
        tillUuid,
        purchaseId,
        redirectUrl
      });

      if (redirectUrl) {
        return res.redirect(302, redirectUrl);
      }

      // Till returned success but no redirect URL (unusual)
      return res.status(200).send(payPortalHTML(
        'Payment Processing',
        '<p>Your payment is being set up. Please wait a moment.</p><div class="spinner"></div>',
        true,
        `/api/payment-redirect-by-shopify-id/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}`,
        `/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}`
      ));
    }

    // ── Till returned an error ──
    const tillError = getTillErrorDetails(tillRes.body);
    const isDuplicateTxn = String(tillError.errorCode) === '3004';
    logger.error('Pay portal — Till debit failed', { shopifyOrderId, txnId, tillError });

    await saveTransaction({
      txnId,
      status: isDuplicateTxn ? 'pending' : 'failed',
      tillError: isDuplicateTxn
        ? 'duplicate_transaction_in_progress'
        : tillRes.rawBody?.substring(0, 500)
    });

    if (isDuplicateTxn) {
      logger.warn('Pay portal — duplicate Till transaction detected, switching to recovery flow', {
        shopifyOrderId,
        txnId,
        errorCode: tillError.errorCode
      });
      return renderPayPortalRecovery(res, shopifyOrderId, email);
    }

    return res.status(502).send(payPortalHTML(
      'Payment Unavailable',
      '<p>We could not connect to the payment gateway. Please try again in a moment or contact us for assistance.</p>'
        + `<p><a href="/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}">Try Again</a></p>`,
      false
    ));

  } catch (err) {
    logger.error('Pay portal — unexpected error', { shopifyOrderId, error: err.message, stack: err.stack });
    return res.status(500).send(payPortalHTML(
      'Something Went Wrong',
      '<p>An unexpected error occurred. Please try again or contact us.</p>'
        + `<p><a href="/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(email)}">Try Again</a></p>`,
      false
    ));
  }
});

/**
 * Generates the payment portal HTML page.
 * Kept inline to avoid extra dependencies — just a branded loading/redirect page.
 */
function payPortalHTML(title, bodyContent, showPoll, pollUrl, reloadUrl) {
  const pollScript = showPoll ? `
    <script>
      (function() {
        var attempts = 0, max = 30;
        function poll() {
          if (++attempts > max) {
            document.getElementById('msg').innerHTML =
              '<p>Taking longer than expected. <a href="${reloadUrl}">Tap here to retry</a>.</p>';
            return;
          }
          fetch('${pollUrl}', { headers: { Accept: 'application/json' } })
            .then(function(r) { return r.json(); })
            .then(function(d) {
              if (d.status === 'ready' && d.redirectUrl) {
                window.location.replace(d.redirectUrl);
              } else if (d.status === 'paid') {
                window.location.replace('${SUCCESS_URL}');
              } else {
                setTimeout(poll, 2000);
              }
            })
            .catch(function() { setTimeout(poll, 3000); });
        }
        setTimeout(poll, 1500);
      })();
    </script>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} — High on Chapel</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      background:#132b38;color:#c1f9f9;display:flex;align-items:center;justify-content:center;
      min-height:100vh;text-align:center;padding:1.5rem}
    .card{max-width:480px;width:100%;background:#082738;
      border:1px solid rgba(193,249,249,0.18);border-radius:28px;padding:3rem 2.5rem;
      box-shadow:0 24px 60px rgba(0,0,0,0.28)}
    .logo{font-size:1.5rem;font-weight:700;letter-spacing:.18em;margin-bottom:.3rem;
      color:#c1f9f9;text-transform:uppercase}
    .subtitle{font-size:.7rem;color:rgba(193,249,249,0.38);margin-bottom:2rem;
      text-transform:uppercase;letter-spacing:.18em}
    h1{font-size:clamp(1.2rem,3vw,1.5rem);font-weight:700;margin-bottom:1rem;
      color:#c1f9f9;text-transform:uppercase;letter-spacing:.08em}
    p{color:rgba(193,249,249,0.72);line-height:1.7;margin-bottom:1rem;font-size:.95rem}
    .small{font-size:.78rem;color:rgba(193,249,249,0.4)}
    a{color:rgba(193,249,249,0.7);text-decoration:underline}
    .spinner{width:44px;height:44px;
      border:2.5px solid rgba(193,249,249,0.1);border-top:2.5px solid rgba(122,171,140,0.7);
      border-radius:50%;animation:spin .9s linear infinite;margin:1.5rem auto}
    @keyframes spin{to{transform:rotate(360deg)}}
    .lock{font-size:.65rem;color:rgba(193,249,249,0.38);margin-top:2rem;display:flex;
      align-items:center;justify-content:center;gap:.4rem;text-transform:uppercase;letter-spacing:.06em}
    .lock svg{width:12px;height:12px;fill:rgba(193,249,249,0.38)}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">High on Chapel
<body>
  <div class="card">
    <div class="logo">High on Chapel
<body>
  <div class="card">
    <div class="logo">High on Chapel</div>
    <div class="subtitle">Secure Payments</div>
    <h1>${title}</h1>
    <div id="msg">${bodyContent}</div>
    <div class="lock">
      <svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>
      Secured by Till Payments &middot; 256-bit SSL
    </div>
  </div>
  ${pollScript}
</body>
</html>`;
}

// ─── Start Server ───────────────────────────────────────────────────────────

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      logger.info('HOCS Till Middleware started', {
        port: PORT,
        env: NODE_ENV,
        tillEndpoint: TILL_BASE_URL,
        shopifyStore: SHOPIFY_STORE_DOMAIN,
        callbackUrl: CALLBACK_URL
      });
    });
  })
  .catch((err) => {
    logger.error('Failed to initialize PostgreSQL', { error: err.message, stack: err.stack });
    process.exit(1);
  });

module.exports = app; // For testing
