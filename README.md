# HOCS Till Payments Middleware

Gateway middleware between **Shopify** (Standard) and **Till Payments** (PayNuts) for High on Chapel.

## Architecture

```
┌──────────────┐    orders/create     ┌────────────────────┐    Debit API     ┌──────────────────┐
│   Shopify    │ ──── webhook ──────▸ │   This Middleware   │ ─────────────▸  │  Till Payments   │
│   (theme)    │                      │   (Node.js/Express) │                  │  Gateway API v3  │
│              │ ◂── Admin API ────── │                     │ ◂── callback ── │                  │
└──────────────┘   mark order paid    └────────────────────┘   X-Signature    └──────────────────┘
```

## Quick Start

```bash
cd middleware
cp .env.example .env
# Edit .env with your actual credentials
npm install
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## Endpoints

| Method | Path                  | Purpose                                      |
|--------|-----------------------|----------------------------------------------|
| POST   | `/api/shopify-webhook`| Receives Shopify `orders/create` webhook      |
| POST   | `/api/till-callback`  | Receives Till async payment callback          |
| GET    | `/health`             | Health check / readiness probe                |

## Security Features Implemented

| # | Recommendation                  | Implementation                                    |
|---|--------------------------------|--------------------------------------------------|
| 1 | Callback signature verification | HMAC-SHA512 on `/api/till-callback`              |
| 2 | 3DS MANDATORY                   | Every debit includes `extraData.3dsecure`        |
| 3 | Full customer data              | Populated from Shopify order billing + customer  |
| 4 | Idempotent transaction IDs      | `HOC-{orderNumber}` — deterministic, no dupes    |
| 5 | Cart permalink expiry           | Client-side `?expires=` param in `payment-link.js`|
| 6 | Amount validation on callback   | Callback amount compared to original order       |
| 7 | Rate limiting                   | Client-side (10s cooldown) + server (5/min/IP)   |
| 8 | Webhook retry handling          | Duplicate webhook/callback detection             |
| 9 | Structured logging & alerting   | JSON logs, error-code specific alerts            |
| 10| Go-live checklist               | This document (see below)                        |

---

## Go-Live Checklist

### Phase 1: Pre-Deployment

- [ ] **Till sandbox testing complete** — all 4 test scripts pass (`test_payment.ps1`)
- [ ] **3DS flow tested** — complete a sandbox payment through the hosted page with 3DS
- [ ] **Callback signature verification tested** — send a test callback, confirm it validates
- [ ] **Amount mismatch tested** — tamper with callback amount, confirm it's rejected and logged

### Phase 2: Environment Configuration

- [ ] **Switch `TILL_BASE_URL`** from `https://test-gateway.tillpayments.com` to `https://gateway.tillpayments.com`
- [ ] **Update Till credentials** — production API key, shared secret, user, password
- [ ] **Set `NODE_ENV=production`**
- [ ] **Configure `CALLBACK_URL`** to use production domain with HTTPS
- [ ] **Verify Shopify Admin API token** has `write_orders` scope
- [ ] **Verify Shopify webhook secret** matches the `orders/create` webhook configuration

### Phase 3: Infrastructure

- [ ] **Deploy middleware** to production host (Railway, Render, Fly.io, Azure, etc.)
- [ ] **Enable HTTPS** — TLS required for callback and webhook endpoints
- [ ] **Set up DNS** — point your middleware domain to the deployment
- [ ] **Test `/health` endpoint** from public internet
- [ ] **Configure Shopify webhook** — set `orders/create` webhook URL to `https://your-domain/api/shopify-webhook`

### Phase 4: Monitoring (Rec #9)

- [ ] **Set up log aggregation** — pipe JSON logs to Datadog / CloudWatch / LogDNA / etc.
- [ ] **Configure alerts** for:
  - `ALERT` level log entries
  - Error code `1004` (connector/config issues)
  - `AMOUNT_MISMATCH` or `CURRENCY_MISMATCH` events
  - Signature verification failures
  - HTTP 5xx from this middleware
- [ ] **Set up uptime monitoring** — ping `/health` every 30s

### Phase 5: Go-Live

- [ ] **Test a real $1 transaction** end-to-end (create order → Till debit → pay → callback → order marked paid)
- [ ] **Verify 3DS challenge appears** on the hosted payment page
- [ ] **Check Shopify order** shows as paid with gateway "Till Payments (PayNuts)"
- [ ] **Monitor logs** for first 24 hours
- [ ] **Disable sandbox** Till credentials
- [ ] **Document rollback procedure** — how to fall back to manual payment if middleware goes down

### Phase 6: Ongoing

- [ ] **Rotate shared secret** quarterly
- [ ] **Review logs** weekly for unusual patterns
- [ ] **Update dependencies** monthly (`npm audit`, `npm update`)
- [ ] **Test disaster recovery** — what happens when middleware is unreachable?
  - Shopify webhook retries for 48h
  - Use `main-payments-out-of-order.liquid` fallback page

---

## File Inventory

| File | Purpose |
|------|---------|
| `middleware/server.js` | Express server — webhook handler, callback handler, Till API client |
| `middleware/package.json` | Dependencies |
| `middleware/.env.example` | Environment variable template |
| `assets/payment-link.js` | Client-side payment link generation (v3.0.0 — expiry, rate-limit) |
| `snippets/cart-drawer.liquid` | Cart drawer with payment link button |
| `sections/main-cart-footer.liquid` | Full cart page footer with payment link button |
| `sections/main-payments-out-of-order.liquid` | Payment outage fallback page |
| `test/test_payment.ps1` | PowerShell sandbox test script |

## Notes for Shopify Standard

- **No server-side Liquid execution** — all payment logic lives in this middleware
- **No Shopify Scripts** (Plus only) — discounts use native Shopify discount codes
- **Theme assets are client-side only** — `payment-link.js` handles UX, not payment processing
- **Webhook is the trigger** — Shopify `orders/create` fires when a manual order is created
- **Cart permalinks** (`/cart/variant:qty,...`) work for any visitor, not session-bound
