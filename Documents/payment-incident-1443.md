# Payment Incident 1443

Date investigated: 2026-03-26

## Outcome
Order `#1443` was not missing from the middleware. The production middleware:
- received the Shopify webhook
- created the Till debit successfully
- redirected the customer to the Till hosted payment page
- received a signed Till callback with `result=OK`

The failure happened after callback receipt. The callback was logged as `Unhandled callback result`, so Shopify was never marked paid and the order remained `financial_status=pending`.

## Verified Evidence
Shopify order facts:
- Order ID: `6697916367035`
- Order number: `1443`
- Created: `2026-03-22T12:13:39+11:00`
- Total: `71.00 AUD`
- Customer email: `hellodollface@me.com`
- Gateway label: `EFTPOS/ Card Payments`
- Financial status: `pending`

Shopify timeline:
- `2026-03-22 12:13:40 +11`: `A $71.00 AUD payment is pending on Eftpos/ Card Payments.`

Railway production logs from deployment `50ff0f7d-57f4-4e7f-8f84-3c74e7157c2a`:
- `2026-03-22T01:13:45Z`: Shopify webhook received for order `1443`
- `2026-03-22T01:13:45Z`: Till debit request returned HTTP `200`
- `2026-03-22T01:13:45Z`: Till debit initiated with:
  - `txnId=HOC-1443`
  - `tillUuid=2de8fedaa6a7f28cd092`
  - `purchaseId=20260322-2de8fedaa6a7f28cd092`
  - Till API response `returnType=REDIRECT`
- `2026-03-22T01:14:23Z`: Pay portal redirected customer to existing Till hosted payment page
- `2026-03-22T01:15:27Z`: Till callback received and signature verified
- `2026-03-22T01:15:27Z`: Callback logged with:
  - `txnId=HOC-1443`
  - `tillUuid=2de8fedaa6a7f28cd092`
  - `result=OK`
  - `cbAmount=71.00`
  - `cbCurrency=AUD`
- `2026-03-22T01:15:27Z`: Middleware logged `Unhandled callback result`

## Root Cause
The callback handler only marked Shopify paid when:

```js
result === 'OK' && returnType === 'FINISHED'
```

For `#1443`, Till sent a signed successful callback with `result=OK`, but the middleware did not receive a usable terminal `returnType`. That caused the callback to fall into the unhandled branch instead of marking the order paid.

## Code Change Applied
The callback handler now:
- still treats explicit `REDIRECT` callbacks as non-terminal
- still treats explicit `ERROR` callbacks as failed
- treats a signed `result=OK` callback with missing `returnType` and missing `status` as a successful payment fallback
- logs the full callback body for future unhandled cases

This prevents orders like `#1443` from getting stranded in `pending` purely because Till omitted terminal metadata on an otherwise successful callback.

## Recommended Vendor Questions
Ask PayNuts / Till / Nuvei to confirm for:
- `merchantTransactionId=HOC-1443`
- `uuid=2de8fedaa6a7f28cd092`
- `purchaseId=20260322-2de8fedaa6a7f28cd092`
- callback URL `https://hocs-till-middleware-production.up.railway.app/api/till-callback`

Questions:
- What was the final transaction state for this payment?
- What exact callback payload was sent for the successful callback?
- Was `returnType` omitted intentionally for this callback type?
- Is there a merchant status endpoint or portal view that supersedes `/api/v3/status/...` for historical transactions?
- Which Nuvei/Till portal is the correct merchant portal for this integration?

## Store Guidance
Until a payment is confirmed in Shopify or by the gateway:
- do not dispatch goods
- treat customer screenshots as evidence of an attempted payment, not proof of settled funds

For `#1443`, the strongest current internal evidence is that the gateway callback was successful enough to be signed and accepted, but the middleware failed to classify it as terminal.
