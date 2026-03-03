/**
 * HOCS Payment Redirect — Checkout UI Extension
 * ──────────────────────────────────────────────
 * Renders on the Shopify Thank You page after checkout.
 * Shows a prominent "Complete Payment" banner for unpaid (manual payment) orders.
 * Links to the Complete Payment theme page with order data pre-filled.
 */

import { useState, useEffect } from 'react';
import {
  reactExtension,
  Banner,
  BlockStack,
  Button,
  Text,
  Spinner,
  useOrder,
  useEmail,
} from '@shopify/ui-extensions-react/checkout';

const MIDDLEWARE_URL = 'https://hocs-till-middleware-production.up.railway.app';
const STORE_URL = 'https://hocdev.myshopify.com';
const POLL_INTERVAL = 2500;
const MAX_POLLS = 24; // 24 × 2.5s = 60 seconds

export default reactExtension('purchase.thank-you.block.render', () => (
  <PaymentRedirectBanner />
));

function PaymentRedirectBanner() {
  const order = useOrder();
  const email = useEmail();

  const [status, setStatus] = useState('polling');   // polling | ready | paid | failed | timeout
  const [redirectUrl, setRedirectUrl] = useState(null);

  // Extract numeric Shopify order ID from GID
  // e.g. "gid://shopify/OrderIdentity/5085102137" → "5085102137"
  const shopifyOrderId = order?.id ? order.id.split('/').pop() : '';
  const customerEmail = email || '';

  // Build a fallback link to the Complete Payment page
  const completePaymentUrl = `${STORE_URL}/pages/complete-payment`
    + `?shopifyId=${encodeURIComponent(shopifyOrderId)}`
    + `&email=${encodeURIComponent(customerEmail)}`;

  // Poll middleware for payment redirect URL
  useEffect(() => {
    if (!shopifyOrderId || !customerEmail) return;

    let cancelled = false;
    let pollCount = 0;

    async function poll() {
      if (cancelled) return;

      pollCount++;
      if (pollCount > MAX_POLLS) {
        setStatus('timeout');
        return;
      }

      try {
        const res = await fetch(
          `${MIDDLEWARE_URL}/api/payment-redirect-by-shopify-id/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(customerEmail)}`,
          { headers: { Accept: 'application/json' } }
        );
        const data = await res.json();
        if (cancelled) return;

        switch (data.status) {
          case 'ready':
            setRedirectUrl(data.redirectUrl);
            setStatus('ready');
            break;
          case 'paid':
            setStatus('paid');
            break;
          case 'failed':
            setStatus('failed');
            break;
          case 'pending':
          default:
            setTimeout(poll, POLL_INTERVAL);
            break;
        }
      } catch (err) {
        // Network error — retry
        if (!cancelled && pollCount < MAX_POLLS) {
          setTimeout(poll, POLL_INTERVAL * 2);
        } else {
          setStatus('timeout');
        }
      }
    }

    // Start polling after 2s (give webhook time to fire)
    const timer = setTimeout(poll, 2000);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [shopifyOrderId, customerEmail]);

  // ── Don't show anything if order is already paid ──
  if (status === 'paid') return null;

  // ── Polling / loading state ──
  if (status === 'polling') {
    return (
      <Banner status="info" title="Setting up your payment…">
        <BlockStack spacing="tight">
          <Text>Connecting to secure payment gateway. This usually takes a few seconds.</Text>
        </BlockStack>
      </Banner>
    );
  }

  // ── Ready — show Pay Now button ──
  if (status === 'ready' && redirectUrl) {
    return (
      <Banner status="warning" title="Complete Your Card Payment">
        <BlockStack spacing="base">
          <Text>
            Your order is confirmed! Click below to securely enter your card details.
          </Text>
          <Button to={redirectUrl}>
            Pay Now →
          </Button>
          <Text size="small" appearance="subdued">
            Secured by Till Payments · 256-bit SSL encrypted
          </Text>
        </BlockStack>
      </Banner>
    );
  }

  // ── Timeout — offer Complete Payment page link ──
  if (status === 'timeout') {
    return (
      <Banner status="warning" title="Complete Your Payment">
        <BlockStack spacing="base">
          <Text>
            Your payment link is still being prepared. Click below to complete your payment.
          </Text>
          <Button to={completePaymentUrl}>
            Go to Payment Page →
          </Button>
        </BlockStack>
      </Banner>
    );
  }

  // ── Failed ──
  if (status === 'failed') {
    return (
      <Banner status="critical" title="Payment Setup Issue">
        <BlockStack spacing="base">
          <Text>
            There was an issue connecting to our payment gateway. Please try the payment page directly.
          </Text>
          <Button to={completePaymentUrl}>
            Try Payment Page →
          </Button>
        </BlockStack>
      </Banner>
    );
  }

  return null;
}
