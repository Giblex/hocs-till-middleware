/**
 * HOCS Payment Redirect — Checkout UI Extension
 * ──────────────────────────────────────────────
 * Renders on the Shopify Thank You page after checkout.
 * Directs unpaid orders straight to the middleware payment portal,
 * which auto-redirects to the Till HPP for card entry.
 *
 * Flow: Thank You → click → Middleware Portal → Till HPP → Pay → Success
 */

import { useState, useEffect } from 'react';
import {
  reactExtension,
  Banner,
  BlockStack,
  Button,
  Text,
  useOrder,
  useEmail,
} from '@shopify/ui-extensions-react/checkout';

const MIDDLEWARE_URL = 'https://hocs-till-middleware-production.up.railway.app';

export default reactExtension('purchase.thank-you.block.render', () => (
  <PaymentRedirectBanner />
));

function PaymentRedirectBanner() {
  const order = useOrder();
  const email = useEmail();

  const [redirecting, setRedirecting] = useState(false);

  // Extract numeric Shopify order ID from GID
  // e.g. "gid://shopify/OrderIdentity/5085102137" → "5085102137"
  const shopifyOrderId = order?.id ? order.id.split('/').pop() : '';
  const customerEmail = email || '';

  // Link directly to the middleware payment portal — no intermediary Shopify page
  const payPortalUrl = `${MIDDLEWARE_URL}/pay/${encodeURIComponent(shopifyOrderId)}`
    + `?email=${encodeURIComponent(customerEmail)}`;

  // ── Don't render if we don't have order/email data ──
  if (!shopifyOrderId || !customerEmail) return null;

  return (
    <Banner status="critical" title="⚠️ Payment Required — Your order is NOT yet paid">
      <BlockStack spacing="base">
        <Text emphasis="bold">
          Your order will be cancelled if payment is not completed.
        </Text>
        <Text>
          Click the button below to enter your card details on our secure payment page.
        </Text>
        <Button
          kind="primary"
          to={payPortalUrl}
          onPress={() => setRedirecting(true)}
        >
          {redirecting ? 'Opening payment page…' : '💳 Complete Payment Now'}
        </Button>
        <Text size="small" appearance="subdued">
          Secured by Till Payments · 256-bit SSL encrypted
        </Text>
      </BlockStack>
    </Banner>
  );
}
