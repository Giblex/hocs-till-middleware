/**
 * HOCS Payment Redirect — Checkout UI Extension
 * Renders on Thank You + Order Status pages.
 * Directs unpaid orders to the middleware payment portal → Till HPP.
 */

import { useState } from 'react';
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

// ── Thank You page target ──
export default reactExtension('purchase.thank-you.block.render', () => (
  <PaymentRedirectBanner />
));

// ── Order Status page target ──
export const orderStatus = reactExtension('customer-account.order-status.block.render', () => (
  <PaymentRedirectBanner />
));

function PaymentRedirectBanner() {
  const order = useOrder();
  const email = useEmail();
  const [redirecting, setRedirecting] = useState(false);

  const shopifyOrderId = order?.id ? order.id.split('/').pop() : '';
  const customerEmail = email || '';

  // Build pay portal URL — works even without email (middleware handles it)
  const payPortalUrl = shopifyOrderId
    ? `${MIDDLEWARE_URL}/pay/${encodeURIComponent(shopifyOrderId)}?email=${encodeURIComponent(customerEmail)}`
    : '';

  // Always render the banner so it's visible (even in customizer preview)
  return (
    <Banner status="critical" title="⚠️ Payment Required — Your order is NOT yet paid">
      <BlockStack spacing="base">
        <Text emphasis="bold">
          Your order will be cancelled if payment is not completed.
        </Text>
        <Text>
          Click the button below to enter your card details on our secure payment page.
        </Text>
        {shopifyOrderId ? (
          <Button
            kind="primary"
            to={payPortalUrl}
            onPress={() => setRedirecting(true)}
          >
            {redirecting ? 'Opening payment page…' : '💳 Complete Payment Now'}
          </Button>
        ) : (
          <Text emphasis="bold">Loading payment details…</Text>
        )}
        <Text size="small" appearance="subdued">
          Secured by Till Payments · 256-bit SSL encrypted
        </Text>
      </BlockStack>
    </Banner>
  );
}
