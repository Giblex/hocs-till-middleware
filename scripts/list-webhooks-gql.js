const sd = process.env.SHOPIFY_STORE_DOMAIN;
const tok = process.env.SHOPIFY_ACCESS_TOKEN;

(async () => {
  const r = await fetch(`https://${sd}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': tok, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `{
        webhookSubscriptions(first: 50) {
          edges {
            node {
              id
              topic
              apiVersion { handle }
              createdAt
              endpoint {
                __typename
                ... on WebhookHttpEndpoint { callbackUrl }
                ... on WebhookEventBridgeEndpoint { arn }
                ... on WebhookPubSubEndpoint { pubSubProject pubSubTopic }
              }
            }
          }
        }
      }`
    })
  });
  const j = await r.json();
  console.log(JSON.stringify(j, null, 2));
})();
