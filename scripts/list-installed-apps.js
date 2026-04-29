// Lists all apps installed on the store. Helps identify orphaned dev apps
// whose webhook subscriptions are pointing at this middleware URL.
const sd = process.env.SHOPIFY_STORE_DOMAIN;
const tok = process.env.SHOPIFY_ACCESS_TOKEN;
(async () => {
  const r = await fetch(`https://${sd}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': tok, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `{
        appInstallations(first: 50) {
          edges { node {
            id
            app { id title appStoreAppUrl developerName }
            accessScopes { handle }
          } }
        }
      }`
    })
  });
  console.log(JSON.stringify(await r.json(), null, 2));
})();
