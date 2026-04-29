#!/usr/bin/env node
/**
 * Removes duplicate Shopify webhook subscriptions for the same topic+address.
 *
 * Why: when both an app subscription AND a store-admin subscription point at
 * the same URL, every order fires two webhooks signed with two different
 * secrets. The middleware can only verify the one whose secret it has, so
 * the other always fails HMAC verification.
 *
 * What it does:
 *   1. Lists all webhook subscriptions via the Admin API.
 *   2. Groups by (topic, address).
 *   3. For each group with >1 entry, keeps the oldest and deletes the rest.
 *
 * Run:  SHOPIFY_STORE_DOMAIN=... SHOPIFY_ACCESS_TOKEN=... node scripts/dedupe-webhooks.js
 *       Add --dry-run to list without deleting.
 */

require('dotenv').config();

const { SHOPIFY_STORE_DOMAIN, SHOPIFY_ACCESS_TOKEN } = process.env;
const API_VERSION = '2026-01';
const DRY_RUN = process.argv.includes('--dry-run');

if (!SHOPIFY_STORE_DOMAIN || !SHOPIFY_ACCESS_TOKEN) {
  console.error('Missing SHOPIFY_STORE_DOMAIN or SHOPIFY_ACCESS_TOKEN');
  process.exit(1);
}

const baseUrl = `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${API_VERSION}`;
const headers = {
  'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
  'Content-Type': 'application/json'
};

async function listWebhooks() {
  const all = [];
  let url = `${baseUrl}/webhooks.json?limit=250`;
  while (url) {
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error(`List failed: ${res.status} ${await res.text()}`);
    const json = await res.json();
    all.push(...json.webhooks);
    const link = res.headers.get('link') || '';
    const next = link.match(/<([^>]+)>;\s*rel="next"/);
    url = next ? next[1] : null;
  }
  return all;
}

async function deleteWebhook(id) {
  const res = await fetch(`${baseUrl}/webhooks/${id}.json`, { method: 'DELETE', headers });
  if (!res.ok) throw new Error(`Delete ${id} failed: ${res.status} ${await res.text()}`);
}

(async () => {
  console.log(`[${DRY_RUN ? 'DRY-RUN' : 'LIVE'}] Listing webhooks for ${SHOPIFY_STORE_DOMAIN}...`);
  const webhooks = await listWebhooks();
  console.log(`Found ${webhooks.length} subscriptions.\n`);

  // Group by topic + address (where it delivers).
  const groups = new Map();
  for (const w of webhooks) {
    const key = `${w.topic}\t${w.address}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(w);
  }

  let deletes = 0;
  for (const [key, subs] of groups) {
    const [topic, address] = key.split('\t');
    if (subs.length === 1) {
      console.log(`✓ ${topic} → ${address}  (1 subscription, OK)`);
      continue;
    }
    // Keep the oldest, delete the rest.
    subs.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    const keeper = subs[0];
    const dupes = subs.slice(1);
    console.log(`! ${topic} → ${address}  (${subs.length} subscriptions)`);
    console.log(`  KEEP   id=${keeper.id} created=${keeper.created_at}`);
    for (const d of dupes) {
      console.log(`  DELETE id=${d.id} created=${d.created_at}`);
      if (!DRY_RUN) {
        await deleteWebhook(d.id);
        deletes++;
      }
    }
  }

  console.log(`\n${DRY_RUN ? 'Would delete' : 'Deleted'} ${DRY_RUN ? groups.size : deletes} duplicate subscriptions.`);
})().catch((err) => {
  console.error('FATAL:', err.message);
  process.exit(1);
});
