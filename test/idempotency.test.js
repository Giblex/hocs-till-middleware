/**
 * Race-condition test for the webhook idempotency claim.
 *
 * Verifies that a single-statement `INSERT ... ON CONFLICT DO NOTHING RETURNING`
 * is atomic under concurrency: exactly one of N concurrent claim attempts
 * for the same order_id wins, the rest see rowCount === 0.
 *
 * Requires a running Postgres reachable via DATABASE_URL with the `webhooks`
 * table created (see server.js initSchema). Uses a unique synthetic
 * order_id per run so it does not collide with real data, and cleans up.
 *
 * Run:  node --test test/idempotency.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

const skip = !DATABASE_URL;
const skipReason = 'DATABASE_URL not set — skipping integration test';

test('atomic claim: only one of N concurrent inserts wins', { skip: skip && skipReason }, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL });
  const orderId = `test-race-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  t.after(async () => {
    await pool.query('DELETE FROM webhooks WHERE order_id = $1', [orderId]);
    await pool.end();
  });

  const N = 20;
  const claim = () =>
    pool.query(
      `INSERT INTO webhooks (order_id, created_at) VALUES ($1, NOW())
       ON CONFLICT (order_id) DO NOTHING RETURNING order_id`,
      [orderId]
    );

  const results = await Promise.all(Array.from({ length: N }, claim));
  const winners = results.filter((r) => r.rowCount === 1).length;
  const losers = results.filter((r) => r.rowCount === 0).length;

  assert.equal(winners, 1, `expected exactly 1 winner, got ${winners}`);
  assert.equal(losers, N - 1, `expected ${N - 1} losers, got ${losers}`);

  // Sanity: the row exists.
  const { rowCount } = await pool.query('SELECT 1 FROM webhooks WHERE order_id = $1', [orderId]);
  assert.equal(rowCount, 1);
});

test('stale claim release: DELETE allows next claim to win', { skip: skip && skipReason }, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL });
  const orderId = `test-stale-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  t.after(async () => {
    await pool.query('DELETE FROM webhooks WHERE order_id = $1', [orderId]);
    await pool.end();
  });

  const claim = () =>
    pool.query(
      `INSERT INTO webhooks (order_id, created_at) VALUES ($1, NOW())
       ON CONFLICT (order_id) DO NOTHING RETURNING order_id`,
      [orderId]
    );

  // First attempt wins.
  const first = await claim();
  assert.equal(first.rowCount, 1);

  // Second attempt loses (simulating duplicate webhook delivery).
  const second = await claim();
  assert.equal(second.rowCount, 0);

  // Simulate the "stale claim release" path from the route handler: caller
  // detects no transaction was saved and deletes the orphaned claim.
  await pool.query('DELETE FROM webhooks WHERE order_id = $1', [orderId]);

  // Third attempt now wins again — Shopify retry can proceed.
  const third = await claim();
  assert.equal(third.rowCount, 1);
});
