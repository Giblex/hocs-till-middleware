/**
 * Weekly Orders Report
 *
 * Cross-references local Till transactions with Shopify orders, builds an
 * Excel workbook with traffic-light row colouring, and emails it to the
 * configured recipients.
 *
 * Colour rules per row:
 *   GREEN  — Till took payment AND Shopify is paid AND order is fulfilled
 *   AMBER  — exactly one or two of those three signals are true
 *   RED    — none are true (no payment movement, not fulfilled)
 *
 * Required env vars:
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS  — SMTP creds
 *   SMTP_FROM                                   — From header
 *   REPORT_RECIPIENTS                           — comma-separated emails
 *                                                 (defaults to AJ + Michael)
 */

const ExcelJS = require('exceljs');
const nodemailer = require('nodemailer');

const DEFAULT_RECIPIENTS = [
  'aj.halliday@giblex.com',
  'Michael@highonchapel.com'
];

// Cell fill colours (ARGB).
const FILL_GREEN = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFC6EFCE' } };
const FILL_AMBER = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFEB9C' } };
const FILL_RED   = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFC7CE' } };
const FONT_GREEN = { color: { argb: 'FF006100' }, bold: true };
const FONT_AMBER = { color: { argb: 'FF9C5700' }, bold: true };
const FONT_RED   = { color: { argb: 'FF9C0006' }, bold: true };

function classifyRow({ tillPaid, shopifyPaid, fulfilled }) {
  const score = (tillPaid ? 1 : 0) + (shopifyPaid ? 1 : 0) + (fulfilled ? 1 : 0);
  if (score === 3) return 'green';
  if (score === 0) return 'red';
  return 'amber';
}

function fillFor(category) {
  if (category === 'green') return { fill: FILL_GREEN, font: FONT_GREEN };
  if (category === 'amber') return { fill: FILL_AMBER, font: FONT_AMBER };
  return { fill: FILL_RED, font: FONT_RED };
}

/**
 * Build the Excel workbook from joined transaction + Shopify order rows.
 * @param {Array} rows  output of fetchReportRows
 * @returns {Buffer}    xlsx file bytes
 */
async function buildWorkbook(rows) {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'HOCS Till Middleware';
  wb.created = new Date();

  // ── Sheet 1: detail ───────────────────────────────────────────────────────
  const sheet = wb.addWorksheet('Orders', {
    views: [{ state: 'frozen', ySplit: 1 }]
  });

  sheet.columns = [
    { header: 'Order #',         key: 'orderNumber',     width: 12 },
    { header: 'Date',            key: 'createdAt',       width: 18 },
    { header: 'Customer',        key: 'customer',        width: 28 },
    { header: 'Email',           key: 'email',           width: 30 },
    { header: 'Amount',          key: 'amount',          width: 12 },
    { header: 'Currency',        key: 'currency',        width: 10 },
    { header: 'Shopify Status',  key: 'shopifyStatus',   width: 18 },
    { header: 'Financial',       key: 'financialStatus', width: 16 },
    { header: 'Fulfillment',     key: 'fulfillmentStatus', width: 16 },
    { header: 'Till Status',     key: 'tillStatus',      width: 16 },
    { header: 'Till Approved',   key: 'tillApproved',    width: 14 },
    { header: 'Till UUID',       key: 'tillUuid',        width: 38 },
    { header: 'Txn ID',          key: 'txnId',           width: 18 },
    { header: 'Category',        key: 'category',        width: 12 }
  ];

  // Header style.
  sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
  sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3A6E' } };
  sheet.getRow(1).alignment = { vertical: 'middle' };
  sheet.getRow(1).height = 22;

  let greenCount = 0, amberCount = 0, redCount = 0;
  let totalAmount = 0, paidAmount = 0;

  for (const r of rows) {
    const category = classifyRow(r);
    if (category === 'green') greenCount++;
    else if (category === 'amber') amberCount++;
    else redCount++;

    const amt = parseFloat(r.amount) || 0;
    totalAmount += amt;
    if (r.tillPaid && r.shopifyPaid) paidAmount += amt;

    const row = sheet.addRow({
      orderNumber: r.orderNumber || '',
      createdAt: r.createdAt ? new Date(r.createdAt) : '',
      customer: r.customer || '',
      email: r.email || '',
      amount: amt,
      currency: r.currency || '',
      shopifyStatus: r.shopifyOrderStatus || '(not found)',
      financialStatus: r.financialStatus || '',
      fulfillmentStatus: r.fulfillmentStatus || 'unfulfilled',
      tillStatus: r.tillStatus || '',
      tillApproved: r.tillPaid ? 'Yes' : 'No',
      tillUuid: r.tillUuid || '',
      txnId: r.txnId || '',
      category: category.toUpperCase()
    });

    row.numFmt = undefined; // reset
    row.getCell('amount').numFmt = '#,##0.00';
    row.getCell('createdAt').numFmt = 'yyyy-mm-dd hh:mm';

    const { fill, font } = fillFor(category);
    row.eachCell((cell) => {
      cell.fill = fill;
      cell.font = { ...cell.font, color: font.color };
    });
    row.getCell('category').font = font;
  }

  // ── Sheet 2: summary ──────────────────────────────────────────────────────
  const summary = wb.addWorksheet('Summary');
  summary.columns = [
    { header: 'Metric', key: 'metric', width: 32 },
    { header: 'Value',  key: 'value',  width: 22 }
  ];
  summary.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
  summary.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3A6E' } };

  const rangeStart = rows.length ? rows[rows.length - 1].createdAt : null;
  const rangeEnd = rows.length ? rows[0].createdAt : null;

  const summaryRows = [
    ['Report generated', new Date()],
    ['Period start', rangeStart ? new Date(rangeStart) : ''],
    ['Period end',   rangeEnd   ? new Date(rangeEnd)   : ''],
    ['Total orders', rows.length],
    ['Green (paid + fulfilled)', greenCount],
    ['Amber (partial)', amberCount],
    ['Red (no movement)', redCount],
    ['Total revenue (gross)', totalAmount],
    ['Confirmed paid revenue', paidAmount],
    ['Unconfirmed/unpaid', totalAmount - paidAmount]
  ];
  for (const [m, v] of summaryRows) {
    const r = summary.addRow({ metric: m, value: v });
    if (typeof v === 'number') r.getCell('value').numFmt = '#,##0.00';
    if (v instanceof Date) r.getCell('value').numFmt = 'yyyy-mm-dd hh:mm';
  }

  // Highlight category rows in summary.
  summary.getRow(6).getCell('value').fill = FILL_GREEN;
  summary.getRow(6).getCell('value').font = FONT_GREEN;
  summary.getRow(7).getCell('value').fill = FILL_AMBER;
  summary.getRow(7).getCell('value').font = FONT_AMBER;
  summary.getRow(8).getCell('value').fill = FILL_RED;
  summary.getRow(8).getCell('value').font = FONT_RED;

  return await wb.xlsx.writeBuffer();
}

/**
 * Pull all transactions from the local DB and join with live Shopify state.
 * @param {Object} ctx  { pool, shopifyAdminAPI, sinceDays }
 */
async function fetchReportRows({ pool, shopifyAdminAPI, sinceDays = 7, logger }) {
  const since = new Date(Date.now() - sinceDays * 24 * 60 * 60 * 1000).toISOString();
  const { rows: txns } = await pool.query(
    `SELECT * FROM transactions WHERE updated_at >= $1 ORDER BY updated_at DESC`,
    [since]
  );

  const out = [];
  for (const t of txns) {
    let shopifyOrder = null;
    if (t.shopify_order_id) {
      try {
        const r = await shopifyAdminAPI('GET', `/orders/${t.shopify_order_id}.json`);
        shopifyOrder = r?.body?.order || null;
      } catch (err) {
        logger?.warn?.('Report: failed to fetch Shopify order', {
          shopifyOrderId: t.shopify_order_id,
          error: err.message
        });
      }
    }

    const tillPaid = ['paid', 'completed', 'captured', 'success'].includes(
      String(t.status || '').toLowerCase()
    );
    const financialStatus = shopifyOrder?.financial_status || '';
    const fulfillmentStatus = shopifyOrder?.fulfillment_status || 'unfulfilled';
    const shopifyPaid = ['paid', 'partially_paid'].includes(financialStatus);
    const fulfilled = ['fulfilled', 'partial'].includes(fulfillmentStatus);

    out.push({
      txnId: t.txn_id,
      orderNumber: t.order_number,
      createdAt: t.updated_at,
      customer: shopifyOrder
        ? [shopifyOrder.customer?.first_name, shopifyOrder.customer?.last_name].filter(Boolean).join(' ')
        : '',
      email: t.customer_email || shopifyOrder?.email || '',
      amount: t.amount,
      currency: t.currency,
      shopifyOrderStatus: shopifyOrder ? (shopifyOrder.cancelled_at ? 'cancelled' : 'open') : null,
      financialStatus,
      fulfillmentStatus,
      tillStatus: t.status,
      tillUuid: t.till_uuid,
      tillPaid,
      shopifyPaid,
      fulfilled
    });
  }
  return out;
}

/**
 * Send the report email with the xlsx attached.
 */
async function sendReportEmail({ buffer, recipients, sinceDays, isTest, logger }) {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error('SMTP_HOST, SMTP_USER, SMTP_PASS required to send report');
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: parseInt(SMTP_PORT || '587', 10),
    secure: parseInt(SMTP_PORT || '587', 10) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });

  const dateStr = new Date().toISOString().slice(0, 10);
  const filename = `hocs-orders-${dateStr}.xlsx`;
  const subject = `${isTest ? '[TEST] ' : ''}HOCS Weekly Orders Report — ${dateStr}`;

  const result = await transporter.sendMail({
    from: SMTP_FROM ? `"${SMTP_FROM}" <${SMTP_USER}>` : SMTP_USER,
    to: recipients.join(', '),
    subject,
    text:
      `Attached is the ${isTest ? 'test ' : ''}weekly orders report covering the last ${sinceDays} days.\n\n` +
      `Rows are colour-coded:\n` +
      `  GREEN  — Till took payment AND Shopify shows paid AND fulfilled\n` +
      `  AMBER  — partial state (one or two of the above)\n` +
      `  RED    — no payment, no fulfilment\n\n` +
      `See the Summary sheet for totals.\n`,
    attachments: [{ filename, content: buffer }]
  });

  logger?.info?.('Weekly report sent', {
    messageId: result.messageId,
    recipients,
    isTest
  });
  return result;
}

/**
 * Public entrypoint: build and email the report. Returns
 * { rowsCount, recipients, messageId, sinceDays }.
 */
async function generateAndSendReport({ pool, shopifyAdminAPI, logger, sinceDays = 7, isTest = false, recipients }) {
  const finalRecipients = recipients?.length ? recipients : (
    process.env.REPORT_RECIPIENTS
      ? process.env.REPORT_RECIPIENTS.split(',').map((s) => s.trim()).filter(Boolean)
      : DEFAULT_RECIPIENTS.slice()
  );

  const rows = await fetchReportRows({ pool, shopifyAdminAPI, sinceDays, logger });
  const buffer = await buildWorkbook(rows);
  const result = await sendReportEmail({ buffer, recipients: finalRecipients, sinceDays, isTest, logger });

  return {
    rowsCount: rows.length,
    recipients: finalRecipients,
    messageId: result.messageId,
    sinceDays,
    isTest
  };
}

module.exports = { generateAndSendReport, buildWorkbook, fetchReportRows };
