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

// Text colours (ARGB).
const TEXT_GREEN = 'FF1B7A3E';   // deep green — fully complete
const TEXT_BLACK = 'FF000000';   // partial / in-progress (was "amber" — text now black)
const TEXT_RED   = 'FFB0282C';   // muted red — cancelled / refunded / voided / failed
const STAFF_FILL = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFE5CC' } }; // faint light orange
const HEADER_FILL = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF3D5478' } }; // lighter charcoal blue
const HEADER_FONT = { bold: true, color: { argb: 'FFFFFFFF' } };
const SUBHEADER_FILL = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEAEEF6' } };
const SUBHEADER_FONT = { bold: true, color: { argb: 'FF3D5478' } };

const STAFF_EMAILS = new Set([
  'aj.halliday@proton.me',
  'michael@highonchapel.com'
]);
const isStaffEmail = (e) => !!e && STAFF_EMAILS.has(String(e).toLowerCase().trim());

// ── Per-cell status classifiers ─────────────────────────────────────────────
// Each returns one of: 'green' (fully complete) | 'black' (partial / in-progress)
//                      | 'red' (cancelled / refunded / voided / failed).

function classifyShopifyStatus(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'cancelled' || v === '(not found)') return 'red';
  return 'black';
}

function classifyFinancial(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'paid') return 'green';
  if (['refunded', 'partially_refunded', 'voided'].includes(v)) return 'red';
  return 'black';
}

function classifyFulfillment(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'fulfilled') return 'green';
  if (['restocked', 'cancelled'].includes(v)) return 'red';
  return 'black';
}

function classifyTillStatus(s) {
  const v = String(s || '').toLowerCase();
  if (['paid', 'completed', 'captured', 'success'].includes(v)) return 'green';
  if (['failed', 'declined', 'cancelled', 'voided', 'refunded', 'error'].includes(v)) return 'red';
  return 'black';
}

function classifyTillApproved(yesNo, tillStatus) {
  const v = String(tillStatus || '').toLowerCase();
  if (yesNo === 'Yes') return 'green';
  if (['failed', 'declined', 'cancelled', 'voided', 'error'].includes(v)) return 'red';
  return 'black';
}

function colorFor(category) {
  if (category === 'green') return TEXT_GREEN;
  if (category === 'red')   return TEXT_RED;
  return TEXT_BLACK;
}

// Row-level summary used only for the trailing "Category" column.
function classifyRowSummary({ tillPaid, shopifyPaid, fulfilled }) {
  const score = (tillPaid ? 1 : 0) + (shopifyPaid ? 1 : 0) + (fulfilled ? 1 : 0);
  if (score === 3) return 'green';
  if (score === 0) return 'red';
  return 'black';
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

  const sheet = wb.addWorksheet('Orders Report', {
    views: [{ state: 'frozen', ySplit: 1, showGridLines: false }]
  });

  // Column definitions for the main table (A-N).
  const columns = [
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
    { header: 'Category',        key: 'category',        width: 12 },
    // Spacer column then the colour key area (P, Q).
    { header: '',                key: '_spacer',         width: 4  },
    { header: '',                key: '_keyLabel',       width: 28 },
    { header: '',                key: '_keyDesc',        width: 60 }
  ];
  sheet.columns = columns;

  // ── Header row ────────────────────────────────────────────────────────────
  const headerRow = sheet.getRow(1);
  for (let i = 1; i <= 14; i++) {
    headerRow.getCell(i).fill = HEADER_FILL;
    headerRow.getCell(i).font = HEADER_FONT;
    headerRow.getCell(i).alignment = { vertical: 'middle', horizontal: 'left' };
    headerRow.getCell(i).border = { bottom: { style: 'thin', color: { argb: 'FF1F3A6E' } } };
  }
  headerRow.height = 22;

  // ── Colour key (rendered to the right of the header) ─────────────────────
  const keyCol1 = 16; // column P
  const keyCol2 = 17; // column Q
  sheet.getCell(1, keyCol1).value = 'Status Key';
  sheet.getCell(1, keyCol1).font = HEADER_FONT;
  sheet.getCell(1, keyCol1).fill = HEADER_FILL;
  sheet.getCell(1, keyCol1).alignment = { vertical: 'middle' };
  sheet.getCell(1, keyCol2).fill = HEADER_FILL;
  sheet.getCell(1, keyCol2).font = HEADER_FONT;

  // Per-cell colour key + staff highlight key.
  const keyEntries = [
    { color: TEXT_GREEN, label: 'GREEN text',  desc: 'Cell is fully complete (paid / fulfilled / captured)', fill: null },
    { color: TEXT_BLACK, label: 'BLACK text',  desc: 'Cell is partial / in-progress',                        fill: null },
    { color: TEXT_RED,   label: 'RED text',    desc: 'Cell is cancelled / refunded / voided / failed',       fill: null },
    { color: TEXT_BLACK, label: 'Light orange row', desc: 'Staff order (likely testing)',                    fill: STAFF_FILL }
  ];
  keyEntries.forEach((entry, i) => {
    const r = 2 + i;
    const labelCell = sheet.getCell(r, keyCol1);
    const descCell  = sheet.getCell(r, keyCol2);
    labelCell.value = entry.label;
    labelCell.font  = { bold: true, color: { argb: entry.color }, size: 12 };
    labelCell.alignment = { vertical: 'middle' };
    descCell.value = entry.desc;
    descCell.font  = { color: { argb: entry.color } };
    descCell.alignment = { vertical: 'middle' };
    if (entry.fill) {
      labelCell.fill = entry.fill;
      descCell.fill  = entry.fill;
    }
  });

  // ── Data rows ─────────────────────────────────────────────────────────────
  let greenCount = 0, amberCount = 0, redCount = 0;
  let totalAmount = 0, paidAmount = 0;

  for (const r of rows) {
    const summary = classifyRowSummary(r);
    if (summary === 'green') greenCount++;
    else if (summary === 'red') redCount++;
    else amberCount++;

    const amt = parseFloat(r.amount) || 0;
    totalAmount += amt;
    if (r.tillPaid && r.shopifyPaid) paidAmount += amt;

    const tillApprovedYesNo = r.tillPaid ? 'Yes' : 'No';
    const shopifyStatusVal  = r.shopifyOrderStatus || '(not found)';
    const fulfillmentVal    = r.fulfillmentStatus || 'unfulfilled';
    const financialVal      = r.financialStatus || '';
    const tillStatusVal     = r.tillStatus || '';

    const row = sheet.addRow({
      orderNumber: r.orderNumber || '',
      createdAt: r.createdAt ? new Date(r.createdAt) : '',
      customer: r.customer || '',
      email: r.email || '',
      amount: amt,
      currency: r.currency || '',
      shopifyStatus: shopifyStatusVal,
      financialStatus: financialVal,
      fulfillmentStatus: fulfillmentVal,
      tillStatus: tillStatusVal,
      tillApproved: tillApprovedYesNo,
      tillUuid: r.tillUuid || '',
      txnId: r.txnId || '',
      category: summary.toUpperCase()
    });

    row.getCell('amount').numFmt = '#,##0.00';
    row.getCell('createdAt').numFmt = 'yyyy-mm-dd hh:mm';

    // Default: black text everywhere.
    for (let i = 1; i <= 14; i++) {
      row.getCell(i).font = { color: { argb: TEXT_BLACK } };
    }

    // Per-cell coloured text only in the five status columns.
    row.getCell('shopifyStatus').font     = { color: { argb: colorFor(classifyShopifyStatus(shopifyStatusVal)) } };
    row.getCell('financialStatus').font   = { color: { argb: colorFor(classifyFinancial(financialVal)) } };
    row.getCell('fulfillmentStatus').font = { color: { argb: colorFor(classifyFulfillment(fulfillmentVal)) } };
    row.getCell('tillStatus').font        = { color: { argb: colorFor(classifyTillStatus(tillStatusVal)) } };
    row.getCell('tillApproved').font      = { color: { argb: colorFor(classifyTillApproved(tillApprovedYesNo, tillStatusVal)) } };

    // Trailing summary column (Category): bold, coloured by row summary.
    row.getCell('category').font = { bold: true, color: { argb: colorFor(summary) } };

    // Staff order? Paint the whole row (cols 1-14) with faint orange fill.
    if (isStaffEmail(r.email)) {
      for (let i = 1; i <= 14; i++) {
        row.getCell(i).fill = STAFF_FILL;
      }
    }
  }

  // ── Summary block, two blank rows below the table ─────────────────────────
  const summaryStart = sheet.lastRow.number + 3;
  const rangeStart = rows.length ? rows[rows.length - 1].createdAt : null;
  const rangeEnd   = rows.length ? rows[0].createdAt : null;

  // Summary heading row (merged across A-D).
  sheet.mergeCells(summaryStart, 1, summaryStart, 4);
  const heading = sheet.getCell(summaryStart, 1);
  heading.value = 'Summary';
  heading.fill  = HEADER_FILL;
  heading.font  = HEADER_FONT;
  heading.alignment = { vertical: 'middle' };
  sheet.getRow(summaryStart).height = 22;

  const staffCount = rows.filter((r) => isStaffEmail(r.email)).length;
  const summaryRows = [
    ['Report generated',          new Date()],
    ['Period start',              rangeStart ? new Date(rangeStart) : ''],
    ['Period end',                rangeEnd   ? new Date(rangeEnd)   : ''],
    ['Total orders',              rows.length],
    ['Fully complete',            greenCount, TEXT_GREEN],
    ['Partial / in-progress',     amberCount, TEXT_BLACK],
    ['Cancelled / refunded / failed', redCount, TEXT_RED],
    ['Staff orders (testing)',    staffCount, TEXT_BLACK],
    ['Total revenue (gross)',     totalAmount],
    ['Confirmed paid revenue',    paidAmount, TEXT_GREEN],
    ['Unconfirmed / unpaid',      totalAmount - paidAmount, TEXT_RED]
  ];

  for (let i = 0; i < summaryRows.length; i++) {
    const [metric, value, color] = summaryRows[i];
    const r = summaryStart + 1 + i;
    sheet.mergeCells(r, 1, r, 3); // metric label spans A-C
    const labelCell = sheet.getCell(r, 1);
    const valueCell = sheet.getCell(r, 4);
    labelCell.value = metric;
    labelCell.font  = SUBHEADER_FONT;
    labelCell.alignment = { vertical: 'middle' };
    valueCell.value = value;
    if (typeof value === 'number') valueCell.numFmt = '#,##0.00';
    if (value instanceof Date)     valueCell.numFmt = 'yyyy-mm-dd hh:mm';
    if (color) valueCell.font = { bold: true, color: { argb: color } };
    else       valueCell.font = { bold: true };
    valueCell.alignment = { vertical: 'middle' };
    if (i % 2 === 0) {
      labelCell.fill = SUBHEADER_FILL;
      valueCell.fill = SUBHEADER_FILL;
    }
  }

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
 * Send the report email with the xlsx attached. Uses Resend HTTP API if
 * RESEND_API_KEY is set; otherwise falls back to nodemailer/SMTP.
 */
async function sendReportEmail({ buffer, recipients, sinceDays, isTest, logger }) {
  const dateStr = new Date().toISOString().slice(0, 10);
  const filename = `hocs-orders-${dateStr}.xlsx`;
  const subject = `${isTest ? `[TEST ${new Date().toISOString().slice(11, 16)}] ` : ''}HOCS Weekly Orders Report — ${dateStr}`;
  const text =
    `Attached is the ${isTest ? 'test ' : ''}weekly orders report covering the last ${sinceDays} days.\n\n` +
    `Rows are colour-coded:\n` +
    `  GREEN  — Till took payment AND Shopify shows paid AND fulfilled\n` +
    `  AMBER  — partial state (one or two of the above)\n` +
    `  RED    — no payment, no fulfilment\n\n` +
    `See the Summary sheet for totals.\n`;

  const { RESEND_API_KEY, RESEND_FROM, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;

  // ── Path A: Resend HTTP API ────────────────────────────────────────────────
  if (RESEND_API_KEY) {
    const from = RESEND_FROM || 'HOCS Reports <reports@highonchapel.com>';
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from,
        to: recipients,
        subject,
        text,
        attachments: [{ filename, content: Buffer.from(buffer).toString('base64') }]
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Resend send failed: ${res.status} ${JSON.stringify(data)}`);
    }
    logger?.info?.('Weekly report sent via Resend', {
      messageId: data.id,
      recipients,
      isTest
    });
    return { messageId: data.id, provider: 'resend' };
  }

  // ── Path B: SMTP fallback ──────────────────────────────────────────────────
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error('No mail provider configured: set RESEND_API_KEY (preferred) or SMTP_HOST/USER/PASS');
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: parseInt(SMTP_PORT || '587', 10),
    secure: parseInt(SMTP_PORT || '587', 10) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });

  const result = await transporter.sendMail({
    from: SMTP_FROM ? `"${SMTP_FROM}" <${SMTP_USER}>` : SMTP_USER,
    to: recipients.join(', '),
    subject,
    text,
    attachments: [{ filename, content: buffer }]
  });

  logger?.info?.('Weekly report sent via SMTP', {
    messageId: result.messageId,
    recipients,
    isTest
  });
  return { messageId: result.messageId, provider: 'smtp' };
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
