'use strict';

const fetch = require('node-fetch');
const nodemailer = require('nodemailer');

/**
 * Sends a confirmation email to a guest after a successful payment.
 * 
 * @param {Object} options
 * @param {string} options.to - Recipient email address
 * @param {string} options.orderNumber - Shopify order number
 * @param {string} options.amount - Order amount
 * @param {string} options.currency - Order currency
 * @param {string} options.storeUrl - Base store URL
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object>} Result of the email sending operation
 */
async function sendGuestConfirmationEmail({ to, orderNumber, amount, currency, storeUrl, logger }) {
  const subject = `Confirmation: Your High on Chapel Order #${orderNumber} has been paid`;
  const orderStatusUrl = `${storeUrl}/account/orders`; // Simplified URL, can be refined

  const text = `Dear Customer,

Thank you for your recent purchase from High on Chapel!

Your order #${orderNumber} for ${amount} ${currency} has been successfully placed and your payment has been confirmed.

You can view your order status here: ${orderStatusUrl}

We appreciate your business!

Sincerely,
The High on Chapel Team`;

  const html = `<p>Dear Customer,</p>
<p>Thank you for your recent purchase from <strong>High on Chapel</strong>!</p>
<p>Your order <strong>#${orderNumber}</strong> for <strong>${amount} ${currency}</strong> has been successfully placed and your payment has been confirmed.</p>
<p>You can view your order status here: <a href="${orderStatusUrl}">${orderStatusUrl}</a></p>
<p>We appreciate your business!</p>
<p>Sincerely,<br>The High on Chapel Team</p>`;

  const { 
    RESEND_API_KEY, 
    RESEND_FROM, 
    SMTP_HOST, 
    SMTP_PORT, 
    SMTP_USER, 
    SMTP_PASS, 
    SMTP_FROM 
  } = process.env;

  // ── Path A: Resend HTTP API ────────────────────────────────────────────────
  if (RESEND_API_KEY) {
    const from = RESEND_FROM || 'High on Chapel <orders@highonchapel.com>';
    try {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from,
          to: [to],
          subject,
          text,
          html
        })
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(`Resend send failed: ${res.status} ${JSON.stringify(data)}`);
      }

      logger?.info?.('Guest confirmation email sent via Resend', {
        messageId: data.id,
        recipient: to,
        orderNumber
      });
      return { success: true, messageId: data.id, provider: 'resend' };
    } catch (err) {
      logger?.error?.('Failed to send guest confirmation email via Resend', {
        error: err.message,
        recipient: to,
        orderNumber
      });
      // Fall through to SMTP if configured
    }
  }

  // ── Path B: SMTP fallback ──────────────────────────────────────────────────
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    try {
      const transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: parseInt(SMTP_PORT || '587', 10),
        secure: parseInt(SMTP_PORT || '587', 10) === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS }
      });

      const from = SMTP_FROM || `"High on Chapel" <${SMTP_USER}>`;
      const result = await transporter.sendMail({
        from,
        to,
        subject,
        text,
        html
      });

      logger?.info?.('Guest confirmation email sent via SMTP', {
        messageId: result.messageId,
        recipient: to,
        orderNumber
      });
      return { success: true, messageId: result.messageId, provider: 'smtp' };
    } catch (err) {
      logger?.error?.('Failed to send guest confirmation email via SMTP', {
        error: err.message,
        recipient: to,
        orderNumber
      });
    }
  }

  return { success: false, error: 'No email provider configured or all providers failed' };
}

module.exports = {
  sendGuestConfirmationEmail
};
