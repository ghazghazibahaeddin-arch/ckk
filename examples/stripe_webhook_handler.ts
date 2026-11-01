/**
 * Real Stripe Webhook Ingestion Example for CCK.
 *
 * Demonstrates ingesting Stripe dispute / refund events to instantly
 * invalidate preconditions and stop autonomous agents from double-disbursing funds.
 */

async function sendStripeRefundWebhook(orderId: string, chargeId: string) {
  const url = 'http://localhost:3000/api/v1/webhooks/ingest';
  const payload = {
    entity_id: `order:${orderId}`,
    field_name: 'status',
    value: 'refunded',
    source: 'stripe_live_webhook',
    payload: {
      event_type: 'charge.refunded',
      charge_id: chargeId,
      amount_refunded: 12000,
      currency: 'usd',
      created_at: new Date().toISOString(),
    },
  };

  console.log(`[Stripe Webhook] Sending charge.refunded event for order ${orderId}...`);
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const result = await response.json();
  console.log('[CCK Webhook Ingestion Result]:', result);
  console.log(`[Causal Continuity Status]: Fact ${result.entity_id}.${result.field_name} is now ${result.fact_state}!`);
}

sendStripeRefundWebhook('1099', 'ch_3N4k8x2eZvKYlo2C1fQ7rY').catch(console.error);
