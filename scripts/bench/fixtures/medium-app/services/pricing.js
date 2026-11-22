const { all } = require("../db");

async function priceItems(items) {
  const ids = items.map(item => Number(item.productId)).filter(Number.isSafeInteger);
  const rows = await all(`SELECT id, price_cents FROM products WHERE id IN (${ids.map(() => "?").join(",")})`, ids);
  const byId = new Map(rows.map(row => [row.id, row.price_cents]));
  let totalCents = 0;
  for (const item of items) totalCents += (byId.get(Number(item.productId)) || 0) * Math.max(1, Math.min(99, Number(item.qty) || 1));
  return { totalCents };
}

module.exports = { priceItems };
