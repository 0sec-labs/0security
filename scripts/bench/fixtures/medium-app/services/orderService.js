const { get, run } = require("../db");
const { nextOrderRef } = require("../lib/ids");
const { priceItems } = require("./pricing");
const mailer = require("./mailer");

async function place(userId, items) {
  const priced = await priceItems(items);
  const result = await run("INSERT INTO orders(user_id, ref, status, total_cents) VALUES(?, ?, 'pending', ?)", [userId, nextOrderRef(), priced.totalCents]);
  const user = await get("SELECT email FROM users WHERE id = ?", [userId]);
  await mailer.send(user.email, "Order received", `Your order #${result.lastID} is pending payment.`);
  return { id: result.lastID, totalCents: priced.totalCents };
}

module.exports = { place };
