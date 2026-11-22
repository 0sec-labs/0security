const { money } = require("../lib/strings");

async function render(order) {
  const lines = [`Invoice for order ${order.id}`, `Status: ${order.status}`, `Total: ${money(order.total_cents)}`];
  return Buffer.from(lines.join("\n"), "utf8");
}

module.exports = { render };
