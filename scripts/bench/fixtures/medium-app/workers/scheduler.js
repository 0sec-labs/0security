const cron = require("node-cron");
const { run } = require("../db");
const { daysAgo } = require("../lib/dates");

cron.schedule("0 3 * * *", async () => {
  await run("DELETE FROM notifications WHERE read = 1 AND created_at < ?", [daysAgo(30).toISOString()]);
});

cron.schedule("*/10 * * * *", async () => {
  await run("UPDATE orders SET status = 'expired' WHERE status = 'pending' AND created_at < ?", [daysAgo(2).toISOString()]);
});
