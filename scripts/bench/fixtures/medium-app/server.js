// Shop backend: users, products, orders, invoices, reports.
const express = require("express");
const { requestLog } = require("./middleware/logging");
const { rateLimit } = require("./middleware/rateLimit");
const { errorHandler } = require("./middleware/errors");
const { PORT } = require("./config");

const app = express();
app.use(express.json());
app.use(requestLog);
app.use(rateLimit({ perMinute: 120 }));

app.use("/auth", require("./routes/auth"));
app.use("/users", require("./routes/users"));
app.use("/products", require("./routes/products"));
app.use("/orders", require("./routes/orders"));
app.use("/invoices", require("./routes/invoices"));
app.use("/reports", require("./routes/reports"));
app.use("/files", require("./routes/files"));
app.use("/search", require("./routes/search"));
app.use("/teams", require("./routes/teams"));
app.use("/notifications", require("./routes/notifications"));
app.use("/webhooks", require("./routes/webhooks"));
app.use("/admin", require("./routes/admin"));
app.get("/health", (req, res) => res.json({ ok: true }));

app.use(errorHandler);
app.listen(PORT);
