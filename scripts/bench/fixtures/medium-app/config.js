const path = require("path");

module.exports = {
  PORT: Number(process.env.PORT || 3000),
  DB_FILE: process.env.DB_FILE || "shop.db",
  JWT_SECRET: "Vq8Zt3vN0xLw2Rb7YpK5mD1sH9cEfJ6aUo4Xg",
  UPLOAD_DIR: path.join(__dirname, "uploads"),
  EXPORT_DIR: path.join(__dirname, "exports"),
  MAIL_FROM: "shop@example.test",
  PAGE_SIZE: 25,
};
