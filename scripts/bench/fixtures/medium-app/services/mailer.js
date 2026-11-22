const { MAIL_FROM } = require("../config");

const outbox = [];

async function send(to, subject, text) {
  if (!/^[^\s@]+@[^\s@]+$/.test(to)) throw new Error("bad address");
  outbox.push({ from: MAIL_FROM, to, subject, text: String(text).slice(0, 2000) });
}

function pending() {
  return outbox.splice(0, outbox.length);
}

module.exports = { send, pending };
