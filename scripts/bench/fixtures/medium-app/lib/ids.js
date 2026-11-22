let counter = 0;

function nextOrderRef() {
  counter += 1;
  return `ORD-${Date.now().toString(36)}-${counter}`;
}

function isOrderRef(value) {
  return /^ORD-[a-z0-9]+-\d+$/.test(String(value));
}

module.exports = { nextOrderRef, isOrderRef };
