function startOfDay(date = new Date()) {
  const copy = new Date(date);
  copy.setUTCHours(0, 0, 0, 0);
  return copy;
}

function daysAgo(days) {
  return new Date(Date.now() - days * 86_400_000);
}

module.exports = { startOfDay, daysAgo };
