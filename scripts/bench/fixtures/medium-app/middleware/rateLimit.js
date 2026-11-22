const hits = new Map();

function rateLimit({ perMinute }) {
  return (req, res, next) => {
    const key = `${req.ip}:${Math.floor(Date.now() / 60000)}`;
    const count = (hits.get(key) || 0) + 1;
    hits.set(key, count);
    if (count > perMinute) return res.sendStatus(429);
    next();
  };
}

module.exports = { rateLimit };
