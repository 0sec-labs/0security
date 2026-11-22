function positiveInt(value) {
  const n = Number.parseInt(value, 10);
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

function requireFields(...names) {
  return (req, res, next) => {
    const missing = names.filter(name => req.body?.[name] === undefined);
    if (missing.length) return res.status(400).json({ error: `missing ${missing.join(", ")}` });
    next();
  };
}

module.exports = { positiveInt, requireFields };
