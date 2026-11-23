const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);

// Merge a user-supplied options object into the defaults, recursively.
export function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (UNSAFE.has(key)) continue;
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      if (!Object.hasOwn(target, key) || !target[key] || typeof target[key] !== "object") target[key] = {};
      merge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

export function withDefaults(userOptions) {
  return merge({ retries: 3, nested: { verbose: false } }, userOptions);
}
