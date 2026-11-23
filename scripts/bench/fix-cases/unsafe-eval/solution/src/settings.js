// Parse a settings document that a user pasted into the import box.
export function parseSettings(text) {
  return JSON.parse(text);
}

export function theme(settings) {
  return settings.theme ?? "light";
}
