let counter = 1000;

export function newId(prefix: string): string {
  counter += 1;
  return `${prefix}_${counter.toString(36)}`;
}
