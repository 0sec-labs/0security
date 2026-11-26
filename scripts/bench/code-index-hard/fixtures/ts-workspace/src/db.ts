export class Table<T extends { id: string }> {
  private rows = new Map<string, T>();

  constructor(readonly name: string) {}

  get(id: string): T | undefined {
    return this.rows.get(id);
  }

  all(): T[] {
    return [...this.rows.values()];
  }

  where(predicate: (row: T) => boolean): T[] {
    return this.all().filter(predicate);
  }

  insert(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  update(id: string, patch: Partial<T>): T | undefined {
    const current = this.rows.get(id);
    if (!current) return undefined;
    const next = { ...current, ...patch, id } as T;
    this.rows.set(id, next);
    return next;
  }

  remove(id: string): boolean {
    return this.rows.delete(id);
  }
}
