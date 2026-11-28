import type { OrgRecord } from "../models/base";

export class Repo<T extends OrgRecord> {
  protected rows = new Map<string, T>();

  constructor(readonly label: string) {}

  findById(id: string): T | undefined {
    return this.rows.get(id);
  }

  findForOrg(orgId: string, id: string): T | undefined {
    const row = this.rows.get(id);
    return row && row.orgId === orgId ? row : undefined;
  }

  listForOrg(orgId: string): T[] {
    return [...this.rows.values()].filter((row) => row.orgId === orgId);
  }

  insert(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  save(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  remove(id: string): boolean {
    return this.rows.delete(id);
  }
}

/** Reference data shared by every organisation (no orgId). */
export class RefRepo<T extends { id: string }> {
  private rows = new Map<string, T>();

  insert(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  findById(id: string): T | undefined {
    return this.rows.get(id);
  }

  list(): T[] {
    return [...this.rows.values()];
  }
}
