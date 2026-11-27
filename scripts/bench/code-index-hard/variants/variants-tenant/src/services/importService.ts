import { parseCsv } from "../lib/csv";
import { customerRepo } from "../repositories/customerRepo";
import { productRepo } from "../repositories/productRepo";
import type { AuthUser } from "../models/base";

export interface PreviewRow {
  line: number;
  customer: string;
  productId: string;
  name: string;
  unitPrice: number;
  unitCost: number;
  quantity: number;
  lineTotal: number;
  margin: number;
}

function resolveCustomer(user: AuthUser, ref: string) {
  return customerRepo.findForOrg(user.orgId, ref) ?? null;
}

function resolveProduct(ref: string) {
  return productRepo.findById(ref) ?? null;
}

export function previewOrderImport(user: AuthUser, csv: string) {
  const rows: PreviewRow[] = [];
  const problems: string[] = [];
  parseCsv(csv).forEach((row, index) => {
    const line = index + 2;
    const customer = resolveCustomer(user, row.customerId ?? "");
    if (!customer) return void problems.push("line " + line + ": unknown customer");
    const product = resolveProduct(row.productId ?? "");
    if (!product) return void problems.push("line " + line + ": unknown product");
    const quantity = Number(row.quantity);
    if (!Number.isInteger(quantity) || quantity <= 0) return void problems.push("line " + line + ": bad quantity");
    rows.push({
      line,
      customer: customer.name,
      productId: product.id,
      name: product.name,
      unitPrice: product.unitPrice,
      unitCost: product.unitCost,
      quantity,
      lineTotal: product.unitPrice * quantity,
      margin: (product.unitPrice - product.unitCost) * quantity,
    });
  });
  return { rows, problems, total: rows.reduce((sum, row) => sum + row.lineTotal, 0) };
}
