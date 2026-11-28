import { randomBytes } from "node:crypto";
import { hashPassword } from "./lib/password";
import { userRepo } from "./repositories/userRepo";
import { customerRepo } from "./repositories/customerRepo";
import { invoiceRepo } from "./repositories/invoiceRepo";
import { contractRepo } from "./repositories/contractRepo";
import { quoteRepo } from "./repositories/quoteRepo";
import { subscriptionRepo } from "./repositories/subscriptionRepo";
import { creditNoteRepo, paymentRepo, refundRepo } from "./repositories/billingRepos";
import { ticketCommentRepo, ticketRepo } from "./repositories/ticketRepo";
import { teamRepo } from "./repositories/teamRepo";
import { productRepo } from "./repositories/productRepo";
import { shipmentRepo } from "./repositories/shipmentRepo";
import { integrationRepo } from "./repositories/integrationRepo";
import { countryRepo, currencyRepo, planRepo } from "./repositories/referenceRepos";
import { contactRepo, dealRepo, leadRepo, campaignRepo, activityRepo, noteRepo, tagRepo } from "./repositories/crmRepos";
import { taskRepo, projectRepo, warehouseRepo, supplierRepo, purchaseOrderRepo, documentRepo, expenseRepo } from "./repositories/opsRepos";
import { categoryRepo, couponRepo, priceListRepo, taxRateRepo, apiKeyRepo, webhookEndpointRepo } from "./repositories/financeRepos";

let seeded = false;

export function seedDemoData(): void {
  if (seeded) return;
  seeded = true;
  const password = process.env.TENANTLY_SEED_PASSWORD ?? randomBytes(9).toString("hex");
  const passwordHash = hashPassword(password);

  userRepo.insert({ id: "usr_alice", orgId: "org_a", email: "alice@alpha.example", name: "Alice Meyer", role: "admin", passwordHash, disabled: false });
  userRepo.insert({ id: "usr_bob", orgId: "org_b", email: "bob@beta.example", name: "Bob Keller", role: "member", passwordHash, disabled: false });
  userRepo.insert({ id: "usr_bea", orgId: "org_b", email: "bea@beta.example", name: "Bea Winter", role: "admin", passwordHash, disabled: false });

  customerRepo.insert({ id: "cus_a1", orgId: "org_a", name: "Harbor Logistics", email: "ap@harbor.example", createdAt: "2026-01-04T10:00:00.000Z" });
  customerRepo.insert({ id: "cus_b1", orgId: "org_b", name: "Pine Studio", email: "billing@pine.example", createdAt: "2026-01-09T10:00:00.000Z" });

  invoiceRepo.insert({ id: "inv_a1", orgId: "org_a", customerId: "cus_a1", number: "INV-A-1001", status: "open", currency: "EUR", lines: [{ description: "Consulting retainer", qty: 1, unitPrice: 4200 }], total: 4200, dueDate: "2026-03-15", createdAt: "2026-02-15T08:00:00.000Z" });
  invoiceRepo.insert({ id: "inv_b1", orgId: "org_b", customerId: "cus_b1", number: "INV-B-2001", status: "open", currency: "USD", lines: [{ description: "Design sprint", qty: 2, unitPrice: 900 }], total: 1800, dueDate: "2026-03-20", createdAt: "2026-02-16T08:00:00.000Z" });

  contractRepo.insert({ id: "con_a1", orgId: "org_a", customerId: "cus_a1", title: "Master services agreement", terms: "Net 30, renews yearly with a 12 percent uplift", value: 98000, startsOn: "2026-01-01", endsOn: "2026-12-31", status: "active" });
  contractRepo.insert({ id: "con_b1", orgId: "org_b", customerId: "cus_b1", title: "Studio retainer", terms: "Monthly, cancel with 60 days notice", value: 24000, startsOn: "2026-02-01", endsOn: "2027-01-31", status: "active" });

  quoteRepo.insert({ id: "quo_a1", orgId: "org_a", customerId: "cus_a1", title: "Warehouse automation phase 2", lines: [{ description: "Conveyor retrofit", qty: 1, unitPrice: 15500 }], total: 15500, validUntil: "2026-04-30", status: "sent", internalNotes: "Floor price is 14000, discount allowed once" });
  quoteRepo.insert({ id: "quo_b1", orgId: "org_b", customerId: "cus_b1", title: "Brand refresh", lines: [{ description: "Identity package", qty: 1, unitPrice: 6200 }], total: 6200, validUntil: "2026-05-15", status: "draft", internalNotes: "Stretch goal is a retainer" });

  subscriptionRepo.insert({ id: "sub_a1", orgId: "org_a", customerId: "cus_a1", planId: "plan_pro", status: "active", seats: 25, currentPeriodEnd: "2026-06-30", monthlyAmount: 1250, paymentMethodLast4: "4242" });
  subscriptionRepo.insert({ id: "sub_b1", orgId: "org_b", customerId: "cus_b1", planId: "plan_basic", status: "active", seats: 5, currentPeriodEnd: "2026-06-30", monthlyAmount: 250, paymentMethodLast4: "1881" });

  paymentRepo.insert({ id: "pay_a1", orgId: "org_a", invoiceId: "inv_a1", amount: 1000, method: "bank", receivedAt: "2026-02-20T12:00:00.000Z" });
  paymentRepo.insert({ id: "pay_b1", orgId: "org_b", invoiceId: "inv_b1", amount: 500, method: "card", receivedAt: "2026-02-21T12:00:00.000Z" });
  creditNoteRepo.insert({ id: "cn_a1", orgId: "org_a", invoiceId: "inv_a1", amount: 150, reason: "Goodwill adjustment" });
  creditNoteRepo.insert({ id: "cn_b1", orgId: "org_b", invoiceId: "inv_b1", amount: 50, reason: "Duplicate line" });
  refundRepo.insert({ id: "rfd_a1", orgId: "org_a", paymentId: "pay_a1", amount: 200, status: "pending" });
  refundRepo.insert({ id: "rfd_b1", orgId: "org_b", paymentId: "pay_b1", amount: 75, status: "pending" });

  ticketRepo.insert({ id: "tkt_a1", orgId: "org_a", customerId: "cus_a1", subject: "Refund dispute on the March order", body: "Customer claims the pallets arrived damaged.", status: "open", priority: "high", createdAt: "2026-03-02T09:30:00.000Z" });
  ticketRepo.insert({ id: "tkt_b1", orgId: "org_b", customerId: "cus_b1", subject: "Logo files missing", body: "Where are the vector exports?", status: "open", priority: "normal", createdAt: "2026-03-03T09:30:00.000Z" });
  ticketCommentRepo.insert({ id: "tcm_a1", orgId: "org_a", ticketId: "tkt_a1", authorId: "usr_alice", body: "Carrier photos requested.", createdAt: "2026-03-02T10:00:00.000Z" });
  ticketCommentRepo.insert({ id: "tcm_b1", orgId: "org_b", ticketId: "tkt_b1", authorId: "usr_bob", body: "Sending the files today.", createdAt: "2026-03-03T10:00:00.000Z" });

  teamRepo.insert({ id: "team_a1", orgId: "org_a", name: "Collections", memberIds: ["usr_alice"] });
  teamRepo.insert({ id: "team_b1", orgId: "org_b", name: "Studio", memberIds: ["usr_bob", "usr_bea"] });

  productRepo.insert({ id: "prd_a1", orgId: "org_a", sku: "A-100", name: "Pallet jack", unitPrice: 450, unitCost: 280, active: true });
  productRepo.insert({ id: "prd_b1", orgId: "org_b", sku: "B-200", name: "Easel stand", unitPrice: 120, unitCost: 55, active: true });

  shipmentRepo.add({ id: "shp_a1", orgId: "org_a", orderRef: "SO-5521", carrier: "Fastline", trackingNo: "FL-77120", status: "in_transit", cost: 182.4, billedAmount: 240, destination: "Rotterdam", events: [{ status: "picked_up", at: "2026-03-01T07:00:00.000Z" }] });
  shipmentRepo.add({ id: "shp_b1", orgId: "org_b", orderRef: "SO-7710", carrier: "Quickpost", trackingNo: "QP-4410", status: "label_created", cost: 18.9, billedAmount: 25, destination: "Zurich", events: [{ status: "label_created", at: "2026-03-02T07:00:00.000Z" }] });

  integrationRepo.insert({ id: "ia_a1", orgId: "org_a", provider: "payments", externalAccountId: "acct_alpha" });
  integrationRepo.insert({ id: "ia_b1", orgId: "org_b", provider: "payments", externalAccountId: "acct_beta" });
  integrationRepo.insert({ id: "ia_a2", orgId: "org_a", provider: "carrier", externalAccountId: "car_alpha" });
  integrationRepo.insert({ id: "ia_b2", orgId: "org_b", provider: "carrier", externalAccountId: "car_beta" });

  currencyRepo.insert({ id: "EUR", name: "Euro", symbol: "EUR" });
  currencyRepo.insert({ id: "USD", name: "US dollar", symbol: "$" });
  currencyRepo.insert({ id: "CHF", name: "Swiss franc", symbol: "CHF" });
  countryRepo.insert({ id: "NL", name: "Netherlands" });
  countryRepo.insert({ id: "CH", name: "Switzerland" });
  planRepo.insert({ id: "plan_basic", name: "Basic", monthlyAmount: 50, seatLimit: 5 });
  planRepo.insert({ id: "plan_pro", name: "Pro", monthlyAmount: 50, seatLimit: 100 });

  contactRepo.insert({ id: "cnt_a1", orgId: "org_a", name: "Sample name a", email: "Sample email a", phone: "Sample phone a", title: "Sample title a", createdAt: "2026-02-01T09:00:00.000Z" });
  contactRepo.insert({ id: "cnt_b1", orgId: "org_b", name: "Sample name b", email: "Sample email b", phone: "Sample phone b", title: "Sample title b", createdAt: "2026-02-01T09:00:00.000Z" });
  dealRepo.insert({ id: "dl_a1", orgId: "org_a", title: "Sample title a", amount: 10, stage: "Sample stage a", customerId: "Sample customerId a", createdAt: "2026-02-01T09:00:00.000Z" });
  dealRepo.insert({ id: "dl_b1", orgId: "org_b", title: "Sample title b", amount: 10, stage: "Sample stage b", customerId: "Sample customerId b", createdAt: "2026-02-01T09:00:00.000Z" });
  leadRepo.insert({ id: "ld_a1", orgId: "org_a", name: "Sample name a", email: "Sample email a", source: "Sample source a", score: 10, createdAt: "2026-02-01T09:00:00.000Z" });
  leadRepo.insert({ id: "ld_b1", orgId: "org_b", name: "Sample name b", email: "Sample email b", source: "Sample source b", score: 10, createdAt: "2026-02-01T09:00:00.000Z" });
  campaignRepo.insert({ id: "cmp_a1", orgId: "org_a", name: "Sample name a", channel: "Sample channel a", budget: 10, active: true, createdAt: "2026-02-01T09:00:00.000Z" });
  campaignRepo.insert({ id: "cmp_b1", orgId: "org_b", name: "Sample name b", channel: "Sample channel b", budget: 10, active: true, createdAt: "2026-02-01T09:00:00.000Z" });
  activityRepo.insert({ id: "act_a1", orgId: "org_a", kind: "Sample kind a", summary: "Sample summary a", dueOn: "Sample dueOn a", createdAt: "2026-02-01T09:00:00.000Z" });
  activityRepo.insert({ id: "act_b1", orgId: "org_b", kind: "Sample kind b", summary: "Sample summary b", dueOn: "Sample dueOn b", createdAt: "2026-02-01T09:00:00.000Z" });
  noteRepo.insert({ id: "nt_a1", orgId: "org_a", subject: "Sample subject a", body: "Sample body a", createdAt: "2026-02-01T09:00:00.000Z" });
  noteRepo.insert({ id: "nt_b1", orgId: "org_b", subject: "Sample subject b", body: "Sample body b", createdAt: "2026-02-01T09:00:00.000Z" });
  tagRepo.insert({ id: "tg_a1", orgId: "org_a", label: "Sample label a", color: "Sample color a", createdAt: "2026-02-01T09:00:00.000Z" });
  tagRepo.insert({ id: "tg_b1", orgId: "org_b", label: "Sample label b", color: "Sample color b", createdAt: "2026-02-01T09:00:00.000Z" });
  taskRepo.insert({ id: "tsk_a1", orgId: "org_a", title: "Sample title a", done: true, dueOn: "Sample dueOn a", assigneeId: "Sample assigneeId a", createdAt: "2026-02-01T09:00:00.000Z" });
  taskRepo.insert({ id: "tsk_b1", orgId: "org_b", title: "Sample title b", done: true, dueOn: "Sample dueOn b", assigneeId: "Sample assigneeId b", createdAt: "2026-02-01T09:00:00.000Z" });
  projectRepo.insert({ id: "prj_a1", orgId: "org_a", name: "Sample name a", status: "Sample status a", budget: 10, createdAt: "2026-02-01T09:00:00.000Z" });
  projectRepo.insert({ id: "prj_b1", orgId: "org_b", name: "Sample name b", status: "Sample status b", budget: 10, createdAt: "2026-02-01T09:00:00.000Z" });
  warehouseRepo.insert({ id: "wh_a1", orgId: "org_a", name: "Sample name a", city: "Sample city a", capacity: 10, createdAt: "2026-02-01T09:00:00.000Z" });
  warehouseRepo.insert({ id: "wh_b1", orgId: "org_b", name: "Sample name b", city: "Sample city b", capacity: 10, createdAt: "2026-02-01T09:00:00.000Z" });
  supplierRepo.insert({ id: "sup_a1", orgId: "org_a", name: "Sample name a", email: "Sample email a", terms: "Sample terms a", createdAt: "2026-02-01T09:00:00.000Z" });
  supplierRepo.insert({ id: "sup_b1", orgId: "org_b", name: "Sample name b", email: "Sample email b", terms: "Sample terms b", createdAt: "2026-02-01T09:00:00.000Z" });
  purchaseOrderRepo.insert({ id: "po_a1", orgId: "org_a", supplierId: "Sample supplierId a", reference: "Sample reference a", amount: 10, status: "Sample status a", createdAt: "2026-02-01T09:00:00.000Z" });
  purchaseOrderRepo.insert({ id: "po_b1", orgId: "org_b", supplierId: "Sample supplierId b", reference: "Sample reference b", amount: 10, status: "Sample status b", createdAt: "2026-02-01T09:00:00.000Z" });
  documentRepo.insert({ id: "doc_a1", orgId: "org_a", title: "Sample title a", kind: "Sample kind a", url: "Sample url a", createdAt: "2026-02-01T09:00:00.000Z" });
  documentRepo.insert({ id: "doc_b1", orgId: "org_b", title: "Sample title b", kind: "Sample kind b", url: "Sample url b", createdAt: "2026-02-01T09:00:00.000Z" });
  expenseRepo.insert({ id: "exp_a1", orgId: "org_a", description: "Sample description a", amount: 10, category: "Sample category a", incurredOn: "Sample incurredOn a", createdAt: "2026-02-01T09:00:00.000Z" });
  expenseRepo.insert({ id: "exp_b1", orgId: "org_b", description: "Sample description b", amount: 10, category: "Sample category b", incurredOn: "Sample incurredOn b", createdAt: "2026-02-01T09:00:00.000Z" });
  categoryRepo.insert({ id: "cat_a1", orgId: "org_a", name: "Sample name a", parentId: "Sample parentId a", createdAt: "2026-02-01T09:00:00.000Z" });
  categoryRepo.insert({ id: "cat_b1", orgId: "org_b", name: "Sample name b", parentId: "Sample parentId b", createdAt: "2026-02-01T09:00:00.000Z" });
  couponRepo.insert({ id: "cpn_a1", orgId: "org_a", code: "Sample code a", percentOff: 10, active: true, createdAt: "2026-02-01T09:00:00.000Z" });
  couponRepo.insert({ id: "cpn_b1", orgId: "org_b", code: "Sample code b", percentOff: 10, active: true, createdAt: "2026-02-01T09:00:00.000Z" });
  priceListRepo.insert({ id: "pl_a1", orgId: "org_a", name: "Sample name a", currency: "Sample currency a", createdAt: "2026-02-01T09:00:00.000Z" });
  priceListRepo.insert({ id: "pl_b1", orgId: "org_b", name: "Sample name b", currency: "Sample currency b", createdAt: "2026-02-01T09:00:00.000Z" });
  taxRateRepo.insert({ id: "tax_a1", orgId: "org_a", name: "Sample name a", ratePercent: 10, region: "Sample region a", createdAt: "2026-02-01T09:00:00.000Z" });
  taxRateRepo.insert({ id: "tax_b1", orgId: "org_b", name: "Sample name b", ratePercent: 10, region: "Sample region b", createdAt: "2026-02-01T09:00:00.000Z" });
  apiKeyRepo.insert({ id: "key_a1", orgId: "org_a", label: "Sample label a", prefix: "Sample prefix a", scopes: "Sample scopes a", createdAt: "2026-02-01T09:00:00.000Z" });
  apiKeyRepo.insert({ id: "key_b1", orgId: "org_b", label: "Sample label b", prefix: "Sample prefix b", scopes: "Sample scopes b", createdAt: "2026-02-01T09:00:00.000Z" });
  webhookEndpointRepo.insert({ id: "whe_a1", orgId: "org_a", url: "Sample url a", events: "Sample events a", active: true, createdAt: "2026-02-01T09:00:00.000Z" });
  webhookEndpointRepo.insert({ id: "whe_b1", orgId: "org_b", url: "Sample url b", events: "Sample events b", active: true, createdAt: "2026-02-01T09:00:00.000Z" });
}
