import { Repo } from "../lib/store";
import type { Task, Project, Warehouse, Supplier, PurchaseOrder, Document, Expense } from "../models/ops";

export const taskRepo = new Repo<Task>("tasks");
export const projectRepo = new Repo<Project>("projects");
export const warehouseRepo = new Repo<Warehouse>("warehouses");
export const supplierRepo = new Repo<Supplier>("suppliers");
export const purchaseOrderRepo = new Repo<PurchaseOrder>("purchaseOrders");
export const documentRepo = new Repo<Document>("documents");
export const expenseRepo = new Repo<Expense>("expenses");
