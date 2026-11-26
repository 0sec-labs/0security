import { Router } from "express";
import { invoiceService } from "../../services/invoiceService";

export const internalInvoicesRouter = Router();

internalInvoicesRouter.get("/:id", (req, res) => {
  res.json(invoiceService.getById(req.params.id));
});
