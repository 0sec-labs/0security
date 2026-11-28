import { Router } from "express";
import { badRequest } from "../lib/errors";
import { previewOrderImport } from "../services/importService";

export const importsRouter = Router();

importsRouter.post("/orders/preview", (req, res) => {
  if (typeof req.body?.csv !== "string" || req.body.csv.length > 200_000) throw badRequest("csv text is required");
  res.json(previewOrderImport(req.user!, req.body.csv));
});
