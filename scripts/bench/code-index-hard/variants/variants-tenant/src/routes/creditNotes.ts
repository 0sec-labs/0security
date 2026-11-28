import { Router } from "express";
import { creditNoteRepo } from "../repositories/billingRepos";
import { assertSameOrg } from "../lib/policy";
import { notFound } from "../lib/errors";

export const creditNotesRouter = Router();

creditNotesRouter.get("/", (req, res) => {
  res.json(creditNoteRepo.listForOrg(req.user!.orgId));
});

creditNotesRouter.get("/:id", (req, res) => {
  const note = creditNoteRepo.findById(req.params.id);
  if (!note) throw notFound("credit note");
  assertSameOrg(req.user!, note, "credit note");
  res.json(note);
});
