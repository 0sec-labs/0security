import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { noteService } from "../services/noteService";
import { parseNoteInput } from "../validators/note";

export const notesRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

notesRouter.get("/", (req, res) => {
  res.json(noteService.list(who(req)));
});

notesRouter.post("/", (req, res) => {
  res.status(201).json(noteService.create(who(req), parseNoteInput(req.body)));
});

notesRouter.get("/:id", (req, res) => {
  res.json(noteService.require(who(req), req.params.id));
});

notesRouter.put("/:id", (req, res) => {
  res.json(noteService.update(who(req), req.params.id, parseNoteInput(req.body)));
});

notesRouter.delete("/:id", (req, res) => {
  noteService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

notesRouter.post("/:id/archive", (req, res) => {
  res.json(noteService.archive(who(req), req.params.id));
});
