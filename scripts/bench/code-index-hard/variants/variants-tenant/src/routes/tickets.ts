import { Router } from "express";
import { ticketService } from "../services/ticketService";
import { badRequest } from "../lib/errors";

export const ticketsRouter = Router();

ticketsRouter.get("/", (req, res) => {
  res.json(ticketService.list(req.user!));
});

ticketsRouter.get("/:id", (req, res) => {
  res.json(ticketService.get(req.user!, req.params.id));
});

ticketsRouter.post("/:id/comments", (req, res) => {
  if (typeof req.body?.body !== "string" || !req.body.body.trim()) throw badRequest("comment body is required");
  res.status(201).json(ticketService.comment(req.user!, req.params.id, req.body.body));
});
