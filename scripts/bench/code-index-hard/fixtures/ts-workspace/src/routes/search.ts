import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { searchService } from "../services/searchService";

export const searchRouter = Router();

searchRouter.get("/", (req, res) => {
  res.json(searchService.search((req as AuthedRequest).user, String(req.query.q ?? "")));
});
