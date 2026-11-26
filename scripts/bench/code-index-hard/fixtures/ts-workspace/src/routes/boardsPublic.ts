import { Router } from "express";
import { boardService } from "../services/boardService";
import { exportService } from "../services/exportService";

export const boardsPublicRouter = Router();

boardsPublicRouter.get("/:slug", (req, res) => {
  res.json(boardService.publicView(req.params.slug));
});

boardsPublicRouter.get("/:slug/export", (req, res) => {
  const board = boardService.published(req.params.slug);
  res.json(exportService.exportProject(board.projectId));
});
