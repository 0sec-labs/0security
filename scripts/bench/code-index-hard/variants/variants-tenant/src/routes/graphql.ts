import { Router } from "express";
import { execute } from "../graphql/executor";
import { createLoaders } from "../graphql/loaders";

export const graphqlRouter = Router();

graphqlRouter.post("/", (req, res) => {
  const user = req.user!;
  const variables = req.body?.variables && typeof req.body.variables === "object" ? req.body.variables : {};
  const result = execute({ query: String(req.body?.query ?? ""), variables }, { user, loaders: createLoaders(user) });
  res.status("errors" in result ? 400 : 200).json(result);
});
