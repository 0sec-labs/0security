import { Repo } from "../lib/store";
import type { Team } from "../models/support";

export const teamRepo = new Repo<Team>("team");
