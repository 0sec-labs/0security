import { Table } from "../db";
import type { Board } from "../models/board";

const table = new Table<Board>("boards");

export const boardRepo = {
  bySlug: (slug: string) => table.where((b) => b.slug === slug)[0],
  insert: (board: Board) => table.insert(board),
};
