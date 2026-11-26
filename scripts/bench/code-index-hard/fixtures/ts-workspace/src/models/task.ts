export interface Task {
  id: string;
  orgId: string;
  projectId: string;
  ownerId: string;
  parentId?: string;
  title: string;
  notes: string;
  visibility: "public" | "private";
  watchers: string[];
  status: "open" | "done";
}
