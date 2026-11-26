export interface Notification {
  id: string;
  orgId: string;
  ownerId: string;
  title: string;
  channel: string;
  archived: boolean;
  createdAt: string;
}
