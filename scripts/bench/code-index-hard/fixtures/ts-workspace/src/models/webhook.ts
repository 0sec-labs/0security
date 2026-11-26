export interface Webhook {
  id: string;
  orgId: string;
  url: string;
  authToken: string;
  events: string[];
  active: boolean;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  event: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  responseStatus: number;
}
