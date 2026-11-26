export interface Org {
  id: string;
  name: string;
  plan: "free" | "team" | "business";
  seats: number;
  renewsAt: string;
  paymentMethodLast4: string;
}
