export interface Order { id: string; userId: string; totalCents: number; paidCents: number; refundedCents: number; status: "open" | "paid" | "cancelled" }
export interface User { id: string; email: string; role: "user" | "admin" }
export interface Invite { token: string; teamId: string; email: string; role: "member" | "owner"; used: boolean }
export const orders = new Map<string, Order>();
export const users = new Map<string, User>();
export const invites = new Map<string, Invite>();
export const members: { teamId: string; userId: string; role: string }[] = [];
