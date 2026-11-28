import { newId } from "../lib/ids";
import { badRequest } from "../lib/http";
import { issueToken } from "../lib/tokens";
import { hashPasscode } from "../lib/passcode";
import { orgRepo } from "../repositories/orgRepo";
import { userRepo } from "../repositories/userRepo";

export const authService = {
  login(email: string, passcode: string) {
    const user = userRepo.byEmail(String(email ?? ""));
    if (!user || user.passcode !== hashPasscode(String(passcode ?? ""))) throw badRequest("invalid credentials");
    return { token: issueToken(user.id), userId: user.id };
  },

  register(input: { name: string; email: string; passcode: string; orgName: string }) {
    const email = String(input.email ?? "").toLowerCase();
    if (!email || userRepo.byEmail(email)) throw badRequest("email unavailable");
    const org = orgRepo.insert({ id: newId("org"), name: String(input.orgName ?? "").slice(0, 80), plan: "free", seats: 3, renewsAt: "2027-01-01", paymentMethodLast4: "0000" });
    const user = userRepo.insert({ id: newId("usr"), orgId: org.id, name: String(input.name ?? "").slice(0, 80), email, role: "manager", passcode: hashPasscode(String(input.passcode ?? "")) });
    return { token: issueToken(user.id), userId: user.id };
  },
};
