import { Repo } from "../lib/store";
import type { User } from "../models/base";

class UserRepo extends Repo<User> {
  findByEmail(email: string): User | undefined {
    const wanted = email.toLowerCase();
    for (const user of this.rows.values()) if (user.email === wanted) return user;
    return undefined;
  }
}

export const userRepo = new UserRepo("user");
