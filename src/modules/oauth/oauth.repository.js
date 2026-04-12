import db from "../../db/client/db.js";
import { oauthAccounts, users } from "../../db/schemas/index.js";
import { eq } from "drizzle-orm";

export const findUserByEmail = async (email, tx = db) => {
  const [user] = await tx
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);
  return user || null;
};

export const findUserById = async (id, tx = db) => {
  const [user] = await tx.select().from(users).where(eq(users.id, id)).limit(1);

  return user || null;
};

export const createUser = async (payload, tx = db) => {
  const [created] = await tx.insert(users).values(payload).returning();
  return created;
};

export const upsertOauthAccount = async (payload, tx = db) => {
  const [row] = await tx
    .insert(oauthAccounts)
    .values(payload)
    .onConflictDoUpdate({
      target: [oauthAccounts.provider, oauthAccounts.providerAccountId],
      set: {
        accessToken: payload.accessToken,
        refreshToken: payload.refreshToken,
        expiresAt: payload.expiresAt,
        updatedAt: new Date(),
      },
    })
    .returning();

  return row;
};
