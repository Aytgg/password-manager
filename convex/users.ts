import { ConvexError, v } from "convex/values";

import { mutation, query } from "./_generated/server";
import { assertPublicKey, requireUserId } from "./lib";

/**
 * Oturumdaki kullanıcının profilini ve açık anahtarını kaydeder.
 *
 * Açık anahtar değiştiyse (ör. yerel kasa sıfırlandı) eski anahtara
 * paketlenmiş erişimler artık çözülemez; bu yüzden kullanıcının tüm erişim
 * satırları silinir.
 */
export const upsertMe = mutation({
  args: {
    email: v.string(),
    displayName: v.string(),
    publicKey: v.string(),
  },
  handler: async (ctx, args) => {
    const clerkId = await requireUserId(ctx);

    const email = args.email.trim();
    const displayName = args.displayName.trim();

    if (!email.includes("@") || email.length > 320) {
      throw new ConvexError("Geçersiz e-posta adresi.");
    }

    if (!displayName || displayName.length > 200) {
      throw new ConvexError("Geçersiz görünen ad.");
    }

    assertPublicKey(args.publicKey);

    const existing = await ctx.db
      .query("users")
      .withIndex("by_clerk_id", (q) => q.eq("clerkId", clerkId))
      .unique();

    const now = Date.now();

    if (!existing) {
      await ctx.db.insert("users", {
        clerkId,
        email,
        displayName,
        publicKey: args.publicKey,
        updatedAt: now,
      });
      return;
    }

    if (existing.publicKey !== args.publicKey) {
      const staleAccesses = await ctx.db
        .query("itemAccess")
        .withIndex("by_user", (q) => q.eq("userId", clerkId))
        .collect();

      for (const access of staleAccesses) {
        await ctx.db.delete(access._id);
      }
    }

    await ctx.db.patch(existing._id, {
      email,
      displayName,
      publicKey: args.publicKey,
      updatedAt: now,
    });
  },
});

/** Yetki verilebilecek diğer kullanıcılar ve açık anahtarları. */
export const listOthers = query({
  args: {},
  handler: async (ctx) => {
    const clerkId = await requireUserId(ctx);

    const users = await ctx.db.query("users").collect();

    return users
      .filter((user) => user.clerkId !== clerkId)
      .map((user) => ({
        userId: user.clerkId,
        email: user.email,
        displayName: user.displayName,
        publicKey: user.publicKey,
      }))
      .sort((a, b) => a.displayName.localeCompare(b.displayName, "tr"));
  },
});
