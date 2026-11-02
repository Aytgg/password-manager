import { getAuthUserId } from "@convex-dev/auth/server";
import { ConvexError, v } from "convex/values";

import type { Id } from "./_generated/dataModel";
import { mutation, query } from "./_generated/server";
import { assertPublicKey, assertWrappedKey, requireActiveUser } from "./lib";
import { wrappedKey } from "./schema";

export const me = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);

    if (!userId) {
      return null;
    }

    const user = await ctx.db.get(userId);

    if (!user) {
      return null;
    }

    const department = user.departmentId
      ? await ctx.db.get(user.departmentId)
      : null;

    return {
      id: user._id,
      email: user.email,
      displayName: user.displayName ?? user.email,
      role: user.role,
      status: user.status,
      departmentId: user.departmentId ?? null,
      departmentName: department?.name ?? null,
      publicKey: user.publicKey ?? null,
    };
  },
});

export const setPublicKey = mutation({
  args: { publicKey: v.string() },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);

    assertPublicKey(args.publicKey);

    if (user.publicKey === args.publicKey) {
      return;
    }

    // Eski anahtara paketlenmiş erişimler yeni anahtarla açılamaz; kaldırılır
    // ve paylaşım kuralına göre anahtar sahiplerince yeniden doldurulur.
    if (user.publicKey !== undefined) {
      for (const access of await ctx.db
        .query("itemAccess")
        .withIndex("by_user", (q) => q.eq("userId", user._id))
        .collect()) {
        await ctx.db.delete(access._id);
      }

      for (const key of await ctx.db
        .query("departmentKeys")
        .withIndex("by_user", (q) => q.eq("userId", user._id))
        .collect()) {
        await ctx.db.delete(key._id);
      }
    }

    await ctx.db.patch(user._id, {
      publicKey: args.publicKey,
      updatedAt: Date.now(),
    });
  },
});

/** Kullanıcının kendi açık anahtarına paketlenmiş bütün anahtarlar. Davetle
 * kayıttan sonra geçici anahtardan kalıcı anahtara taşımak için kullanılır. */
export const myWrappedKeys = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);

    return {
      publicKey: user.publicKey ?? null,
      itemAccesses: (
        await ctx.db
          .query("itemAccess")
          .withIndex("by_user", (q) => q.eq("userId", user._id))
          .collect()
      ).map((row) => ({ id: row._id, access: row.access })),
      departmentKeys: (
        await ctx.db
          .query("departmentKeys")
          .withIndex("by_user", (q) => q.eq("userId", user._id))
          .collect()
      ).map((row) => ({ id: row._id, access: row.access })),
    };
  },
});

/**
 * Kullanıcının bütün anahtar paketlerini yeni açık anahtarına taşır. İstemci
 * eski anahtarı bildiğini, her paketi yeniden paketleyerek gösterir; liste
 * eksiksiz olmalıdır (arada yeni paylaşım olduysa tekrar denenir).
 */
export const rotateKey = mutation({
  args: {
    fromPublicKey: v.string(),
    publicKey: v.string(),
    itemAccesses: v.array(v.object({ id: v.id("itemAccess"), access: wrappedKey })),
    departmentKeys: v.array(v.object({ id: v.id("departmentKeys"), access: wrappedKey })),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);

    assertPublicKey(args.publicKey);

    if (user.publicKey !== args.fromPublicKey) {
      throw new ConvexError("Hesabın açık anahtarı değişmiş.");
    }

    const itemRows = await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", user._id))
      .collect();
    const departmentRows = await ctx.db
      .query("departmentKeys")
      .withIndex("by_user", (q) => q.eq("userId", user._id))
      .collect();

    const requireExact = (rows: { _id: string }[], given: { id: string }[]) => {
      const ids = new Set(given.map((entry) => entry.id));

      if (
        ids.size !== given.length ||
        ids.size !== rows.length ||
        rows.some((row) => !ids.has(row._id))
      ) {
        throw new ConvexError("Anahtarların değişti. Tekrar deneniyor.");
      }
    };

    requireExact(itemRows, args.itemAccesses);
    requireExact(departmentRows, args.departmentKeys);

    for (const entry of args.itemAccesses) {
      assertWrappedKey(entry.access);
      await ctx.db.patch(entry.id as Id<"itemAccess">, { access: entry.access });
    }

    for (const entry of args.departmentKeys) {
      assertWrappedKey(entry.access);
      await ctx.db.patch(entry.id as Id<"departmentKeys">, { access: entry.access });
    }

    await ctx.db.patch(user._id, { publicKey: args.publicKey, updatedAt: Date.now() });
  },
});
