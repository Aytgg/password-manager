import { ConvexError, v } from "convex/values";

import type { Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  assertSealedField,
  assertWrappedKey,
  requireUserId,
} from "./lib";
import { sealedField, wrappedKey } from "./schema";

const ITEM_ID = /^item-[0-9a-f]{32}$/;

async function requireOwnedItem(
  ctx: MutationCtx,
  ownerId: string,
  id: Id<"items">,
  expectedKeyVersion: number,
) {
  const item = await ctx.db.get(id);

  if (!item) {
    throw new ConvexError("Parola bulunamadı.");
  }

  if (item.ownerId !== ownerId) {
    throw new ConvexError(
      "Yalnızca kendi parolalarının yetkilerini yönetebilirsin.",
    );
  }

  if (item.keyVersion !== expectedKeyVersion) {
    throw new ConvexError(
      "Parola başka bir işlemle güncellendi. Listeyi yenileyip tekrar dene.",
    );
  }

  return item;
}

/**
 * Kullanıcının erişebildiği kayıtlar ve her biri için kullanıcının kendi
 * paketlenmiş anahtarı.
 */
export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const userId = await requireUserId(ctx);

    const accesses = await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();

    const results = await Promise.all(
      accesses.map(async (access) => {
        const item = await ctx.db.get(access.item);

        if (!item) {
          return null;
        }

        return {
          id: item._id,
          itemId: item.itemId,
          ownerId: item.ownerId,
          isOwner: item.ownerId === userId,
          metadata: item.metadata,
          secret: item.secret,
          keyVersion: item.keyVersion,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt,
          access: access.access,
        };
      }),
    );

    return results.filter((item) => item !== null);
  },
});

export const create = mutation({
  args: {
    itemId: v.string(),
    metadata: sealedField,
    secret: sealedField,
    ownerAccess: wrappedKey,
  },
  handler: async (ctx, args) => {
    const ownerId = await requireUserId(ctx);

    if (!ITEM_ID.test(args.itemId)) {
      throw new ConvexError("Geçersiz kayıt kimliği.");
    }

    assertSealedField(args.metadata);
    assertSealedField(args.secret);
    assertWrappedKey(args.ownerAccess);

    const duplicate = await ctx.db
      .query("items")
      .withIndex("by_item_id", (q) => q.eq("itemId", args.itemId))
      .unique();

    if (duplicate) {
      throw new ConvexError("Bu kayıt kimliği zaten kullanılıyor.");
    }

    const now = Date.now();

    const id = await ctx.db.insert("items", {
      itemId: args.itemId,
      ownerId,
      metadata: args.metadata,
      secret: args.secret,
      keyVersion: 1,
      createdAt: now,
      updatedAt: now,
    });

    await ctx.db.insert("itemAccess", {
      item: id,
      userId: ownerId,
      access: args.ownerAccess,
    });

    return id;
  },
});

/** Sahibin görebileceği erişim listesi (kullanıcı kimlikleri). */
export const accessList = query({
  args: { id: v.id("items") },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const item = await ctx.db.get(args.id);

    if (!item || item.ownerId !== userId) {
      throw new ConvexError("Parola bulunamadı.");
    }

    const accesses = await ctx.db
      .query("itemAccess")
      .withIndex("by_item", (q) => q.eq("item", args.id))
      .collect();

    return accesses
      .map((access) => access.userId)
      .filter((accessUserId) => accessUserId !== userId);
  },
});

export const grant = mutation({
  args: {
    id: v.id("items"),
    keyVersion: v.number(),
    recipientId: v.string(),
    access: wrappedKey,
  },
  handler: async (ctx, args) => {
    const ownerId = await requireUserId(ctx);

    await requireOwnedItem(ctx, ownerId, args.id, args.keyVersion);
    assertWrappedKey(args.access);

    if (args.recipientId === ownerId) {
      throw new ConvexError("Kendine yeniden yetki veremezsin.");
    }

    const recipient = await ctx.db
      .query("users")
      .withIndex("by_clerk_id", (q) => q.eq("clerkId", args.recipientId))
      .unique();

    if (!recipient) {
      throw new ConvexError("Yetki verilecek kullanıcı bulunamadı.");
    }

    const existing = await ctx.db
      .query("itemAccess")
      .withIndex("by_item_and_user", (q) =>
        q.eq("item", args.id).eq("userId", args.recipientId),
      )
      .unique();

    if (existing) {
      throw new ConvexError("Bu kullanıcıya zaten erişim verilmiş.");
    }

    await ctx.db.insert("itemAccess", {
      item: args.id,
      userId: args.recipientId,
      access: args.access,
    });
  },
});

/**
 * Kaydı yeni bir DEK ile şifrelenmiş haliyle değiştirir ve erişim listesini
 * `accesses` ile değiştirir. Yalnızca erişim kaldırmak için kullanılır:
 * listede mevcut erişimi olmayan bir kullanıcı bulunamaz.
 */
export const rekey = mutation({
  args: {
    id: v.id("items"),
    keyVersion: v.number(),
    metadata: sealedField,
    secret: sealedField,
    accesses: v.array(
      v.object({
        userId: v.string(),
        access: wrappedKey,
      }),
    ),
  },
  handler: async (ctx, args) => {
    const ownerId = await requireUserId(ctx);

    const item = await requireOwnedItem(ctx, ownerId, args.id, args.keyVersion);

    assertSealedField(args.metadata);
    assertSealedField(args.secret);

    const currentAccesses = await ctx.db
      .query("itemAccess")
      .withIndex("by_item", (q) => q.eq("item", args.id))
      .collect();

    const currentUserIds = new Set(currentAccesses.map((a) => a.userId));
    const nextUserIds = new Set<string>();

    for (const entry of args.accesses) {
      assertWrappedKey(entry.access);

      if (nextUserIds.has(entry.userId)) {
        throw new ConvexError("Erişim listesinde tekrar eden kullanıcı var.");
      }

      if (!currentUserIds.has(entry.userId)) {
        throw new ConvexError(
          "Yeniden anahtarlama yalnızca mevcut erişimleri koruyabilir.",
        );
      }

      nextUserIds.add(entry.userId);
    }

    if (!nextUserIds.has(ownerId)) {
      throw new ConvexError("Parola sahibinin erişimi kaldırılamaz.");
    }

    if (nextUserIds.size === currentUserIds.size) {
      throw new ConvexError("Kaldırılacak bir erişim seçilmedi.");
    }

    await ctx.db.patch(item._id, {
      metadata: args.metadata,
      secret: args.secret,
      keyVersion: item.keyVersion + 1,
      updatedAt: Date.now(),
    });

    for (const access of currentAccesses) {
      await ctx.db.delete(access._id);
    }

    for (const entry of args.accesses) {
      await ctx.db.insert("itemAccess", {
        item: item._id,
        userId: entry.userId,
        access: entry.access,
      });
    }
  },
});
