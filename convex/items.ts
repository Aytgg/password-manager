import { ConvexError, v } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  allowedUsers,
  assertSealedField,
  assertWrappedKey,
  removeDisallowedAccess,
  requireActiveUser,
} from "./lib";
import { sealedField, wrappedKey } from "./schema";

const ITEM_ID = /^item-[0-9a-f]{32}$/;

async function requireOwnedItem(
  ctx: QueryCtx,
  ownerId: string,
  id: Id<"items">,
) {
  const item = await ctx.db.get(id);

  if (!item || item.ownerId !== ownerId) {
    throw new ConvexError("Parola bulunamadı ya da sahibi değilsin.");
  }

  return item;
}

function requireKeyVersion(item: Doc<"items">, expected: number) {
  if (item.keyVersion !== expected) {
    throw new ConvexError(
      "Parola başka bir işlemle güncellendi. Tekrar deneniyor.",
    );
  }
}

async function myAccess(ctx: QueryCtx, itemId: Id<"items">, userId: string) {
  return await ctx.db
    .query("itemAccess")
    .withIndex("by_item_and_user", (q) => q.eq("item", itemId).eq("userId", userId))
    .unique();
}

function serialize(item: Doc<"items">, access: Doc<"itemAccess">, userId: string) {
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
}

/**
 * Kullanıcının anahtarına sahip olduğu kayıtlar ve her biri için kullanıcının
 * kendi paketlenmiş anahtarı.
 */
export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);
    const userId = user.clerkId!;

    const accesses = await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();

    const results = await Promise.all(
      accesses.map(async (access) => {
        const item = await ctx.db.get(access.item);
        return item ? serialize(item, access, userId) : null;
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
    const user = await requireActiveUser(ctx);
    const ownerId = user.clerkId!;

    if (!user.publicKey) {
      throw new ConvexError("Önce kasanın açık anahtarı kaydedilmeli.");
    }

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
      needsRekey: false,
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

/** Sahibin yetkilendirme paneli: departman ve kişi bazında paylaşım durumu. */
export const sharing = query({
  args: { id: v.id("items") },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await requireOwnedItem(ctx, user.clerkId!, args.id);

    const grants = await ctx.db
      .query("itemGrants")
      .withIndex("by_item", (q) => q.eq("item", item._id))
      .collect();

    const grantedDepartments = new Set(
      grants.flatMap((grant) => (grant.departmentId ? [grant.departmentId] : [])),
    );
    const grantedUsers = new Set(
      grants.flatMap((grant) => (grant.userId ? [grant.userId] : [])),
    );

    const accessUserIds = new Set(
      (
        await ctx.db
          .query("itemAccess")
          .withIndex("by_item", (q) => q.eq("item", item._id))
          .collect()
      ).map((access) => access.userId),
    );

    const departments = await ctx.db.query("departments").collect();
    const departmentNames = new Map(departments.map((d) => [d._id, d.name]));

    const users = (await ctx.db.query("users").collect()).filter(
      (candidate) =>
        candidate.status === "active" &&
        candidate.clerkId !== undefined &&
        candidate.clerkId !== user.clerkId,
    );

    return {
      departments: departments
        .map((department) => ({
          id: department._id,
          name: department.name,
          granted: grantedDepartments.has(department._id),
        }))
        .sort((a, b) => a.name.localeCompare(b.name, "tr")),
      users: users
        .map((candidate) => ({
          userId: candidate.clerkId!,
          email: candidate.email,
          displayName: candidate.displayName ?? candidate.email,
          departmentName: candidate.departmentId
            ? (departmentNames.get(candidate.departmentId) ?? null)
            : null,
          direct: grantedUsers.has(candidate.clerkId!),
          viaDepartment:
            candidate.departmentId !== undefined &&
            grantedDepartments.has(candidate.departmentId),
          hasKey: accessUserIds.has(candidate.clerkId!),
          hasPublicKey: candidate.publicKey !== undefined,
        }))
        .sort((a, b) => a.displayName.localeCompare(b.displayName, "tr")),
    };
  },
});

export const setUserGrant = mutation({
  args: { id: v.id("items"), userId: v.string(), granted: v.boolean() },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await requireOwnedItem(ctx, user.clerkId!, args.id);

    if (args.userId === item.ownerId) {
      throw new ConvexError("Parola sahibinin erişimi değiştirilemez.");
    }

    const existing = (
      await ctx.db
        .query("itemGrants")
        .withIndex("by_item", (q) => q.eq("item", item._id))
        .collect()
    ).find((grant) => grant.userId === args.userId);

    if (args.granted) {
      if (existing) {
        return;
      }

      const recipient = await ctx.db
        .query("users")
        .withIndex("by_clerk_id", (q) => q.eq("clerkId", args.userId))
        .unique();

      if (!recipient || recipient.status !== "active") {
        throw new ConvexError("Yetki verilecek kullanıcı bulunamadı.");
      }

      await ctx.db.insert("itemGrants", { item: item._id, userId: args.userId });
      return;
    }

    if (existing) {
      await ctx.db.delete(existing._id);
      await removeDisallowedAccess(ctx, item._id);
    }
  },
});

export const setDepartmentGrant = mutation({
  args: {
    id: v.id("items"),
    departmentId: v.id("departments"),
    granted: v.boolean(),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await requireOwnedItem(ctx, user.clerkId!, args.id);

    if (!(await ctx.db.get(args.departmentId))) {
      throw new ConvexError("Departman bulunamadı.");
    }

    const existing = (
      await ctx.db
        .query("itemGrants")
        .withIndex("by_item", (q) => q.eq("item", item._id))
        .collect()
    ).find((grant) => grant.departmentId === args.departmentId);

    if (args.granted) {
      if (!existing) {
        await ctx.db.insert("itemGrants", {
          item: item._id,
          departmentId: args.departmentId,
        });
      }
      return;
    }

    if (existing) {
      await ctx.db.delete(existing._id);
      await removeDisallowedAccess(ctx, item._id);
    }
  },
});

/**
 * Kurala göre erişimi olması gereken fakat anahtarı eksik kullanıcılar için,
 * kayda erişimi olan bir istemcinin ürettiği anahtar paketlerini ekler.
 * Zaten anahtarı olan kullanıcılar sessizce atlanır.
 */
export const addAccesses = mutation({
  args: {
    id: v.id("items"),
    keyVersion: v.number(),
    accesses: v.array(v.object({ userId: v.string(), access: wrappedKey })),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await ctx.db.get(args.id);

    if (!item || !(await myAccess(ctx, args.id, user.clerkId!))) {
      throw new ConvexError("Bu parolaya erişimin yok.");
    }

    requireKeyVersion(item, args.keyVersion);

    const allowed = await allowedUsers(ctx, item);

    for (const entry of args.accesses) {
      assertWrappedKey(entry.access);

      if (!allowed.has(entry.userId)) {
        throw new ConvexError("Paylaşım kuralı bu kullanıcıya erişim vermiyor.");
      }

      if (await myAccess(ctx, args.id, entry.userId)) {
        continue;
      }

      await ctx.db.insert("itemAccess", {
        item: args.id,
        userId: entry.userId,
        access: entry.access,
      });
    }
  },
});

/**
 * Kaydı yeni bir DEK ile şifrelenmiş haliyle değiştirir ve anahtar
 * paketlerini `accesses` ile değiştirir. Yalnızca sahip yapabilir; listedeki
 * herkesin kurala göre erişimi olmalıdır.
 */
export const rekey = mutation({
  args: {
    id: v.id("items"),
    keyVersion: v.number(),
    metadata: sealedField,
    secret: sealedField,
    accesses: v.array(v.object({ userId: v.string(), access: wrappedKey })),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const ownerId = user.clerkId!;
    const item = await requireOwnedItem(ctx, ownerId, args.id);

    requireKeyVersion(item, args.keyVersion);
    assertSealedField(args.metadata);
    assertSealedField(args.secret);

    const allowed = await allowedUsers(ctx, item);
    const seen = new Set<string>();

    for (const entry of args.accesses) {
      assertWrappedKey(entry.access);

      if (seen.has(entry.userId)) {
        throw new ConvexError("Erişim listesinde tekrar eden kullanıcı var.");
      }

      if (!allowed.has(entry.userId)) {
        throw new ConvexError("Paylaşım kuralı bu kullanıcıya erişim vermiyor.");
      }

      seen.add(entry.userId);
    }

    if (!seen.has(ownerId)) {
      throw new ConvexError("Parola sahibinin erişimi kaldırılamaz.");
    }

    await ctx.db.patch(item._id, {
      metadata: args.metadata,
      secret: args.secret,
      keyVersion: item.keyVersion + 1,
      needsRekey: false,
      updatedAt: Date.now(),
    });

    const currentAccesses = await ctx.db
      .query("itemAccess")
      .withIndex("by_item", (q) => q.eq("item", item._id))
      .collect();

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

/**
 * İstemcinin arka planda yapması gereken şifreleme işleri:
 * - fills: erişimim olan kayıtlarda, kurala göre erişimi olup anahtarı
 *   eksik kullanıcılar (anahtarı ben paketlerim).
 * - rekeys: sahibi olduğum ve erişimi kaldırılmış kayıtlar (yeni DEK).
 */
export const pendingWork = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);
    const userId = user.clerkId!;

    const accesses = await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();

    const fills = [];
    const rekeys = [];

    for (const access of accesses) {
      const item = await ctx.db.get(access.item);

      if (!item) {
        continue;
      }

      const allowed = await allowedUsers(ctx, item);

      const current = new Set(
        (
          await ctx.db
            .query("itemAccess")
            .withIndex("by_item", (q) => q.eq("item", item._id))
            .collect()
        ).map((row) => row.userId),
      );

      if (item.needsRekey) {
        if (item.ownerId === userId) {
          rekeys.push({
            item: serialize(item, access, userId),
            recipients: [...current]
              .filter((id) => id !== userId && allowed.has(id))
              .map((id) => ({ userId: id, publicKey: allowed.get(id)!.publicKey })),
          });
        }

        // Eski DEK artık dağıtılmamalı; eksikler rekey sonrası yeni DEK
        // ile tamamlanır.
        continue;
      }

      const missing = [...allowed.values()].filter(
        (candidate) => !current.has(candidate.clerkId),
      );

      if (missing.length > 0) {
        fills.push({
          item: serialize(item, access, userId),
          recipients: missing.map((candidate) => ({
            userId: candidate.clerkId,
            publicKey: candidate.publicKey,
          })),
        });
      }
    }

    return { fills, rekeys };
  },
});

// Paylaşım kuralı gereği kullanıcının görmesi gereken fakat anahtarı henüz
// paketlenmemiş kayıtların sayısı. Anahtarı yalnızca kayda erişimi olan bir
// istemci paketleyebildiği için bu kayıtlar o kişi çevrimiçi olunca açılır.
export const pendingSharedCount = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);
    const userId = user.clerkId!;

    const grants = [
      ...(await ctx.db
        .query("itemGrants")
        .withIndex("by_user", (q) => q.eq("userId", userId))
        .collect()),
      ...(user.departmentId
        ? await ctx.db
            .query("itemGrants")
            .withIndex("by_department", (q) => q.eq("departmentId", user.departmentId))
            .collect()
        : []),
    ];

    const itemIds = new Set(grants.map((grant) => grant.item));
    let count = 0;

    for (const itemId of itemIds) {
      const item = await ctx.db.get(itemId);

      if (!item || item.ownerId === userId) {
        continue;
      }

      const access = await ctx.db
        .query("itemAccess")
        .withIndex("by_item_and_user", (q) => q.eq("item", itemId).eq("userId", userId))
        .unique();

      if (!access) {
        count += 1;
      }
    }

    return count;
  },
});
