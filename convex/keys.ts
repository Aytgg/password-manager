import { ConvexError, v } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  assertPublicKey,
  assertWrappedKey,
  currentDepartmentKey,
  departmentKeyHolders,
  requireActiveUser,
} from "./lib";
import { wrappedKey } from "./schema";

const holderAccess = v.object({ userId: v.id("users"), access: wrappedKey });

function holderList(holders: Awaited<ReturnType<typeof departmentKeyHolders>>) {
  return [...holders.values()].map((holder) => ({
    userId: holder._id,
    publicKey: holder.publicKey,
  }));
}

/** Gönderilen paketlerin, kurala göre anahtarı tutması gerekenlerin tamamı
 * olduğunu doğrular. */
function requireExactHolders(
  holders: Map<Id<"users">, unknown>,
  accesses: { userId: Id<"users"> }[],
) {
  const given = new Set(accesses.map((entry) => entry.userId));

  if (
    given.size !== accesses.length ||
    given.size !== holders.size ||
    [...given].some((userId) => !holders.has(userId))
  ) {
    throw new ConvexError("Departman anahtarı sahipleri değişti. Tekrar deneniyor.");
  }
}

async function requireDepartmentKey(
  ctx: QueryCtx,
  user: Doc<"users">,
  departmentId: Id<"departments">,
  keyVersion: number,
) {
  const department = await ctx.db.get(departmentId);

  if (!department) {
    throw new ConvexError("Departman bulunamadı.");
  }

  if (department.keyVersion !== keyVersion) {
    throw new ConvexError("Departman anahtarı değişti. Tekrar deneniyor.");
  }

  if (!(await currentDepartmentKey(ctx, department, user._id))) {
    throw new ConvexError("Bu departmanın anahtarına sahip değilsin.");
  }

  return department;
}

/**
 * Departman anahtarlarıyla ilgili, istemcinin arka planda yapması gereken
 * işler. Yöneticiler her departmanın anahtarını tuttuğu için bu işler
 * genellikle değişikliği yapan yöneticinin cihazında hemen tamamlanır.
 * - inits: anahtarı henüz üretilmemiş departmanlar (yalnızca yöneticiler).
 * - fills: anahtarı tutması gereken fakat paketi olmayan kişiler.
 * - rotations: bir anahtar sahibi çıkarıldığı için yenilenmesi gerekenler.
 */
export const pendingWork = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);

    const inits = [];
    const fills = [];
    const rotations = [];

    for (const department of await ctx.db.query("departments").collect()) {
      const holders = await departmentKeyHolders(ctx, department._id);

      if (department.keyVersion === 0) {
        if (user.role === "admin" && holders.has(user._id)) {
          inits.push({ departmentId: department._id, holders: holderList(holders) });
        }
        continue;
      }

      const myKey = await currentDepartmentKey(ctx, department, user._id);

      if (!myKey || !department.publicKey) {
        continue;
      }

      const key = { publicKey: department.publicKey, access: myKey.access };

      if (department.needsRotation) {
        const itemKeys = (
          await ctx.db
            .query("itemDepartmentAccess")
            .withIndex("by_department", (q) => q.eq("department", department._id))
            .collect()
        )
          .filter((row) => row.keyVersion === department.keyVersion)
          .map((row) => ({ item: row.item, access: row.access }));

        rotations.push({
          departmentId: department._id,
          keyVersion: department.keyVersion,
          key,
          holders: holderList(holders),
          itemKeys,
        });
        continue;
      }

      const missing = [];
      for (const holder of holders.values()) {
        if (!(await currentDepartmentKey(ctx, department, holder._id))) {
          missing.push({ userId: holder._id, publicKey: holder.publicKey });
        }
      }

      if (missing.length > 0) {
        fills.push({
          departmentId: department._id,
          keyVersion: department.keyVersion,
          key,
          recipients: missing,
        });
      }
    }

    return { inits, fills, rotations };
  },
});

/** Departmanın ilk anahtarını kaydeder; paketler bütün anahtar sahiplerini
 * kapsamalıdır. */
export const initDepartmentKey = mutation({
  args: {
    departmentId: v.id("departments"),
    publicKey: v.string(),
    accesses: v.array(holderAccess),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);

    if (user.role !== "admin") {
      throw new ConvexError("Departman anahtarını yalnızca yönetici oluşturabilir.");
    }

    const department = await ctx.db.get(args.departmentId);

    if (!department) {
      throw new ConvexError("Departman bulunamadı.");
    }

    if (department.keyVersion !== 0) {
      throw new ConvexError("Departman anahtarı zaten oluşturulmuş.");
    }

    assertPublicKey(args.publicKey);
    args.accesses.forEach((entry) => assertWrappedKey(entry.access));
    requireExactHolders(await departmentKeyHolders(ctx, department._id), args.accesses);

    await ctx.db.patch(department._id, {
      publicKey: args.publicKey,
      keyVersion: 1,
      needsRotation: false,
    });

    for (const entry of args.accesses) {
      await ctx.db.insert("departmentKeys", {
        department: department._id,
        keyVersion: 1,
        userId: entry.userId,
        access: entry.access,
      });
    }
  },
});

/** Departman anahtarını, tutması gereken fakat paketi olmayan kişilere
 * dağıtır. Gönderen kişi anahtarın güncel sürümüne sahip olmalıdır. */
export const addDepartmentKeys = mutation({
  args: {
    departmentId: v.id("departments"),
    keyVersion: v.number(),
    accesses: v.array(holderAccess),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const department = await requireDepartmentKey(ctx, user, args.departmentId, args.keyVersion);

    if (department.needsRotation) {
      throw new ConvexError("Departman anahtarı yenilenmeden dağıtılamaz.");
    }

    const holders = await departmentKeyHolders(ctx, department._id);

    for (const entry of args.accesses) {
      assertWrappedKey(entry.access);

      if (!holders.has(entry.userId)) {
        throw new ConvexError("Bu kişi departman anahtarını tutamaz.");
      }

      const existing = await ctx.db
        .query("departmentKeys")
        .withIndex("by_department_and_user", (q) =>
          q.eq("department", department._id).eq("userId", entry.userId),
        )
        .unique();

      if (existing?.keyVersion === department.keyVersion) {
        continue;
      }

      if (existing) {
        await ctx.db.patch(existing._id, { keyVersion: department.keyVersion, access: entry.access });
      } else {
        await ctx.db.insert("departmentKeys", {
          department: department._id,
          keyVersion: department.keyVersion,
          userId: entry.userId,
          access: entry.access,
        });
      }
    }
  },
});

/**
 * Departman anahtarını yeniler: yeni anahtar kalan sahiplere dağıtılır ve
 * departmana paketlenmiş bütün kayıt anahtarları yeni anahtara taşınır.
 */
export const rotateDepartmentKey = mutation({
  args: {
    departmentId: v.id("departments"),
    keyVersion: v.number(),
    publicKey: v.string(),
    accesses: v.array(holderAccess),
    itemKeys: v.array(v.object({ item: v.id("items"), access: wrappedKey })),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const department = await requireDepartmentKey(ctx, user, args.departmentId, args.keyVersion);

    assertPublicKey(args.publicKey);
    args.accesses.forEach((entry) => assertWrappedKey(entry.access));
    args.itemKeys.forEach((entry) => assertWrappedKey(entry.access));
    requireExactHolders(await departmentKeyHolders(ctx, department._id), args.accesses);

    const itemRows = (
      await ctx.db
        .query("itemDepartmentAccess")
        .withIndex("by_department", (q) => q.eq("department", department._id))
        .collect()
    ).filter((row) => row.keyVersion === department.keyVersion);

    const givenItems = new Map(args.itemKeys.map((entry) => [entry.item, entry.access]));

    if (
      givenItems.size !== args.itemKeys.length ||
      givenItems.size !== itemRows.length ||
      itemRows.some((row) => !givenItems.has(row.item))
    ) {
      throw new ConvexError("Departmanın kayıtları değişti. Tekrar deneniyor.");
    }

    const nextVersion = department.keyVersion + 1;

    await ctx.db.patch(department._id, {
      publicKey: args.publicKey,
      keyVersion: nextVersion,
      needsRotation: false,
    });

    for (const row of itemRows) {
      await ctx.db.patch(row._id, { keyVersion: nextVersion, access: givenItems.get(row.item)! });
    }

    // Eski sürüme ait paketler (çıkarılanlarınki dahil) silinir.
    for (const row of await ctx.db
      .query("departmentKeys")
      .withIndex("by_department_and_user", (q) => q.eq("department", department._id))
      .collect()) {
      await ctx.db.delete(row._id);
    }

    for (const entry of args.accesses) {
      await ctx.db.insert("departmentKeys", {
        department: department._id,
        keyVersion: nextVersion,
        userId: entry.userId,
        access: entry.access,
      });
    }
  },
});
