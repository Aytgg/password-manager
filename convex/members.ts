import { ConvexError, v } from "convex/values";
import type { Infer } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  assertAuthSecret,
  assertPublicKey,
  canManageUser,
  normalizeEmail,
  reconcileUserAccess,
  requireActiveUser,
  sha256Hex,
} from "./lib";
import { role } from "./schema";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const inviteArgs = {
  email: v.string(),
  role,
  departmentId: v.optional(v.id("departments")),
};

async function checkInvite(
  ctx: QueryCtx,
  actor: Doc<"users">,
  args: { email: string; role: Infer<typeof role>; departmentId?: Id<"departments"> },
) {
  const email = normalizeEmail(args.email);

  if (!EMAIL.test(email) || email.length > 320) {
    throw new ConvexError("Geçersiz e-posta adresi.");
  }

  if (actor.role === "manager") {
    if (args.role !== "member" || args.departmentId !== actor.departmentId) {
      throw new ConvexError(
        "Departman yöneticisi yalnızca kendi departmanına personel davet edebilir.",
      );
    }
  } else if (actor.role !== "admin") {
    throw new ConvexError("Kullanıcı davet etme yetkin yok.");
  }

  if (args.role !== "admin") {
    if (!args.departmentId || !(await ctx.db.get(args.departmentId))) {
      throw new ConvexError("Bir departman seçilmeli.");
    }
  }

  const existing = await ctx.db
    .query("users")
    .withIndex("by_email", (q) => q.eq("email", email))
    .unique();

  if (existing) {
    throw new ConvexError("Bu e-posta adresiyle kayıtlı bir kullanıcı zaten var.");
  }

  return email;
}

// Davetin geçerlilik süresi (saat); arayüzdeki seçeneklerle aynı.
const INVITE_TTL_HOURS = [24, 72, 168];

/**
 * Davet kodu yöneticinin cihazında üretilir; sunucuya yalnızca koddan
 * türetilen geçici açık anahtar ve doğrulayıcı gelir. Doğrulayıcının özeti
 * saklanır, kodun kendisi hiç görülmez.
 */
const inviteKeyArgs = {
  publicKey: v.string(),
  verifier: v.string(),
  expiresInHours: v.number(),
};

async function inviteFields(args: { publicKey: string; verifier: string; expiresInHours: number }) {
  if (!INVITE_TTL_HOURS.includes(args.expiresInHours)) {
    throw new ConvexError("Geçersiz davet süresi.");
  }

  assertPublicKey(args.publicKey);

  return {
    publicKey: args.publicKey,
    inviteVerifierHash: await sha256Hex(assertAuthSecret(args.verifier)),
    inviteExpiresAt: Date.now() + args.expiresInHours * 60 * 60 * 1000,
  };
}

export const invite = mutation({
  args: { ...inviteArgs, ...inviteKeyArgs },
  returns: v.object({ expiresAt: v.number() }),
  handler: async (ctx, args) => {
    const actor = await requireActiveUser(ctx);
    const email = await checkInvite(ctx, actor, args);
    const fields = await inviteFields(args);
    const now = Date.now();

    await ctx.db.insert("users", {
      email,
      role: args.role,
      departmentId: args.departmentId,
      status: "invited",
      ...fields,
      createdAt: now,
      updatedAt: now,
    });

    return { expiresAt: fields.inviteExpiresAt };
  },
});

/**
 * Henüz kaydolmamış bir kullanıcı için yeni davet kodu kaydeder; eskisi
 * geçersizleşir. Eski geçici anahtara paketlenmiş anahtarlar artık
 * açılamayacağı için silinir: departman anahtarlarını yöneticinin cihazı
 * hemen yeniden paketler, kişiye doğrudan paylaşılanları ise paylaşan kişi
 * çevrimiçi olduğunda.
 */
export const renewInvite = mutation({
  args: { id: v.id("users"), ...inviteKeyArgs },
  returns: v.object({ expiresAt: v.number() }),
  handler: async (ctx, args) => {
    const actor = await requireActiveUser(ctx);
    const target = await ctx.db.get(args.id);

    if (!target || !canManageUser(actor, target)) {
      throw new ConvexError("Bu kullanıcıyı yönetme yetkin yok.");
    }

    if (target.status !== "invited") {
      throw new ConvexError("Bu kullanıcı daveti zaten kullanmış.");
    }

    const fields = await inviteFields(args);

    for (const access of await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", target._id))
      .collect()) {
      await ctx.db.delete(access._id);
    }

    for (const key of await ctx.db
      .query("departmentKeys")
      .withIndex("by_user", (q) => q.eq("userId", target._id))
      .collect()) {
      await ctx.db.delete(key._id);
    }

    await ctx.db.patch(target._id, { ...fields, updatedAt: Date.now() });

    return { expiresAt: fields.inviteExpiresAt };
  },
});

export const list = query({
  args: {},
  handler: async (ctx) => {
    const actor = await requireActiveUser(ctx);

    let users: Doc<"users">[];

    if (actor.role === "admin") {
      users = await ctx.db.query("users").collect();
    } else if (actor.role === "manager" && actor.departmentId) {
      users = await ctx.db
        .query("users")
        .withIndex("by_department", (q) => q.eq("departmentId", actor.departmentId))
        .collect();
    } else {
      throw new ConvexError("Kullanıcı listesini görme yetkin yok.");
    }

    const departments = new Map(
      (await ctx.db.query("departments").collect()).map((d) => [d._id, d.name]),
    );

    const ownedItems = new Map<Id<"users">, number>();
    for (const user of users) {
      ownedItems.set(
        user._id,
        (
          await ctx.db
            .query("items")
            .withIndex("by_owner", (q) => q.eq("ownerId", user._id))
            .collect()
        ).length,
      );
    }

    return users
      .map((user) => ({
        id: user._id,
        email: user.email,
        displayName: user.displayName ?? null,
        role: user.role,
        status: user.status,
        departmentId: user.departmentId ?? null,
        departmentName: user.departmentId
          ? (departments.get(user.departmentId) ?? null)
          : null,
        hasPublicKey: user.publicKey !== undefined,
        inviteExpiresAt: user.status === "invited" ? (user.inviteExpiresAt ?? null) : null,
        isSelf: user._id === actor._id,
        ownedItemCount: ownedItems.get(user._id) ?? 0,
        canManage: canManageUser(actor, user),
      }))
      .sort((a, b) => a.email.localeCompare(b.email, "tr"));
  },
});

export const update = mutation({
  args: {
    id: v.id("users"),
    role: v.optional(role),
    departmentId: v.optional(v.id("departments")),
    enabled: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const actor = await requireActiveUser(ctx);
    const target = await ctx.db.get(args.id);

    if (!target) {
      throw new ConvexError("Kullanıcı bulunamadı.");
    }

    if (!canManageUser(actor, target)) {
      throw new ConvexError("Bu kullanıcıyı yönetme yetkin yok.");
    }

    const changesRoleOrDepartment =
      (args.role !== undefined && args.role !== target.role) ||
      (args.departmentId !== undefined && args.departmentId !== target.departmentId);

    if (changesRoleOrDepartment && actor.role !== "admin") {
      throw new ConvexError("Rol ve departmanı yalnızca yönetici değiştirebilir.");
    }

    const nextRole = args.role ?? target.role;
    const nextDepartmentId = args.departmentId ?? target.departmentId;

    if (nextRole !== "admin") {
      if (!nextDepartmentId || !(await ctx.db.get(nextDepartmentId))) {
        throw new ConvexError("Bir departman seçilmeli.");
      }
    }

    let nextStatus = target.status;

    if (args.enabled === false) {
      nextStatus = "disabled";
    } else if (args.enabled === true && target.status === "disabled") {
      nextStatus = target.inviteVerifierHash === undefined ? "active" : "invited";
    }

    await ctx.db.patch(target._id, {
      role: nextRole,
      departmentId: nextDepartmentId,
      status: nextStatus,
      updatedAt: Date.now(),
    });

    await reconcileUserAccess(ctx, target._id);
  },
});
