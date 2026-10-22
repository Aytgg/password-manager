import { ConvexError, v } from "convex/values";
import type { Infer } from "convex/values";

import { internal } from "./_generated/api";
import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import {
  action,
  internalMutation,
  internalQuery,
  mutation,
  query,
} from "./_generated/server";
import {
  canManageUser,
  normalizeEmail,
  reconcileUserAccess,
  requireActiveUser,
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

export const prepareInvite = internalQuery({
  args: inviteArgs,
  handler: async (ctx, args) => {
    const actor = await requireActiveUser(ctx);
    return await checkInvite(ctx, actor, args);
  },
});

export const createInvited = internalMutation({
  args: inviteArgs,
  handler: async (ctx, args) => {
    const actor = await requireActiveUser(ctx);
    const email = await checkInvite(ctx, actor, args);
    const now = Date.now();

    await ctx.db.insert("users", {
      email,
      role: args.role,
      departmentId: args.role === "admin" ? args.departmentId : args.departmentId!,
      status: "invited",
      createdAt: now,
      updatedAt: now,
    });
  },
});

export const invite = action({
  args: inviteArgs,
  handler: async (ctx, args) => {
    const email = await ctx.runQuery(internal.members.prepareInvite, args);

    const secretKey = process.env.CLERK_SECRET_KEY;

    if (!secretKey) {
      throw new ConvexError("Sunucuda CLERK_SECRET_KEY tanımlı değil.");
    }

    const response = await fetch("https://api.clerk.com/v1/invitations", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${secretKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email_address: email,
        notify: true,
        ignore_existing: true,
      }),
    });

    if (!response.ok) {
      console.error("Clerk invitation failed", response.status, await response.text());
      throw new ConvexError(`Clerk daveti gönderilemedi (HTTP ${response.status}).`);
    }

    await ctx.runMutation(internal.members.createInvited, args);
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
        isSelf: user._id === actor._id,
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
      nextStatus = target.clerkId ? "active" : "invited";
    }

    await ctx.db.patch(target._id, {
      role: nextRole,
      departmentId: nextDepartmentId,
      status: nextStatus,
      updatedAt: Date.now(),
    });

    if (target.clerkId) {
      await reconcileUserAccess(ctx, target.clerkId);
    }
  },
});
