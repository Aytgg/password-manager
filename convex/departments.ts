import { ConvexError, v } from "convex/values";

import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  DEFAULT_DEPARTMENTS,
  deleteUser,
  reconcileUserAccess,
  removeDisallowedAccess,
  requireActiveUser,
  requireAdmin,
} from "./lib";

export const list = query({
  args: {},
  handler: async (ctx) => {
    await requireActiveUser(ctx);

    const departments = await ctx.db.query("departments").collect();

    return departments
      .map((department) => ({ id: department._id, name: department.name }))
      .sort((a, b) => a.name.localeCompare(b.name, "tr"));
  },
});

function departmentName(rawName: string) {
  const name = rawName.trim();

  if (!name || name.length > 60) {
    throw new ConvexError("Departman adı 1-60 karakter olmalı.");
  }

  return name;
}

async function insertDepartment(ctx: MutationCtx, rawName: string) {
  const name = departmentName(rawName);

  const existing = await ctx.db
    .query("departments")
    .withIndex("by_name", (q) => q.eq("name", name))
    .unique();

  if (existing) {
    return existing._id;
  }

  // Anahtar, bir yöneticinin cihazında arka planda üretilir (keys.pendingWork).
  return await ctx.db.insert("departments", {
    name,
    keyVersion: 0,
    needsRotation: false,
    createdAt: Date.now(),
  });
}

export const create = mutation({
  args: { name: v.string() },
  handler: async (ctx, args) => {
    await requireAdmin(ctx);
    return await insertDepartment(ctx, args.name);
  },
});

export const createDefaults = mutation({
  args: {},
  handler: async (ctx) => {
    await requireAdmin(ctx);

    for (const name of DEFAULT_DEPARTMENTS) {
      await insertDepartment(ctx, name);
    }
  },
});

export const rename = mutation({
  args: { id: v.id("departments"), name: v.string() },
  handler: async (ctx, args) => {
    await requireAdmin(ctx);

    const department = await ctx.db.get(args.id);

    if (!department) {
      throw new ConvexError("Departman bulunamadı.");
    }

    const name = departmentName(args.name);
    const existing = await ctx.db
      .query("departments")
      .withIndex("by_name", (q) => q.eq("name", name))
      .unique();

    if (existing && existing._id !== department._id) {
      throw new ConvexError("Bu isimde bir departman zaten var.");
    }

    await ctx.db.patch(department._id, { name });
  },
});

/**
 * Departmanı siler. Departmandaki her kullanıcı için ne yapılacağı
 * belirtilmelidir: başka bir departmana taşıma ya da kullanıcıyı silme.
 * Departmanla yapılan paylaşımlar kalkar; o kayıtlar yeniden şifrelenir.
 */
export const remove = mutation({
  args: {
    id: v.id("departments"),
    assignments: v.array(
      v.union(
        v.object({
          userId: v.id("users"),
          action: v.literal("move"),
          departmentId: v.id("departments"),
        }),
        v.object({ userId: v.id("users"), action: v.literal("delete") }),
      ),
    ),
  },
  handler: async (ctx, args) => {
    const actor = await requireAdmin(ctx);
    const department = await ctx.db.get(args.id);

    if (!department) {
      throw new ConvexError("Departman bulunamadı.");
    }

    const members = await ctx.db
      .query("users")
      .withIndex("by_department", (q) => q.eq("departmentId", department._id))
      .collect();
    const memberIds = new Set(members.map((member) => member._id));
    const given = new Set(args.assignments.map((assignment) => assignment.userId));

    if (
      given.size !== args.assignments.length ||
      given.size !== memberIds.size ||
      [...given].some((userId) => !memberIds.has(userId))
    ) {
      throw new ConvexError("Departmandaki kullanıcılar değişti. Listeyi kontrol edip tekrar dene.");
    }

    for (const assignment of args.assignments) {
      if (assignment.action === "delete") {
        if (assignment.userId === actor._id) {
          throw new ConvexError("Kendi hesabını silemezsin; kendini başka bir departmana taşı.");
        }
        continue;
      }

      if (assignment.departmentId === department._id || !(await ctx.db.get(assignment.departmentId))) {
        throw new ConvexError("Taşınacak departman geçersiz.");
      }
    }

    for (const assignment of args.assignments) {
      if (assignment.action === "delete") {
        await deleteUser(ctx, assignment.userId);
      } else {
        await ctx.db.patch(assignment.userId, {
          departmentId: assignment.departmentId,
          updatedAt: Date.now(),
        });
        await reconcileUserAccess(ctx, assignment.userId);
      }
    }

    // Departmanla yapılan paylaşımlar kalkar; departman üyeleri DEK'leri
    // görmüş olduğu için kayıtlar yeniden şifrelenir.
    for (const grant of await ctx.db
      .query("itemGrants")
      .withIndex("by_department", (q) => q.eq("departmentId", department._id))
      .collect()) {
      await ctx.db.delete(grant._id);
      await removeDisallowedAccess(ctx, grant.item);

      const item = await ctx.db.get(grant.item);
      if (item && !item.needsRekey) {
        await ctx.db.patch(item._id, { needsRekey: true });
      }
    }

    for (const row of await ctx.db
      .query("itemDepartmentAccess")
      .withIndex("by_department", (q) => q.eq("department", department._id))
      .collect()) {
      await ctx.db.delete(row._id);
    }

    for (const row of await ctx.db
      .query("departmentKeys")
      .withIndex("by_department_and_user", (q) => q.eq("department", department._id))
      .collect()) {
      await ctx.db.delete(row._id);
    }

    await ctx.db.delete(department._id);
  },
});
