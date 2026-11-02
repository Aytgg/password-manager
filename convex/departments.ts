import { ConvexError, v } from "convex/values";

import type { MutationCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { DEFAULT_DEPARTMENTS, requireActiveUser, requireAdmin } from "./lib";

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

async function insertDepartment(ctx: MutationCtx, rawName: string) {
  const name = rawName.trim();

  if (!name || name.length > 60) {
    throw new ConvexError("Departman adı 1-60 karakter olmalı.");
  }

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
