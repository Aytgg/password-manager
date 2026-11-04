import { ConvexError, v } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import { accessibleItemIds, canManageFolder, requireActiveUser } from "./lib";

const MAX_NAME_LENGTH = 100;
const MAX_DEPTH = 20;

function folderName(raw: string) {
  const name = raw.trim();

  if (!name || name.length > MAX_NAME_LENGTH) {
    throw new ConvexError(`Klasör adı 1-${MAX_NAME_LENGTH} karakter olmalı.`);
  }

  return name;
}

async function requireManagedFolder(ctx: QueryCtx, user: Doc<"users">, id: Id<"folders">) {
  const folder = await ctx.db.get(id);

  if (!folder || !canManageFolder(user, folder)) {
    throw new ConvexError("Klasör bulunamadı ya da yönetme yetkin yok.");
  }

  return folder;
}

/** Klasörün kökten kendisine kadar atası olan klasörler (kendisi dahil). */
async function ancestry(ctx: QueryCtx, folder: Doc<"folders">) {
  const chain = [folder];
  let current = folder;

  while (current.parentId && chain.length <= MAX_DEPTH) {
    const parent = await ctx.db.get(current.parentId);
    if (!parent) break;
    chain.push(parent);
    current = parent;
  }

  return chain;
}

async function subtreeHeight(ctx: QueryCtx, folderId: Id<"folders">): Promise<number> {
  let height = 0;

  for (const child of await ctx.db
    .query("folders")
    .withIndex("by_parent", (q) => q.eq("parentId", folderId))
    .collect()) {
    height = Math.max(height, 1 + (await subtreeHeight(ctx, child._id)));
  }

  return height;
}

/** Aynı klasör altında aynı ad (büyük/küçük harf farkı gözetmeden) olamaz. */
async function requireUniqueName(
  ctx: QueryCtx,
  parentId: Id<"folders"> | undefined,
  name: string,
  exceptId?: Id<"folders">,
) {
  const siblings = await ctx.db
    .query("folders")
    .withIndex("by_parent", (q) => q.eq("parentId", parentId))
    .collect();
  const key = name.toLocaleLowerCase("tr");

  if (siblings.some((sibling) => sibling._id !== exceptId && sibling.name.toLocaleLowerCase("tr") === key)) {
    throw new ConvexError("Bu konumda aynı isimde bir klasör zaten var.");
  }
}

/**
 * Kullanıcının görebildiği klasörler: kendi oluşturdukları ve içinde
 * (alt klasörler dahil) açabildiği bir kayıt bulunanlar. Yöneticiler bütün
 * klasörleri görür.
 */
export const list = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);
    const all = await ctx.db.query("folders").collect();
    const byId = new Map(all.map((folder) => [folder._id, folder]));
    const visible = new Set<Id<"folders">>();

    const addWithAncestors = (id: Id<"folders"> | undefined) => {
      let current = id ? byId.get(id) : undefined;

      while (current && !visible.has(current._id)) {
        visible.add(current._id);
        current = current.parentId ? byId.get(current.parentId) : undefined;
      }
    };

    if (user.role === "admin") {
      all.forEach((folder) => visible.add(folder._id));
    } else {
      all
        .filter((folder) => folder.ownerId === user._id)
        .forEach((folder) => addWithAncestors(folder._id));

      for (const itemId of await accessibleItemIds(ctx, user)) {
        addWithAncestors((await ctx.db.get(itemId))?.folderId);
      }
    }

    return [...visible]
      .map((id) => byId.get(id)!)
      .map((folder) => ({
        id: folder._id,
        name: folder.name,
        // Görünmeyen bir üst klasör olamaz; yine de olursa kökte gösterilir.
        parentId: folder.parentId && visible.has(folder.parentId) ? folder.parentId : null,
        isOwner: folder.ownerId === user._id,
        canManage: canManageFolder(user, folder),
      }))
      .sort((a, b) => a.name.localeCompare(b.name, "tr"));
  },
});

export const create = mutation({
  args: { name: v.string(), parentId: v.optional(v.id("folders")) },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const name = folderName(args.name);

    if (args.parentId) {
      const parent = await requireManagedFolder(ctx, user, args.parentId);

      if ((await ancestry(ctx, parent)).length >= MAX_DEPTH) {
        throw new ConvexError(`Klasörler en fazla ${MAX_DEPTH} seviye iç içe olabilir.`);
      }
    }

    await requireUniqueName(ctx, args.parentId, name);

    const now = Date.now();

    return await ctx.db.insert("folders", {
      name,
      parentId: args.parentId,
      ownerId: user._id,
      createdAt: now,
      updatedAt: now,
    });
  },
});

export const rename = mutation({
  args: { id: v.id("folders"), name: v.string() },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const folder = await requireManagedFolder(ctx, user, args.id);
    const name = folderName(args.name);

    await requireUniqueName(ctx, folder.parentId, name, folder._id);
    await ctx.db.patch(folder._id, { name, updatedAt: Date.now() });
  },
});

/** Klasörü başka bir klasörün altına ya da köke (`parentId: null`) taşır. */
export const move = mutation({
  args: { id: v.id("folders"), parentId: v.union(v.id("folders"), v.null()) },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const folder = await requireManagedFolder(ctx, user, args.id);
    const parentId = args.parentId ?? undefined;

    if (parentId) {
      const parent = await requireManagedFolder(ctx, user, parentId);
      const chain = await ancestry(ctx, parent);

      if (chain.some((ancestor) => ancestor._id === folder._id)) {
        throw new ConvexError("Klasör kendi içine ya da alt klasörüne taşınamaz.");
      }

      if (chain.length + 1 + (await subtreeHeight(ctx, folder._id)) > MAX_DEPTH) {
        throw new ConvexError(`Klasörler en fazla ${MAX_DEPTH} seviye iç içe olabilir.`);
      }
    }

    await requireUniqueName(ctx, parentId, folder.name, folder._id);
    await ctx.db.patch(folder._id, { parentId, updatedAt: Date.now() });
  },
});

/**
 * Klasörü siler. İçindeki kayıtlar ve alt klasörler bir üst klasöre (kök
 * klasörse köke) taşınır; hiçbir kayıt silinmez. Taşınan alt klasörün adı
 * üst klasörde çakışırsa sonuna "(2)" gibi bir ek alır.
 */
export const remove = mutation({
  args: { id: v.id("folders") },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const folder = await requireManagedFolder(ctx, user, args.id);
    const now = Date.now();

    for (const item of await ctx.db
      .query("items")
      .withIndex("by_folder", (q) => q.eq("folderId", folder._id))
      .collect()) {
      await ctx.db.patch(item._id, { folderId: folder.parentId });
    }

    const siblings = (
      await ctx.db
        .query("folders")
        .withIndex("by_parent", (q) => q.eq("parentId", folder.parentId))
        .collect()
    ).filter((sibling) => sibling._id !== folder._id);
    const taken = new Set(siblings.map((sibling) => sibling.name.toLocaleLowerCase("tr")));

    for (const child of await ctx.db
      .query("folders")
      .withIndex("by_parent", (q) => q.eq("parentId", folder._id))
      .collect()) {
      let name = child.name;
      for (let n = 2; taken.has(name.toLocaleLowerCase("tr")); n++) {
        name = `${child.name} (${n})`;
      }
      taken.add(name.toLocaleLowerCase("tr"));

      await ctx.db.patch(child._id, { parentId: folder.parentId, name, updatedAt: now });
    }

    await ctx.db.delete(folder._id);
  },
});
