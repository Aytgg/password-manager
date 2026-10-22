import { ConvexError } from "convex/values";
import type { Infer } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import type { sealedField, wrappedKey } from "./schema";

export const DEFAULT_DEPARTMENTS = ["Yazılım", "Satış", "Destek", "Diğer"];

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function requireIdentity(ctx: QueryCtx) {
  const identity = await ctx.auth.getUserIdentity();

  if (!identity) {
    throw new ConvexError("Oturum doğrulanamadı.");
  }

  return identity;
}

export async function findUserByClerkId(ctx: QueryCtx, clerkId: string) {
  return await ctx.db
    .query("users")
    .withIndex("by_clerk_id", (q) => q.eq("clerkId", clerkId))
    .unique();
}

export async function requireActiveUser(ctx: QueryCtx): Promise<Doc<"users">> {
  const identity = await requireIdentity(ctx);
  const user = await findUserByClerkId(ctx, identity.subject);

  if (!user || user.status !== "active") {
    throw new ConvexError("Bu hesabın sisteme erişim yetkisi yok.");
  }

  return user;
}

export async function requireAdmin(ctx: QueryCtx): Promise<Doc<"users">> {
  const user = await requireActiveUser(ctx);

  if (user.role !== "admin") {
    throw new ConvexError("Bu işlem yalnızca yönetici tarafından yapılabilir.");
  }

  return user;
}

export function canManageUser(actor: Doc<"users">, target: Doc<"users">): boolean {
  if (actor._id === target._id) {
    return false;
  }

  if (actor.role === "admin") {
    return true;
  }

  return (
    actor.role === "manager" &&
    actor.departmentId !== undefined &&
    target.departmentId === actor.departmentId &&
    target.role === "member"
  );
}

export function isReachable(
  user: Doc<"users">,
): user is Doc<"users"> & { clerkId: string; publicKey: string } {
  return (
    user.status === "active" &&
    user.clerkId !== undefined &&
    user.publicKey !== undefined
  );
}

export async function allowedUsers(
  ctx: QueryCtx,
  item: Doc<"items">,
): Promise<Map<string, Doc<"users"> & { clerkId: string; publicKey: string }>> {
  const allowed = new Map<
    string,
    Doc<"users"> & { clerkId: string; publicKey: string }
  >();

  const add = (user: Doc<"users"> | null) => {
    if (user && isReachable(user)) {
      allowed.set(user.clerkId, user);
    }
  };

  add(await findUserByClerkId(ctx, item.ownerId));

  const grants = await ctx.db
    .query("itemGrants")
    .withIndex("by_item", (q) => q.eq("item", item._id))
    .collect();

  for (const grant of grants) {
    if (grant.userId !== undefined) {
      add(await findUserByClerkId(ctx, grant.userId));
    }

    if (grant.departmentId !== undefined) {
      const members = await ctx.db
        .query("users")
        .withIndex("by_department", (q) =>
          q.eq("departmentId", grant.departmentId),
        )
        .collect();

      members.forEach(add);
    }
  }

  return allowed;
}

export async function removeDisallowedAccess(ctx: MutationCtx, itemId: Id<"items">) {
  const item = await ctx.db.get(itemId);

  if (!item) {
    return;
  }

  const allowed = await allowedUsers(ctx, item);

  const accesses = await ctx.db
    .query("itemAccess")
    .withIndex("by_item", (q) => q.eq("item", itemId))
    .collect();

  let removed = false;

  for (const access of accesses) {
    if (!allowed.has(access.userId) && access.userId !== item.ownerId) {
      await ctx.db.delete(access._id);
      removed = true;
    }
  }

  if (removed && !item.needsRekey) {
    await ctx.db.patch(itemId, { needsRekey: true });
  }
}

export async function reconcileUserAccess(ctx: MutationCtx, clerkId: string) {
  const accesses = await ctx.db
    .query("itemAccess")
    .withIndex("by_user", (q) => q.eq("userId", clerkId))
    .collect();

  for (const access of accesses) {
    await removeDisallowedAccess(ctx, access.item);
  }
}

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

const PUBLIC_KEY_LENGTH = 44;
const NONCE_LENGTH = 16;
const MAX_CIPHERTEXT_LENGTH = 16 * 1024;

function assertBase64(value: string, field: string, length?: number) {
  if (!BASE64.test(value) || value.length % 4 !== 0) {
    throw new ConvexError(`${field} geçerli base64 değil.`);
  }

  if (length !== undefined && value.length !== length) {
    throw new ConvexError(`${field} uzunluğu geçersiz.`);
  }

  if (value.length > MAX_CIPHERTEXT_LENGTH) {
    throw new ConvexError(`${field} çok büyük.`);
  }
}

export function assertPublicKey(value: string) {
  assertBase64(value, "Açık anahtar", PUBLIC_KEY_LENGTH);
}

export function assertSealedField(value: Infer<typeof sealedField>) {
  assertBase64(value.nonce, "Nonce", NONCE_LENGTH);
  assertBase64(value.ciphertext, "Şifreli veri");
}

export function assertWrappedKey(value: Infer<typeof wrappedKey>) {
  assertBase64(value.ephemeralPublicKey, "Geçici açık anahtar", PUBLIC_KEY_LENGTH);
  assertBase64(value.nonce, "Anahtar nonce", NONCE_LENGTH);
  assertBase64(value.ciphertext, "Paketlenmiş anahtar");
}
