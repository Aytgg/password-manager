import { getAuthUserId } from "@convex-dev/auth/server";
import { ConvexError } from "convex/values";
import type { Infer } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import type { sealedField, wrappedKey } from "./schema";

export const DEFAULT_DEPARTMENTS = ["Yazılım", "Satış", "Destek", "Diğer"];

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function requireActiveUser(ctx: QueryCtx): Promise<Doc<"users">> {
  const userId = await getAuthUserId(ctx);

  if (!userId) {
    throw new ConvexError("Oturum doğrulanamadı.");
  }

  const user = await ctx.db.get(userId);

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

export type ReachableUser = Doc<"users"> & { publicKey: string };

/**
 * Anahtar alabilecek kullanıcı. Davet edilmiş kullanıcının da (davet
 * kodundan türetilen) açık anahtarı vardır; böylece kaydolmadan önce de
 * ona şifre paylaşılabilir.
 */
export function isReachable(user: Doc<"users">): user is ReachableUser {
  return user.status !== "disabled" && user.publicKey !== undefined;
}

/**
 * Departman anahtarını tutması gerekenler: departman üyeleri ve tüm
 * yöneticiler. Yöneticiler, kimse çevrimiçi değilken de yeni üyelere anahtar
 * verebilmek için her departmanın anahtarını tutar.
 */
export function isDepartmentKeyHolder(
  user: Doc<"users">,
  departmentId: Id<"departments">,
): user is ReachableUser {
  return isReachable(user) && (user.role === "admin" || user.departmentId === departmentId);
}

export async function departmentKeyHolders(
  ctx: QueryCtx,
  departmentId: Id<"departments">,
): Promise<Map<Id<"users">, ReachableUser>> {
  const holders = new Map<Id<"users">, ReachableUser>();

  const candidates = [
    ...(await ctx.db
      .query("users")
      .withIndex("by_role", (q) => q.eq("role", "admin"))
      .collect()),
    ...(await ctx.db
      .query("users")
      .withIndex("by_department", (q) => q.eq("departmentId", departmentId))
      .collect()),
  ];

  for (const user of candidates) {
    if (isDepartmentKeyHolder(user, departmentId)) {
      holders.set(user._id, user);
    }
  }

  return holders;
}

/** Çağıranın departmanın güncel anahtarına ait paketi. */
export async function currentDepartmentKey(
  ctx: QueryCtx,
  department: Doc<"departments">,
  userId: Id<"users">,
) {
  if (department.keyVersion === 0) {
    return null;
  }

  const row = await ctx.db
    .query("departmentKeys")
    .withIndex("by_department_and_user", (q) =>
      q.eq("department", department._id).eq("userId", userId),
    )
    .unique();

  return row && row.keyVersion === department.keyVersion ? row : null;
}

export async function itemGrants(ctx: QueryCtx, itemId: Id<"items">) {
  const grants = await ctx.db
    .query("itemGrants")
    .withIndex("by_item", (q) => q.eq("item", itemId))
    .collect();

  return {
    userIds: new Set(grants.flatMap((grant) => (grant.userId ? [grant.userId] : []))),
    departmentIds: new Set(
      grants.flatMap((grant) => (grant.departmentId ? [grant.departmentId] : [])),
    ),
  };
}

/** Bir kayıt üzerindeki yetkiler. Görüntüleme diğerlerinin önkoşuludur. */
export type Permissions = { view: boolean; edit: boolean; delete: boolean; share: boolean };

/** Görüntülemenin yanında verilebilen ek yetkiler. */
export type ExtraPermissions = { edit: boolean; delete: boolean; share: boolean };

export const NO_PERMISSIONS: Permissions = { view: false, edit: false, delete: false, share: false };
export const ALL_PERMISSIONS: Permissions = { view: true, edit: true, delete: true, share: true };

export function grantPermissions(grant: Doc<"itemGrants">): ExtraPermissions {
  return { edit: grant.canEdit === true, delete: grant.canDelete === true, share: grant.canShare === true };
}

/**
 * Kullanıcının kayıt üzerindeki yetkileri: sahip ve yöneticiler her şeyi
 * yapar; diğerlerinde kişiye ve departmanına verilen kuralların birleşimi.
 */
export async function itemPermissions(
  ctx: QueryCtx,
  user: Doc<"users">,
  item: Doc<"items">,
): Promise<Permissions> {
  if (item.ownerId === user._id || user.role === "admin") {
    return ALL_PERMISSIONS;
  }

  const result = { ...NO_PERMISSIONS };

  for (const grant of await ctx.db
    .query("itemGrants")
    .withIndex("by_item", (q) => q.eq("item", item._id))
    .collect()) {
    if (
      grant.userId === user._id ||
      (grant.departmentId !== undefined && grant.departmentId === user.departmentId)
    ) {
      const extra = grantPermissions(grant);
      result.view = true;
      result.edit ||= extra.edit;
      result.delete ||= extra.delete;
      result.share ||= extra.share;
    }
  }

  return result;
}

/** DEK'i doğrudan kendi açık anahtarına paketlenmesi gerekenler: sahip,
 * kişiye doğrudan yetki verilenler ve bütün yöneticiler (yöneticiler her
 * parolayı görür). Departman üyeleri departman anahtarı üzerinden erişir. */
export async function directRecipients(
  ctx: QueryCtx,
  item: Doc<"items">,
): Promise<Map<Id<"users">, ReachableUser>> {
  const recipients = new Map<Id<"users">, ReachableUser>();
  const { userIds } = await itemGrants(ctx, item._id);

  const users = [
    ...(await Promise.all([item.ownerId, ...userIds].map((userId) => ctx.db.get(userId)))),
    ...(await ctx.db
      .query("users")
      .withIndex("by_role", (q) => q.eq("role", "admin"))
      .collect()),
  ];

  for (const user of users) {
    if (user && isReachable(user)) {
      recipients.set(user._id, user);
    }
  }

  return recipients;
}

/** Kuralı karşılamayan anahtar paketlerini siler; silinen olursa kayıt yeni
 * bir DEK ile yeniden şifrelenmek üzere işaretlenir. */
export async function removeDisallowedAccess(ctx: MutationCtx, itemId: Id<"items">) {
  const item = await ctx.db.get(itemId);

  if (!item) {
    return;
  }

  const recipients = await directRecipients(ctx, item);
  const { departmentIds } = await itemGrants(ctx, itemId);

  let removed = false;

  for (const access of await ctx.db
    .query("itemAccess")
    .withIndex("by_item", (q) => q.eq("item", itemId))
    .collect()) {
    if (!recipients.has(access.userId) && access.userId !== item.ownerId) {
      await ctx.db.delete(access._id);
      removed = true;
    }
  }

  for (const access of await ctx.db
    .query("itemDepartmentAccess")
    .withIndex("by_item", (q) => q.eq("item", itemId))
    .collect()) {
    if (!departmentIds.has(access.department)) {
      await ctx.db.delete(access._id);
      removed = true;
    }
  }

  if (removed && !item.needsRekey) {
    await ctx.db.patch(itemId, { needsRekey: true });
  }
}

/**
 * Departman anahtarı sahiplerinden biri çıkarıldığında: departman anahtarı
 * yenilenmek üzere işaretlenir ve departmanla paylaşılan kayıtlar yeniden
 * şifrelenir (çıkarılan kişi DEK'leri önceden görmüş olabilir).
 */
export async function markDepartmentCompromised(
  ctx: MutationCtx,
  departmentId: Id<"departments">,
) {
  const department = await ctx.db.get(departmentId);

  if (department && department.keyVersion > 0 && !department.needsRotation) {
    await ctx.db.patch(departmentId, { needsRotation: true });
  }

  for (const grant of await ctx.db
    .query("itemGrants")
    .withIndex("by_department", (q) => q.eq("departmentId", departmentId))
    .collect()) {
    const item = await ctx.db.get(grant.item);

    if (item && !item.needsRekey) {
      await ctx.db.patch(item._id, { needsRekey: true });
    }
  }
}

/** Kullanıcının rolü, departmanı ya da durumu değiştiğinde artık tutmaması
 * gereken anahtarları kaldırır. */
export async function reconcileUserAccess(ctx: MutationCtx, userId: Id<"users">) {
  const user = await ctx.db.get(userId);

  for (const access of await ctx.db
    .query("itemAccess")
    .withIndex("by_user", (q) => q.eq("userId", userId))
    .collect()) {
    await removeDisallowedAccess(ctx, access.item);
  }

  for (const key of await ctx.db
    .query("departmentKeys")
    .withIndex("by_user", (q) => q.eq("userId", userId))
    .collect()) {
    if (!user || !isDepartmentKeyHolder(user, key.department)) {
      await ctx.db.delete(key._id);
      await markDepartmentCompromised(ctx, key.department);
    }
  }
}

/** Klasör oluşturabilenler: yöneticiler ve departman yöneticileri. */
export function canCreateFolders(user: Doc<"users">) {
  return user.role === "admin" || user.role === "manager";
}

/** Klasörü düzenleyebilenler (ad, taşıma, silme, alt klasör): yöneticiler
 * her klasörü, departman yöneticileri kendi oluşturduklarını. */
export function canManageFolder(user: Doc<"users">, folder: Doc<"folders">) {
  return user.role === "admin" || (user.role === "manager" && folder.ownerId === user._id);
}

/** Bir kaydı bütün anahtar paketleri, paylaşım kuralları ve geçmişiyle siler. */
export async function deleteItem(ctx: MutationCtx, itemId: Id<"items">) {
  for (const table of ["itemAccess", "itemDepartmentAccess", "itemGrants", "itemHistory"] as const) {
    for (const row of await ctx.db
      .query(table)
      .withIndex("by_item", (q) => q.eq("item", itemId))
      .collect()) {
      await ctx.db.delete(row._id);
    }
  }

  await ctx.db.delete(itemId);
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

const HEX_SECRET = /^[0-9a-f]{64}$/;

/** İstemcinin paroladan türettiği giriş anahtarı (32 bayt, hex). */
export function assertAuthSecret(value: unknown): string {
  if (typeof value !== "string" || !HEX_SECRET.test(value)) {
    throw new ConvexError("Geçersiz giriş bilgisi.");
  }

  return value;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));

  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
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
