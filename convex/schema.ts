import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export const sealedField = v.object({
  nonce: v.string(),
  ciphertext: v.string(),
});

export const wrappedKey = v.object({
  ephemeralPublicKey: v.string(),
  nonce: v.string(),
  ciphertext: v.string(),
});

export const role = v.union(
  v.literal("admin"),
  v.literal("manager"),
  v.literal("member"),
);

export const userStatus = v.union(
  v.literal("invited"),
  v.literal("active"),
  v.literal("disabled"),
);

// Convex Auth tabloları; `users` tablosu aşağıda uygulamaya özel tanımlanır
// ve `auth.ts` içindeki createOrUpdateUser ile yönetilir.
const { users: _authUsers, ...authOnlyTables } = authTables;

export default defineSchema({
  ...authOnlyTables,

  // Her departmanın bir X25519 anahtar çifti vardır; özel anahtar
  // `departmentKeys` ile üyelere ve yöneticilere paketlenir. `keyVersion` 0
  // ise anahtar henüz bir yöneticinin cihazında üretilmemiştir.
  departments: defineTable({
    name: v.string(),
    publicKey: v.optional(v.string()),
    keyVersion: v.number(),
    // Bir anahtar sahibi çıkarıldı; anahtar yenilenmeli.
    needsRotation: v.boolean(),
    createdAt: v.number(),
  }).index("by_name", ["name"]),

  departmentKeys: defineTable({
    department: v.id("departments"),
    keyVersion: v.number(),
    userId: v.id("users"),
    access: wrappedKey,
  })
    .index("by_department_and_user", ["department", "userId"])
    .index("by_user", ["userId"]),

  users: defineTable({
    email: v.string(),
    displayName: v.optional(v.string()),
    // Davet edilmiş kullanıcıda davet kodundan türetilen geçici anahtar;
    // kayıttan sonra kullanıcının kalıcı anahtarı.
    publicKey: v.optional(v.string()),
    role,
    departmentId: v.optional(v.id("departments")),
    status: userStatus,
    // Davet kodundan türetilen doğrulayıcının SHA-256 özeti. Kodun kendisi
    // sunucuya hiç gelmez.
    inviteVerifierHash: v.optional(v.string()),
    inviteExpiresAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_email", ["email"])
    .index("by_department", ["departmentId"])
    .index("by_role", ["role"]),

  items: defineTable({
    itemId: v.string(),
    ownerId: v.id("users"),
    metadata: sealedField,
    secret: sealedField,
    keyVersion: v.number(),
    needsRekey: v.boolean(),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_item_id", ["itemId"])
    .index("by_owner", ["ownerId"]),

  itemGrants: defineTable({
    item: v.id("items"),
    userId: v.optional(v.id("users")),
    departmentId: v.optional(v.id("departments")),
  })
    .index("by_item", ["item"])
    .index("by_user", ["userId"])
    .index("by_department", ["departmentId"]),

  // Kaydın DEK'i, doğrudan erişimi olan kullanıcının açık anahtarına paketli.
  itemAccess: defineTable({
    item: v.id("items"),
    userId: v.id("users"),
    access: wrappedKey,
  })
    .index("by_item", ["item"])
    .index("by_user", ["userId"])
    .index("by_item_and_user", ["item", "userId"]),

  // Kaydın DEK'i, paylaşıldığı departmanın açık anahtarına paketli.
  itemDepartmentAccess: defineTable({
    item: v.id("items"),
    department: v.id("departments"),
    keyVersion: v.number(),
    access: wrappedKey,
  })
    .index("by_item", ["item"])
    .index("by_department", ["department"])
    .index("by_item_and_department", ["item", "department"]),
});
