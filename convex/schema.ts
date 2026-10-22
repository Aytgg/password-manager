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

export default defineSchema({
  departments: defineTable({
    name: v.string(),
    createdAt: v.number(),
  }).index("by_name", ["name"]),

  users: defineTable({
    email: v.string(),
    clerkId: v.optional(v.string()),
    displayName: v.optional(v.string()),
    publicKey: v.optional(v.string()),
    role,
    departmentId: v.optional(v.id("departments")),
    status: userStatus,
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_clerk_id", ["clerkId"])
    .index("by_email", ["email"])
    .index("by_department", ["departmentId"]),

  items: defineTable({
    itemId: v.string(),
    ownerId: v.string(),
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
    userId: v.optional(v.string()),
    departmentId: v.optional(v.id("departments")),
  })
    .index("by_item", ["item"])
    .index("by_user", ["userId"])
    .index("by_department", ["departmentId"]),

  itemAccess: defineTable({
    item: v.id("items"),
    userId: v.string(),
    access: wrappedKey,
  })
    .index("by_item", ["item"])
    .index("by_user", ["userId"])
    .index("by_item_and_user", ["item", "userId"]),
});
