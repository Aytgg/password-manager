import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

// Sunucu yalnızca şifreli veri saklar. Tüm şifreleme ve çözme Tauri
// uygulamasının Rust tarafında yapılır; ikili değerler base64 metindir.

export const sealedField = v.object({
  nonce: v.string(),
  ciphertext: v.string(),
});

export const wrappedKey = v.object({
  ephemeralPublicKey: v.string(),
  nonce: v.string(),
  ciphertext: v.string(),
});

export default defineSchema({
  users: defineTable({
    // Clerk kullanıcı kimliği (JWT `sub`).
    clerkId: v.string(),
    email: v.string(),
    displayName: v.string(),
    // X25519 açık anahtarı. Özel anahtar yalnızca kullanıcının cihazında.
    publicKey: v.string(),
    updatedAt: v.number(),
  }).index("by_clerk_id", ["clerkId"]),

  items: defineTable({
    // İstemcinin ürettiği kimlik; şifreli alanların AAD'sine bağlıdır.
    itemId: v.string(),
    ownerId: v.string(),
    // Başlık ve kullanıcı adı (JSON), kaydın DEK'i ile şifreli.
    metadata: sealedField,
    // Parolanın kendisi, kaydın DEK'i ile şifreli.
    secret: sealedField,
    // Her rekey işleminde artar; eşzamanlı değişiklikleri reddetmek için.
    keyVersion: v.number(),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_item_id", ["itemId"])
    .index("by_owner", ["ownerId"]),

  // Kaydın DEK'inin, erişimi olan her kullanıcının açık anahtarına
  // paketlenmiş hali. Satır yoksa kullanıcının erişimi yoktur.
  itemAccess: defineTable({
    item: v.id("items"),
    userId: v.string(),
    access: wrappedKey,
  })
    .index("by_item", ["item"])
    .index("by_user", ["userId"])
    .index("by_item_and_user", ["item", "userId"]),
});
