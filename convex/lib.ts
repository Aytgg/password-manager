import { ConvexError } from "convex/values";
import type { Infer } from "convex/values";

import type { QueryCtx } from "./_generated/server";
import type { sealedField, wrappedKey } from "./schema";

export async function requireUserId(ctx: QueryCtx): Promise<string> {
  const identity = await ctx.auth.getUserIdentity();

  if (!identity) {
    throw new ConvexError("Oturum doğrulanamadı.");
  }

  return identity.subject;
}

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

// 32 bayt -> 44 karakter, 12 bayt -> 16 karakter base64.
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
