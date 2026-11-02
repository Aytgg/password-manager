import { ConvexCredentials } from "@convex-dev/auth/providers/ConvexCredentials";
import {
  convexAuth,
  createAccount,
  getAuthSessionId,
  getAuthUserId,
  invalidateSessions,
  modifyAccountCredentials,
  retrieveAccount,
} from "@convex-dev/auth/server";
import { ConvexError, v } from "convex/values";

import { internal } from "./_generated/api";
import type { DataModel, Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { action, internalQuery, query } from "./_generated/server";
import { assertAuthSecret, normalizeEmail, sha256Hex } from "./lib";

const PROVIDER = "password";

async function hasAdmin(ctx: QueryCtx) {
  return (
    (await ctx.db
      .query("users")
      .withIndex("by_role", (q) => q.eq("role", "admin"))
      .first()) !== null
  );
}

/** Henüz yönetici yoksa ilk yönetici bootstrap koduyla kaydolabilir. */
export const bootstrapAvailable = query({
  args: {},
  returns: v.boolean(),
  handler: async (ctx) => !!process.env.ADMIN_BOOTSTRAP_CODE && !(await hasAdmin(ctx)),
});

// İstemci parolayı hiçbir zaman göndermez. Gönderilen `secret`, paroladan
// Argon2id + HKDF ile türetilmiş 256 bitlik bir değerdir ve kasa anahtarına
// ulaşmaya yetmez. Yüksek entropili olduğu için sunucuda SHA-256 yeterlidir;
// parola tahmini zaten istemci tarafındaki Argon2id maliyetini gerektirir.
const secretCrypto = {
  hashSecret: async (secret: string) => await sha256Hex(secret),
  verifySecret: async (secret: string, hash: string) => {
    const actual = await sha256Hex(secret);

    if (actual.length !== hash.length) return false;

    let diff = 0;
    for (let i = 0; i < actual.length; i++) {
      diff |= actual.charCodeAt(i) ^ hash.charCodeAt(i);
    }
    return diff === 0;
  },
};

/**
 * - `signIn`: e-posta + secret.
 * - `signUp`: davet edilen e-posta + secret + davet kodundan istemcide
 *   türetilen `inviteVerifier` (kodun kendisi sunucuya gelmez).
 *   Henüz yönetici yokken ilk yönetici `bootstrapCode` (ADMIN_BOOTSTRAP_CODE)
 *   ile kaydolur; o anda sistemde davet olmadığı için kod düz gönderilir.
 */
const Password = ConvexCredentials<DataModel>({
  id: PROVIDER,
  authorize: async (params, ctx) => {
    const email = normalizeEmail(String(params.email ?? ""));
    const secret = assertAuthSecret(params.secret);

    if (!email) {
      throw new ConvexError("E-posta gerekli.");
    }

    if (params.flow === "signUp") {
      const inviteVerifier =
        params.inviteVerifier === undefined ? undefined : assertAuthSecret(params.inviteVerifier);
      const bootstrapCode = String(params.bootstrapCode ?? "").trim();

      if (!inviteVerifier && !bootstrapCode) {
        throw new ConvexError("Davet kodu gerekli.");
      }

      const { user } = await createAccount<DataModel>(ctx, {
        provider: PROVIDER,
        account: { id: email, secret },
        profile: { email, inviteVerifier, bootstrapCode } as never,
      });

      if (user.status !== "active") {
        throw new ConvexError("Bu hesabın sisteme erişim yetkisi yok.");
      }

      return { userId: user._id };
    }

    if (params.flow === "signIn") {
      const retrieved = await retrieveAccount<DataModel>(ctx, {
        provider: PROVIDER,
        account: { id: email, secret },
      }).catch(() => null);

      if (!retrieved) {
        throw new ConvexError("E-posta ya da parola yanlış.");
      }

      if (retrieved.user.status !== "active") {
        throw new ConvexError("Bu hesap devre dışı bırakılmış.");
      }

      return { userId: retrieved.user._id };
    }

    throw new ConvexError("Geçersiz giriş akışı.");
  },
  crypto: secretCrypto,
});

export const { auth, signIn, signOut, store, isAuthenticated } = convexAuth({
  providers: [Password],
  callbacks: {
    // Kullanıcı kaydı yalnızca davetle (ya da ilk yönetici için bootstrap
    // koduyla) oluşur. Var olan hesaplarda kullanıcı satırı değiştirilmez.
    async createOrUpdateUser(rawCtx, args) {
      if (args.existingUserId) {
        return args.existingUserId;
      }

      const ctx = rawCtx as unknown as MutationCtx;

      const email = normalizeEmail(String(args.profile.email ?? ""));
      const inviteVerifier = String(args.profile.inviteVerifier ?? "");
      const bootstrapCode = String(args.profile.bootstrapCode ?? "");
      const now = Date.now();

      const invited = await ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", email))
        .unique();

      if (invited) {
        if (
          invited.status !== "invited" ||
          invited.inviteVerifierHash === undefined ||
          !inviteVerifier ||
          invited.inviteVerifierHash !== (await sha256Hex(inviteVerifier)) ||
          (invited.inviteExpiresAt ?? 0) < now
        ) {
          throw new ConvexError("Davet kodu geçersiz ya da süresi dolmuş.");
        }

        // Açık anahtar, kullanıcı ona paketlenmiş anahtarları kalıcı
        // anahtarına taşıyana kadar (users.rotateKey) geçici anahtar kalır.
        await ctx.db.patch(invited._id, {
          status: "active",
          inviteVerifierHash: undefined,
          inviteExpiresAt: undefined,
          updatedAt: now,
        });

        return invited._id;
      }

      const expectedBootstrapCode = process.env.ADMIN_BOOTSTRAP_CODE;

      if (
        expectedBootstrapCode &&
        bootstrapCode === expectedBootstrapCode &&
        !(await hasAdmin(ctx))
      ) {
        return await ctx.db.insert("users", {
          email,
          role: "admin",
          status: "active",
          createdAt: now,
          updatedAt: now,
        });
      }

      throw new ConvexError("Davet kodu geçersiz ya da süresi dolmuş.");
    },
  },
});

export const accountEmail = internalQuery({
  args: { userId: v.id("users") },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    const user = await ctx.db.get(args.userId);
    return user?.status === "active" ? user.email : null;
  },
});

/**
 * Parolayı değiştirir. İstemci, mevcut ve yeni paroladan türettiği iki
 * secret'ı gönderir; diğer cihazlardaki oturumlar kapatılır.
 */
export const changePassword = action({
  args: { currentSecret: v.string(), newSecret: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);

    if (!userId) {
      throw new ConvexError("Oturum doğrulanamadı.");
    }

    const email: string | null = await ctx.runQuery(internal.auth.accountEmail, { userId });

    if (!email) {
      throw new ConvexError("Bu hesabın sisteme erişim yetkisi yok.");
    }

    const currentSecret = assertAuthSecret(args.currentSecret);
    const newSecret = assertAuthSecret(args.newSecret);

    const retrieved = await retrieveAccount<DataModel>(ctx, {
      provider: PROVIDER,
      account: { id: email, secret: currentSecret },
    }).catch(() => null);

    if (!retrieved || retrieved.user._id !== userId) {
      throw new ConvexError("Mevcut parola yanlış.");
    }

    await modifyAccountCredentials<DataModel>(ctx, {
      provider: PROVIDER,
      account: { id: email, secret: newSecret },
    });

    const sessionId = await getAuthSessionId(ctx);

    await invalidateSessions<DataModel>(ctx, {
      userId: userId as Id<"users">,
      except: sessionId ? [sessionId] : [],
    });

    return null;
  },
});
