import { ConvexError, v } from "convex/values";

import { internal } from "./_generated/api";
import { action, internalMutation, mutation, query } from "./_generated/server";
import {
  assertPublicKey,
  findUserByClerkId,
  normalizeEmail,
  requireActiveUser,
} from "./lib";

export const me = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();

    if (!identity) {
      return null;
    }

    const user = await findUserByClerkId(ctx, identity.subject);

    if (!user) {
      return null;
    }

    const department = user.departmentId
      ? await ctx.db.get(user.departmentId)
      : null;

    return {
      id: user._id,
      email: user.email,
      displayName: user.displayName ?? user.email,
      role: user.role,
      status: user.status,
      departmentId: user.departmentId ?? null,
      departmentName: department?.name ?? null,
      hasPublicKey: user.publicKey !== undefined,
    };
  },
});

const linkResult = v.union(v.literal("linked"), v.literal("needs_email"));

export const linkAccount = internalMutation({
  args: {
    clerkId: v.string(),
    displayName: v.optional(v.string()),
    verifiedEmail: v.optional(v.string()),
  },
  returns: linkResult,
  handler: async (ctx, args) => {
    const now = Date.now();
    const existing = await findUserByClerkId(ctx, args.clerkId);

    if (existing) {
      if (existing.status !== "active") {
        throw new ConvexError("Bu hesap devre dışı bırakılmış.");
      }

      if (args.displayName && args.displayName !== existing.displayName) {
        await ctx.db.patch(existing._id, {
          displayName: args.displayName,
          updatedAt: now,
        });
      }

      return "linked";
    }

    if (!args.verifiedEmail) {
      return "needs_email";
    }

    const email = normalizeEmail(args.verifiedEmail);

    const invited = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .unique();

    if (invited) {
      if (invited.status === "disabled") {
        throw new ConvexError("Bu hesap devre dışı bırakılmış.");
      }

      if (invited.clerkId !== undefined) {
        throw new ConvexError(
          "Bu e-posta başka bir hesaba bağlı. Yöneticine başvur.",
        );
      }

      await ctx.db.patch(invited._id, {
        clerkId: args.clerkId,
        displayName: args.displayName ?? invited.displayName,
        status: "active",
        updatedAt: now,
      });

      return "linked";
    }

    const adminEmail = process.env.ADMIN_EMAIL;

    if (adminEmail && normalizeEmail(adminEmail) === email) {
      await ctx.db.insert("users", {
        email,
        clerkId: args.clerkId,
        displayName: args.displayName,
        role: "admin",
        status: "active",
        createdAt: now,
        updatedAt: now,
      });

      return "linked";
    }

    throw new ConvexError(
      "Bu hesap davet edilmemiş. Erişim için yöneticine başvur.",
    );
  },
});

type ClerkUser = {
  primary_email_address_id: string | null;
  email_addresses: {
    id: string;
    email_address: string;
    verification: { status: string } | null;
  }[];
};

// Oturum token'ı e-posta taşımıyorsa doğrulanmış birincil e-posta Clerk
// Backend API'sinden alınır; böylece Clerk JWT şablonuna bağımlı kalınmaz.
async function fetchVerifiedPrimaryEmail(clerkId: string): Promise<string> {
  const secretKey = process.env.CLERK_SECRET_KEY;

  if (!secretKey) {
    throw new ConvexError("Sunucuda CLERK_SECRET_KEY tanımlı değil.");
  }

  const response = await fetch(
    `https://api.clerk.com/v1/users/${encodeURIComponent(clerkId)}`,
    { headers: { Authorization: `Bearer ${secretKey}` } },
  );

  if (!response.ok) {
    console.error("Clerk user lookup failed", response.status, await response.text());
    throw new ConvexError(`Clerk kullanıcı bilgisi alınamadı (HTTP ${response.status}).`);
  }

  const user = (await response.json()) as ClerkUser;

  const primary = user.email_addresses.find(
    (address) => address.id === user.primary_email_address_id,
  );

  if (!primary || primary.verification?.status !== "verified") {
    throw new ConvexError("Hesabın birincil e-posta adresi doğrulanmamış.");
  }

  return primary.email_address;
}

export const activate = action({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();

    if (!identity) {
      throw new ConvexError("Oturum doğrulanamadı.");
    }

    const clerkId = identity.subject;
    const displayName = identity.name?.trim() || undefined;

    const tokenEmail =
      identity.email && identity.emailVerified === true ? identity.email : undefined;

    const result = await ctx.runMutation(internal.users.linkAccount, {
      clerkId,
      displayName,
      verifiedEmail: tokenEmail,
    });

    if (result === "needs_email") {
      await ctx.runMutation(internal.users.linkAccount, {
        clerkId,
        displayName,
        verifiedEmail: await fetchVerifiedPrimaryEmail(clerkId),
      });
    }

    return null;
  },
});

export const setPublicKey = mutation({
  args: { publicKey: v.string() },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);

    assertPublicKey(args.publicKey);

    if (user.publicKey === args.publicKey) {
      return;
    }

    if (user.clerkId !== undefined && user.publicKey !== undefined) {
      const staleAccesses = await ctx.db
        .query("itemAccess")
        .withIndex("by_user", (q) => q.eq("userId", user.clerkId!))
        .collect();

      for (const access of staleAccesses) {
        await ctx.db.delete(access._id);
      }
    }

    await ctx.db.patch(user._id, {
      publicKey: args.publicKey,
      updatedAt: Date.now(),
    });
  },
});
