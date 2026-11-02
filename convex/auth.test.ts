import { convexTest } from "convex-test";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { api } from "./_generated/api";
import schema from "./schema";
import { modules } from "./test.setup";

const newTest = () => convexTest(schema, modules);
type TestConvex = ReturnType<typeof newTest>;

// İstemcinin paroladan türettiği 32 baytlık giriş anahtarı (hex).
const secret = (n: number) => n.toString(16).padStart(2, "0").repeat(32);

async function stubJwtKeys() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );

  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const pem = btoa(String.fromCharCode(...pkcs8)).match(/.{1,64}/g)!.join("\n");
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);

  vi.stubEnv("JWT_PRIVATE_KEY", `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`);
  vi.stubEnv("JWKS", JSON.stringify({ keys: [{ use: "sig", ...jwk }] }));
  vi.stubEnv("CONVEX_SITE_URL", "https://test.convex.site");
}

function signIn(
  t: TestConvex,
  params: {
    flow: "signIn" | "signUp";
    email: string;
    secret: string;
    inviteVerifier?: string;
    bootstrapCode?: string;
  },
) {
  return t.action(api.auth.signIn, { provider: "password", params });
}

async function userByEmail(t: TestConvex, email: string) {
  return await t.run((ctx) =>
    ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .unique(),
  );
}

beforeEach(async () => {
  await stubJwtKeys();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("ilk yönetici", () => {
  test("bootstrap koduyla kaydolan ilk hesap yönetici olur", async () => {
    vi.stubEnv("ADMIN_BOOTSTRAP_CODE", "BOOT-CODE");
    const t = newTest();

    const result = await signIn(t, {
      flow: "signUp",
      email: "Boss@VS.com",
      secret: secret(1),
      bootstrapCode: "BOOT-CODE",
    });

    expect(result.tokens?.token).toBeTruthy();
    expect(await userByEmail(t, "boss@vs.com")).toMatchObject({
      role: "admin",
      status: "active",
    });
  });

  test("yönetici varken bootstrap kodu işe yaramaz", async () => {
    vi.stubEnv("ADMIN_BOOTSTRAP_CODE", "BOOT-CODE");
    const t = newTest();

    expect(await t.query(api.auth.bootstrapAvailable, {})).toBe(true);

    await signIn(t, { flow: "signUp", email: "boss@vs.com", secret: secret(1), bootstrapCode: "BOOT-CODE" });

    await expect(
      signIn(t, { flow: "signUp", email: "evil@vs.com", secret: secret(2), bootstrapCode: "BOOT-CODE" }),
    ).rejects.toThrow(/Davet kodu geçersiz/);

    expect(await userByEmail(t, "evil@vs.com")).toBeNull();
    expect(await t.query(api.auth.bootstrapAvailable, {})).toBe(false);
  });

  test("bootstrap kodu tanımlı değilse davetsiz kayıt reddedilir", async () => {
    const t = newTest();

    await expect(
      signIn(t, { flow: "signUp", email: "x@vs.com", secret: secret(1), bootstrapCode: "ANY" }),
    ).rejects.toThrow(/Davet kodu geçersiz/);
  });
});

describe("davet ve giriş", () => {
  async function setupWithInvite() {
    vi.stubEnv("ADMIN_BOOTSTRAP_CODE", "BOOT-CODE");
    const t = newTest();

    await signIn(t, { flow: "signUp", email: "boss@vs.com", secret: secret(1), bootstrapCode: "BOOT-CODE" });
    const boss = (await userByEmail(t, "boss@vs.com"))!;
    const asBoss = t.withIdentity({ subject: `${boss._id}|session` });

    const departmentId = await asBoss.mutation(api.departments.create, { name: "Yazılım" });
    // Kod ve ondan türetilen anahtarlar yöneticinin cihazında üretilir;
    // sunucu yalnızca açık anahtarı ve doğrulayıcıyı görür.
    const invite = { verifier: secret(40) };
    await asBoss.mutation(api.members.invite, {
      email: "New@VS.com",
      role: "member",
      departmentId,
      publicKey: btoa(String.fromCharCode(...new Array<number>(32).fill(7))),
      verifier: invite.verifier,
      expiresInHours: 24,
    });

    return { t, asBoss, invite };
  }

  test("davet koduyla kaydolan kullanıcı aktifleşir ve kod tek kullanımlıktır", async () => {
    const { t, invite } = await setupWithInvite();

    await signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: invite.verifier });

    const user = await userByEmail(t, "new@vs.com");
    expect(user).toMatchObject({ status: "active", role: "member" });
    expect(user!.inviteVerifierHash).toBeUndefined();

    // Aynı kodla başka bir parola kaydedilemez.
    await expect(
      signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(6), inviteVerifier: invite.verifier }),
    ).rejects.toThrow();
  });

  test("yanlış davet kodu reddedilir", async () => {
    const { t } = await setupWithInvite();

    await expect(
      signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: secret(99) }),
    ).rejects.toThrow(/Davet kodu geçersiz/);

    expect(await userByEmail(t, "new@vs.com")).toMatchObject({ status: "invited" });
  });

  test("süresi dolmuş davet reddedilir", async () => {
    const { t } = await setupWithInvite();
    const user = (await userByEmail(t, "new@vs.com"))!;

    await t.run((ctx) => ctx.db.patch(user._id, { inviteExpiresAt: Date.now() - 1 }));

    await expect(
      signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: secret(40) }),
    ).rejects.toThrow(/süresi dolmuş/);
  });

  test("yenilenen davet eski kodu geçersiz kılar", async () => {
    const { t, asBoss, invite } = await setupWithInvite();
    const user = (await userByEmail(t, "new@vs.com"))!;

    const renewed = { verifier: secret(41) };
    await asBoss.mutation(api.members.renewInvite, {
      id: user._id,
      publicKey: btoa(String.fromCharCode(...new Array<number>(32).fill(8))),
      verifier: renewed.verifier,
      expiresInHours: 72,
    });

    await expect(
      signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: invite.verifier }),
    ).rejects.toThrow(/Davet kodu geçersiz/);

    await signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: renewed.verifier });
    expect(await userByEmail(t, "new@vs.com")).toMatchObject({ status: "active" });
  });

  test("giriş doğru secret ister; devre dışı hesap giremez", async () => {
    const { t, asBoss, invite } = await setupWithInvite();

    await signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: invite.verifier });

    expect(
      (await signIn(t, { flow: "signIn", email: "NEW@vs.com", secret: secret(5) })).tokens?.token,
    ).toBeTruthy();

    await expect(
      signIn(t, { flow: "signIn", email: "new@vs.com", secret: secret(6) }),
    ).rejects.toThrow(/E-posta ya da parola yanlış/);

    const user = (await userByEmail(t, "new@vs.com"))!;
    await asBoss.mutation(api.members.update, { id: user._id, enabled: false });

    await expect(
      signIn(t, { flow: "signIn", email: "new@vs.com", secret: secret(5) }),
    ).rejects.toThrow(/devre dışı/);
  });

  test("parola değişikliği mevcut secret'ı ister ve yeni secret ile giriş açılır", async () => {
    const { t, invite } = await setupWithInvite();

    await signIn(t, { flow: "signUp", email: "new@vs.com", secret: secret(5), inviteVerifier: invite.verifier });

    const user = (await userByEmail(t, "new@vs.com"))!;
    const session = await t.run((ctx) =>
      ctx.db
        .query("authSessions")
        .withIndex("userId", (q) => q.eq("userId", user._id))
        .first(),
    );
    const asUser = t.withIdentity({ subject: `${user._id}|${session!._id}` });

    await expect(
      asUser.action(api.auth.changePassword, { currentSecret: secret(9), newSecret: secret(7) }),
    ).rejects.toThrow(/Mevcut parola yanlış/);

    await asUser.action(api.auth.changePassword, { currentSecret: secret(5), newSecret: secret(7) });

    await expect(
      signIn(t, { flow: "signIn", email: "new@vs.com", secret: secret(5) }),
    ).rejects.toThrow(/E-posta ya da parola yanlış/);
    expect(
      (await signIn(t, { flow: "signIn", email: "new@vs.com", secret: secret(7) })).tokens?.token,
    ).toBeTruthy();
  });

  test("ham parola gibi biçimsiz secret kabul edilmez", async () => {
    const { t, invite } = await setupWithInvite();

    await expect(
      signIn(t, { flow: "signUp", email: "new@vs.com", secret: "hunter2hunter2", inviteVerifier: invite.verifier }),
    ).rejects.toThrow(/Geçersiz giriş bilgisi/);
  });
});
