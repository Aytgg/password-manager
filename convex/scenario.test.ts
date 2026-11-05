import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";

import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import schema from "./schema";
import { modules } from "./test.setup";

// Sunucu şifreli veriyi çözmez; biçimce geçerli base64 değerler yeterli.
const b64 = (bytes: number, fill: number) =>
  btoa(String.fromCharCode(...new Array<number>(bytes).fill(fill)));
const publicKey = (n: number) => b64(32, n);
const sealed = (n: number) => ({ nonce: b64(12, n), ciphertext: b64(40, n) });
const wrapped = (n: number) => ({ ephemeralPublicKey: b64(32, n), nonce: b64(12, n), ciphertext: b64(48, n) });
const verifier = (n: number) => n.toString(16).padStart(2, "0").repeat(32);

let itemCounter = 0;

/**
 * Sıfırdan bir kurulumu, istemcideki KeySync bileşeninin yaptığı işlerle
 * birlikte canlandırır. Her kullanıcının "cihazı" uygulama açıkken arka
 * planda şunları yapar:
 * 1. kimlik anahtarını eşitler (davetle kayıtta rotateKey, yoksa setPublicKey),
 * 2. keys.pendingWork: departman anahtarı oluşturma, dağıtma, yenileme,
 * 3. items.pendingWork: yeniden şifreleme ve eksik paketleri doldurma.
 */
async function world() {
  const t = convexTest(schema, modules);

  // İlk yönetici bootstrap koduyla kaydolur; açık anahtarı yoktur.
  const adminId = await t.run((ctx) =>
    ctx.db.insert("users", {
      email: "admin@vs.com",
      displayName: "admin",
      role: "admin",
      status: "active",
      createdAt: 0,
      updatedAt: 0,
    }),
  );

  const asId = (userId: Id<"users">) => t.withIdentity({ subject: `${userId}|session` });

  // Cihazdaki kalıcı kimlik ve (davetliyse) geçici davet kimliği.
  const devices = new Map<Id<"users">, { identity: string; invite: string | null }>();
  let keyCounter = 100;

  devices.set(adminId, { identity: publicKey(keyCounter++), invite: null });

  async function syncIdentity(userId: Id<"users">) {
    const device = devices.get(userId)!;
    const me = await asId(userId).query(api.users.me, {});

    if (device.invite && me?.publicKey === device.invite) {
      const keys = await asId(userId).query(api.users.myWrappedKeys, {});
      await asId(userId).mutation(api.users.rotateKey, {
        fromPublicKey: device.invite,
        publicKey: device.identity,
        itemAccesses: keys.itemAccesses.map((entry) => ({ id: entry.id, access: wrapped(70) })),
        departmentKeys: keys.departmentKeys.map((entry) => ({ id: entry.id, access: wrapped(71) })),
      });
      device.invite = null;
      return true;
    }

    device.invite = null;

    if (me?.publicKey !== device.identity) {
      await asId(userId).mutation(api.users.setPublicKey, { publicKey: device.identity });
      return true;
    }

    return false;
  }

  async function departmentWork(userId: Id<"users">) {
    const as = asId(userId);
    const work = await as.query(api.keys.pendingWork, {});

    for (const init of work.inits) {
      await as.mutation(api.keys.initDepartmentKey, {
        departmentId: init.departmentId,
        publicKey: publicKey(keyCounter++),
        accesses: init.holders.map((h) => ({ userId: h.userId, access: wrapped(30) })),
      });
    }

    for (const fill of work.fills) {
      await as.mutation(api.keys.addDepartmentKeys, {
        departmentId: fill.departmentId,
        keyVersion: fill.keyVersion,
        accesses: fill.recipients.map((r) => ({ userId: r.userId, access: wrapped(31) })),
      });
    }

    for (const rotation of work.rotations) {
      await as.mutation(api.keys.rotateDepartmentKey, {
        departmentId: rotation.departmentId,
        keyVersion: rotation.keyVersion,
        publicKey: publicKey(keyCounter++),
        accesses: rotation.holders.map((h) => ({ userId: h.userId, access: wrapped(32) })),
        itemKeys: rotation.itemKeys.map((k) => ({ item: k.item, access: wrapped(33) })),
      });
    }

    return work.inits.length + work.fills.length + work.rotations.length > 0;
  }

  async function itemWork(userId: Id<"users">) {
    const as = asId(userId);
    const work = await as.query(api.items.pendingWork, {});

    for (const task of work.rekeys) {
      await as.mutation(api.items.rekey, {
        id: task.item.id,
        keyVersion: task.item.keyVersion,
        metadata: sealed(3),
        secret: sealed(4),
        history: task.history,
        accesses: task.recipients.map((r) => ({ userId: r.userId, access: wrapped(40) })),
        departmentAccesses: task.departments.map((d) => ({
          departmentId: d.departmentId,
          keyVersion: d.keyVersion,
          access: wrapped(41),
        })),
      });
    }

    for (const task of work.fills) {
      await as.mutation(api.items.addAccesses, {
        id: task.item.id,
        keyVersion: task.item.keyVersion,
        accesses: task.recipients.map((r) => ({ userId: r.userId, access: wrapped(42) })),
        departmentAccesses: task.departments.map((d) => ({
          departmentId: d.departmentId,
          keyVersion: d.keyVersion,
          access: wrapped(43),
        })),
      });
    }

    return work.rekeys.length + work.fills.length > 0;
  }

  /** Kullanıcı uygulamayı açar; arka plan işleri bitene kadar çalışır. */
  async function open(userId: Id<"users">) {
    for (let round = 0; round < 10; round++) {
      const changed =
        (await syncIdentity(userId)) | Number(await departmentWork(userId)) | Number(await itemWork(userId));
      if (!changed) return;
    }
    throw new Error("Arka plan işleri bitmedi.");
  }

  async function invite(email: string, departmentId: Id<"departments">, role: "member" | "manager" = "member") {
    const inviteKey = publicKey(keyCounter++);
    await asId(adminId).mutation(api.members.invite, {
      email,
      role,
      departmentId,
      publicKey: inviteKey,
      verifier: verifier(keyCounter),
      expiresInHours: 24,
    });

    const userId = (await t.run((ctx) =>
      ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", email))
        .unique(),
    ))!._id;

    devices.set(userId, { identity: publicKey(keyCounter++), invite: inviteKey });
    return userId;
  }

  /** Davetli kayıt olur (auth.createOrUpdateUser'ın yaptığı). */
  const register = (userId: Id<"users">) =>
    t.run((ctx) =>
      ctx.db.patch(userId, { status: "active", inviteVerifierHash: undefined, inviteExpiresAt: undefined }),
    );

  const createItem = (owner: Id<"users">) =>
    asId(owner).mutation(api.items.create, {
      itemId: `item-${(++itemCounter).toString(16).padStart(32, "0")}`,
      metadata: sealed(1),
      secret: sealed(2),
      ownerAccess: wrapped(1),
    });

  /** Alıcının gözünden: listede mi, "hazırlanıyor" sayısı, paneldeki durum. */
  async function view(userId: Id<"users">, itemId: Id<"items">, sharer: Id<"users">) {
    const listed = (await asId(userId).query(api.items.listMine, {})).find((item) => item.id === itemId);
    const pending = await asId(userId).query(api.items.pendingSharedCount, {});
    const panel = (await asId(sharer).query(api.items.sharing, { id: itemId })).users.find(
      (user) => user.userId === userId,
    );
    return { visible: listed !== undefined, via: listed?.access.kind ?? null, pending, hasKey: panel?.hasKey };
  }

  return { t, adminId, asId, open, invite, register, createItem, view };
}

describe("uçtan uca: departman üzerinden paylaşım", () => {
  test("yönetici kurar, davet eder; üye paylaşır, departman üyesi görür", async () => {
    const { adminId, asId, open, invite, register, createItem, view } = await world();
    const admin = asId(adminId);

    await open(adminId);
    const yazilim = await admin.mutation(api.departments.create, { name: "Yazılım" });
    const satis = await admin.mutation(api.departments.create, { name: "Satış" });

    const alice = await invite("alice@vs.com", yazilim);
    const carol = await invite("carol@vs.com", satis);
    await open(adminId);

    await register(alice);
    await open(alice);
    await register(carol);
    await open(carol);

    const item = await createItem(alice);
    await asId(alice).mutation(api.items.setDepartmentGrant, { id: item, departmentId: satis, granted: true });
    await open(alice);

    expect(await view(carol, item, alice)).toEqual({ visible: true, via: "department", pending: 0, hasKey: true });
  });

  test("yönetici departmanları kurduktan sonra uygulamayı hiç açmazsa", async () => {
    const { adminId, asId, open, invite, register, createItem, view } = await world();
    const admin = asId(adminId);

    await open(adminId);
    const yazilim = await admin.mutation(api.departments.create, { name: "Yazılım" });
    const satis = await admin.mutation(api.departments.create, { name: "Satış" });
    const alice = await invite("alice@vs.com", yazilim);
    const carol = await invite("carol@vs.com", satis);
    // Yönetici arka plan işleri çalışmadan çıkar.

    await register(alice);
    await open(alice);
    await register(carol);
    await open(carol);

    const item = await createItem(alice);
    await asId(alice).mutation(api.items.setDepartmentGrant, { id: item, departmentId: satis, granted: true });
    await open(alice);

    // Departman anahtarı henüz yok: beklemede görünmesi doğru.
    expect(await view(carol, item, alice)).toMatchObject({ visible: false, pending: 1 });

    // Yönetici uygulamayı açınca anahtar oluşur; sonra sahip ya da alıcı açınca tamamlanır.
    await open(adminId);
    await open(alice);
    expect(await view(carol, item, alice)).toEqual({ visible: true, via: "department", pending: 0, hasKey: true });
  });

  test("alıcı paylaşımdan sonra kaydolur", async () => {
    const { adminId, asId, open, invite, register, createItem, view } = await world();
    const admin = asId(adminId);

    await open(adminId);
    const yazilim = await admin.mutation(api.departments.create, { name: "Yazılım" });
    const satis = await admin.mutation(api.departments.create, { name: "Satış" });
    const alice = await invite("alice@vs.com", yazilim);
    await open(adminId);
    await register(alice);
    await open(alice);

    const item = await createItem(alice);
    await asId(alice).mutation(api.items.setDepartmentGrant, { id: item, departmentId: satis, granted: true });
    await open(alice);

    const carol = await invite("carol@vs.com", satis);
    await open(adminId);
    await register(carol);
    await open(carol);

    expect(await view(carol, item, alice)).toEqual({ visible: true, via: "department", pending: 0, hasKey: true });
  });

  test("paylaşan kişi aynı departmanda", async () => {
    const { adminId, asId, open, invite, register, createItem, view } = await world();
    const admin = asId(adminId);

    await open(adminId);
    const satis = await admin.mutation(api.departments.create, { name: "Satış" });
    const alice = await invite("alice@vs.com", satis);
    const carol = await invite("carol@vs.com", satis);
    await open(adminId);
    await register(alice);
    await open(alice);
    await register(carol);
    await open(carol);

    const item = await createItem(alice);
    await asId(alice).mutation(api.items.setDepartmentGrant, { id: item, departmentId: satis, granted: true });
    await open(alice);

    expect(await view(carol, item, alice)).toEqual({ visible: true, via: "department", pending: 0, hasKey: true });
  });

  test("yönetici paylaşır, departman yöneticisi ve üye görür", async () => {
    const { adminId, asId, open, invite, register, createItem, view } = await world();
    const admin = asId(adminId);

    await open(adminId);
    const satis = await admin.mutation(api.departments.create, { name: "Satış" });
    const mia = await invite("mia@vs.com", satis, "manager");
    const carol = await invite("carol@vs.com", satis);
    await open(adminId);
    await register(mia);
    await open(mia);
    await register(carol);
    await open(carol);

    const item = await createItem(adminId);
    await admin.mutation(api.items.setDepartmentGrant, { id: item, departmentId: satis, granted: true });
    await open(adminId);

    expect(await view(carol, item, adminId)).toEqual({ visible: true, via: "department", pending: 0, hasKey: true });
    expect(await view(mia, item, adminId)).toEqual({ visible: true, via: "department", pending: 0, hasKey: true });
  });
});
