import { convexTest } from "convex-test";
import { afterEach, describe, expect, test, vi } from "vitest";

import { api, internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import schema from "./schema";
import { modules } from "./test.setup";

// Sunucu şifreli veriyi çözmediği için testlerde biçimce geçerli, içerikçe
// anlamsız base64 değerler yeterlidir.
const b64 = (bytes: number, fill: number) =>
  btoa(String.fromCharCode(...new Array<number>(bytes).fill(fill)));

const publicKey = (n: number) => b64(32, n);
const sealed = (n: number) => ({ nonce: b64(12, n), ciphertext: b64(40, n) });
const wrapped = (n: number) => ({
  ephemeralPublicKey: b64(32, n),
  nonce: b64(12, n),
  ciphertext: b64(48, n),
});

let itemCounter = 0;
const newItemId = () => `item-${(++itemCounter).toString(16).padStart(32, "0")}`;

async function setup() {
  const t = convexTest(schema, modules);

  const ids = await t.run(async (ctx) => {
    const now = Date.now();

    const yazilim = await ctx.db.insert("departments", { name: "Yazılım", createdAt: now });
    const satis = await ctx.db.insert("departments", { name: "Satış", createdAt: now });

    const user = (
      clerkId: string,
      role: "admin" | "manager" | "member",
      departmentId: Id<"departments"> | undefined,
      key: number,
    ) =>
      ctx.db.insert("users", {
        email: `${clerkId}@vs.com`,
        clerkId,
        displayName: clerkId,
        publicKey: publicKey(key),
        role,
        departmentId,
        status: "active",
        createdAt: now,
        updatedAt: now,
      });

    return {
      yazilim,
      satis,
      admin: await user("admin", "admin", undefined, 1),
      alice: await user("alice", "member", yazilim, 2),
      bob: await user("bob", "member", yazilim, 3),
      carol: await user("carol", "member", satis, 4),
      manager: await user("manager", "manager", satis, 5),
    };
  });

  const as = (clerkId: string) => t.withIdentity({ subject: clerkId });

  async function createItem(owner: string) {
    return await as(owner).mutation(api.items.create, {
      itemId: newItemId(),
      metadata: sealed(1),
      secret: sealed(2),
      ownerAccess: wrapped(1),
    });
  }

  async function fill(actor: string, id: Id<"items">, userIds: string[]) {
    const item = await t.run(async (ctx) => ctx.db.get(id));

    await as(actor).mutation(api.items.addAccesses, {
      id,
      keyVersion: item!.keyVersion,
      accesses: userIds.map((userId, index) => ({ userId, access: wrapped(10 + index) })),
    });
  }

  async function accessUserIds(id: Id<"items">) {
    return await t.run(async (ctx) =>
      (
        await ctx.db
          .query("itemAccess")
          .withIndex("by_item", (q) => q.eq("item", id))
          .collect()
      )
        .map((row) => row.userId)
        .sort(),
    );
  }

  const getItem = (id: Id<"items">) => t.run(async (ctx) => ctx.db.get(id));

  return { t, ids, as, createItem, fill, accessUserIds, getItem };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("hesap eşleştirme", () => {
  test("ADMIN_EMAIL ile giren doğrulanmış hesap yönetici olur", async () => {
    vi.stubEnv("ADMIN_EMAIL", "boss@vs.com");
    const t = convexTest(schema, modules);
    const boss = t.withIdentity({ subject: "boss", email: "Boss@VS.com", emailVerified: true });

    await boss.action(api.users.activate, {});

    expect(await boss.query(api.users.me, {})).toMatchObject({
      role: "admin",
      status: "active",
      email: "boss@vs.com",
    });
  });

  test("davet edilmemiş hesap reddedilir", async () => {
    vi.stubEnv("ADMIN_EMAIL", "boss@vs.com");
    const t = convexTest(schema, modules);

    await expect(
      t
        .withIdentity({ subject: "stranger", email: "stranger@vs.com", emailVerified: true })
        .action(api.users.activate, {}),
    ).rejects.toThrow(/davet edilmemiş/);

    expect(
      await t.withIdentity({ subject: "stranger" }).query(api.users.me, {}),
    ).toBeNull();
  });

  test("davetli e-posta ilk girişte hesaba bağlanır", async () => {
    const { t, ids } = await setup();

    await t.run(async (ctx) => {
      await ctx.db.insert("users", {
        email: "new@vs.com",
        role: "member",
        departmentId: ids.yazilim,
        status: "invited",
        createdAt: 0,
        updatedAt: 0,
      });
    });

    const newcomer = t.withIdentity({ subject: "new", email: "new@vs.com", emailVerified: true });
    await newcomer.action(api.users.activate, {});

    expect(await newcomer.query(api.users.me, {})).toMatchObject({
      status: "active",
      departmentName: "Yazılım",
    });
  });

  test("devre dışı bırakılmış davet kabul edilmez", async () => {
    const { t, ids } = await setup();

    await t.run(async (ctx) => {
      await ctx.db.insert("users", {
        email: "gone@vs.com",
        role: "member",
        departmentId: ids.yazilim,
        status: "disabled",
        createdAt: 0,
        updatedAt: 0,
      });
    });

    await expect(
      t
        .withIdentity({ subject: "gone", email: "gone@vs.com", emailVerified: true })
        .action(api.users.activate, {}),
    ).rejects.toThrow(/devre dışı/);
  });

  test("token'daki doğrulanmamış e-postaya güvenilmez", async () => {
    vi.stubEnv("ADMIN_EMAIL", "boss@vs.com");
    vi.stubEnv("CLERK_SECRET_KEY", "");
    const t = convexTest(schema, modules);

    // Doğrulanmamış e-posta kullanılmaz; Clerk API'ye başvurulur, anahtar
    // olmadığı için işlem reddedilir ve yönetici hesabı oluşmaz.
    await expect(
      t
        .withIdentity({ subject: "fake", email: "boss@vs.com", emailVerified: false })
        .action(api.users.activate, {}),
    ).rejects.toThrow(/CLERK_SECRET_KEY/);

    expect(await t.withIdentity({ subject: "fake" }).query(api.users.me, {})).toBeNull();
  });
});

describe("paylaşım ve rekey", () => {
  test("departman paylaşımı üyeye bekleyen anahtar bırakır, tamamlanınca görünür", async () => {
    const { as, ids, createItem, fill } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.yazilim,
      granted: true,
    });

    expect(await as("bob").query(api.items.listMine, {})).toHaveLength(0);
    expect(await as("bob").query(api.items.pendingSharedCount, {})).toBe(1);

    // Erişimi olmayan bob anahtar üretemez; işi erişimi olan alice görür.
    expect((await as("bob").query(api.items.pendingWork, {})).fills).toHaveLength(0);

    const work = await as("alice").query(api.items.pendingWork, {});
    expect(work.fills).toHaveLength(1);
    expect(work.fills[0].recipients.map((r) => r.userId)).toEqual(["bob"]);
    expect(work.fills[0].recipients[0].publicKey).toBe(publicKey(3));

    await fill("alice", id, ["bob"]);

    expect(await as("bob").query(api.items.listMine, {})).toHaveLength(1);
    expect(await as("bob").query(api.items.pendingSharedCount, {})).toBe(0);
    expect((await as("alice").query(api.items.pendingWork, {})).fills).toHaveLength(0);
  });

  test("departman paylaşımı kaldırılınca erişim silinir ve rekey zorunlu olur", async () => {
    const { as, ids, createItem, fill, accessUserIds, getItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.yazilim,
      granted: true,
    });
    await fill("alice", id, ["bob"]);

    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.yazilim,
      granted: false,
    });

    expect(await as("bob").query(api.items.listMine, {})).toHaveLength(0);
    expect(await accessUserIds(id)).toEqual(["alice"]);
    expect((await getItem(id))!.needsRekey).toBe(true);

    const work = await as("alice").query(api.items.pendingWork, {});
    expect(work.rekeys).toHaveLength(1);
    expect(work.rekeys[0].recipients).toEqual([]);
  });

  test("rekey kuralları: yalnız sahip, güncel sürüm, yalnız yetkililer, sahip dahil", async () => {
    const { as, createItem, fill, accessUserIds, getItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: true });
    await fill("alice", id, ["bob"]);
    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: false });

    const valid = {
      id,
      keyVersion: 1,
      metadata: sealed(7),
      secret: sealed(8),
      accesses: [{ userId: "alice", access: wrapped(20) }],
    };

    await expect(as("bob").mutation(api.items.rekey, valid)).rejects.toThrow(/sahibi değilsin/);
    await expect(as("carol").mutation(api.items.rekey, valid)).rejects.toThrow(/sahibi değilsin/);

    await expect(
      as("alice").mutation(api.items.rekey, { ...valid, keyVersion: 0 }),
    ).rejects.toThrow(/başka bir işlemle güncellendi/);

    await expect(
      as("alice").mutation(api.items.rekey, {
        ...valid,
        accesses: [...valid.accesses, { userId: "bob", access: wrapped(21) }],
      }),
    ).rejects.toThrow(/erişim vermiyor/);

    await expect(
      as("alice").mutation(api.items.rekey, { ...valid, accesses: [] }),
    ).rejects.toThrow(/sahibinin erişimi kaldırılamaz/);

    await expect(
      as("alice").mutation(api.items.rekey, {
        ...valid,
        accesses: [valid.accesses[0], valid.accesses[0]],
      }),
    ).rejects.toThrow(/tekrar eden/);

    await as("alice").mutation(api.items.rekey, valid);

    const item = await getItem(id);
    expect(item).toMatchObject({ keyVersion: 2, needsRekey: false, metadata: sealed(7) });
    expect(await accessUserIds(id)).toEqual(["alice"]);
    expect((await as("alice").query(api.items.pendingWork, {})).rekeys).toHaveLength(0);
  });

  test("bir kişi kaldırılınca rekey kalan kişileri korur", async () => {
    const { as, createItem, fill, accessUserIds } = await setup();
    const id = await createItem("alice");

    for (const userId of ["bob", "carol"]) {
      await as("alice").mutation(api.items.setUserGrant, { id, userId, granted: true });
    }
    await fill("alice", id, ["bob", "carol"]);

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: false });

    const task = (await as("alice").query(api.items.pendingWork, {})).rekeys[0];
    expect(task.recipients).toEqual([{ userId: "carol", publicKey: publicKey(4) }]);

    await as("alice").mutation(api.items.rekey, {
      id,
      keyVersion: task.item.keyVersion,
      metadata: sealed(7),
      secret: sealed(8),
      accesses: [
        { userId: "alice", access: wrapped(20) },
        { userId: "carol", access: wrapped(21) },
      ],
    });

    expect(await accessUserIds(id)).toEqual(["alice", "carol"]);
    expect(await as("carol").query(api.items.listMine, {})).toHaveLength(1);
    expect(await as("bob").query(api.items.listMine, {})).toHaveLength(0);
  });

  test("rekey beklerken eski anahtar dağıtılmaz, rekey sonrası eksikler tamamlanır", async () => {
    const { as, createItem, fill } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: true });
    await fill("alice", id, ["bob"]);
    await as("alice").mutation(api.items.setUserGrant, { id, userId: "carol", granted: true });
    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: false });

    let work = await as("alice").query(api.items.pendingWork, {});
    expect(work.fills).toHaveLength(0);
    expect(work.rekeys).toHaveLength(1);

    await as("alice").mutation(api.items.rekey, {
      id,
      keyVersion: 1,
      metadata: sealed(7),
      secret: sealed(8),
      accesses: [{ userId: "alice", access: wrapped(20) }],
    });

    work = await as("alice").query(api.items.pendingWork, {});
    expect(work.fills).toHaveLength(1);
    expect(work.fills[0].item.keyVersion).toBe(2);
    expect(work.fills[0].recipients.map((r) => r.userId)).toEqual(["carol"]);
  });

  test("departman değişikliği eski departman paylaşımlarına erişimi kaldırır", async () => {
    const { as, ids, createItem, fill, accessUserIds, getItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.yazilim,
      granted: true,
    });
    await fill("alice", id, ["bob"]);

    await as("admin").mutation(api.members.update, { id: ids.bob, departmentId: ids.satis });

    expect(await accessUserIds(id)).toEqual(["alice"]);
    expect((await getItem(id))!.needsRekey).toBe(true);
    expect(await as("bob").query(api.items.pendingSharedCount, {})).toBe(0);
  });

  test("departmana katılan kişi departman paylaşımlarını bekler", async () => {
    const { as, ids, createItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.yazilim,
      granted: true,
    });

    await as("admin").mutation(api.members.update, { id: ids.carol, departmentId: ids.yazilim });

    expect(await as("carol").query(api.items.pendingSharedCount, {})).toBe(1);

    const work = await as("alice").query(api.items.pendingWork, {});
    expect(work.fills[0].recipients.map((r) => r.userId).sort()).toEqual(["bob", "carol"]);
  });

  test("devre dışı bırakılan kullanıcının erişimi silinir ve API'ye erişemez", async () => {
    const { as, ids, createItem, fill, accessUserIds, getItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: true });
    await fill("alice", id, ["bob"]);

    await as("admin").mutation(api.members.update, { id: ids.bob, enabled: false });

    expect(await accessUserIds(id)).toEqual(["alice"]);
    expect((await getItem(id))!.needsRekey).toBe(true);
    await expect(as("bob").query(api.items.listMine, {})).rejects.toThrow(/erişim yetkisi yok/);

    // Rekey anahtar listesinde devre dışı kullanıcı bulunamaz.
    const work = await as("alice").query(api.items.pendingWork, {});
    expect(work.rekeys[0].recipients).toEqual([]);
  });

  test("addAccesses: erişimi olmayan anahtar ekleyemez, kurala uymayan kişiye anahtar verilemez", async () => {
    const { as, createItem, fill } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: true });

    await expect(
      as("carol").mutation(api.items.addAccesses, {
        id,
        keyVersion: 1,
        accesses: [{ userId: "bob", access: wrapped(9) }],
      }),
    ).rejects.toThrow(/erişimin yok/);

    await expect(
      as("alice").mutation(api.items.addAccesses, {
        id,
        keyVersion: 1,
        accesses: [{ userId: "carol", access: wrapped(9) }],
      }),
    ).rejects.toThrow(/erişim vermiyor/);

    await expect(
      as("alice").mutation(api.items.addAccesses, {
        id,
        keyVersion: 99,
        accesses: [{ userId: "bob", access: wrapped(9) }],
      }),
    ).rejects.toThrow(/başka bir işlemle güncellendi/);

    // Erişimi olan alıcı da kurala uyan başka biri için anahtar üretebilir.
    await fill("alice", id, ["bob"]);
    await as("alice").mutation(api.items.setUserGrant, { id, userId: "carol", granted: true });
    await fill("bob", id, ["carol"]);

    expect(await as("carol").query(api.items.listMine, {})).toHaveLength(1);
  });

  test("açık anahtarı değişen kullanıcının eski erişimi silinir ve yeni anahtarla tamamlanır", async () => {
    const { as, createItem, fill, accessUserIds, getItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: true });
    await fill("alice", id, ["bob"]);

    await as("bob").mutation(api.users.setPublicKey, { publicKey: publicKey(9) });

    expect(await accessUserIds(id)).toEqual(["alice"]);
    // Kural değişmediği için rekey gerekmez; yalnızca yeni anahtara paket gerekir.
    expect((await getItem(id))!.needsRekey).toBe(false);

    const work = await as("alice").query(api.items.pendingWork, {});
    expect(work.fills[0].recipients).toEqual([{ userId: "bob", publicKey: publicKey(9) }]);
  });

  test("paylaşımı yalnızca sahip görür ve yönetir", async () => {
    const { as, ids, createItem, fill } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: "bob", granted: true });
    await fill("alice", id, ["bob"]);

    await expect(as("bob").query(api.items.sharing, { id })).rejects.toThrow(/sahibi değilsin/);
    await expect(
      as("bob").mutation(api.items.setUserGrant, { id, userId: "carol", granted: true }),
    ).rejects.toThrow(/sahibi değilsin/);
    await expect(
      as("admin").mutation(api.items.setDepartmentGrant, {
        id,
        departmentId: ids.satis,
        granted: true,
      }),
    ).rejects.toThrow(/sahibi değilsin/);
  });
});

describe("kullanıcı yönetimi", () => {
  test("departman yöneticisi yalnızca kendi departmanındaki personeli devre dışı bırakabilir", async () => {
    const { t, as, ids } = await setup();

    await as("manager").mutation(api.members.update, { id: ids.carol, enabled: false });
    expect((await t.run((ctx) => ctx.db.get(ids.carol)))!.status).toBe("disabled");

    await expect(
      as("manager").mutation(api.members.update, { id: ids.bob, enabled: false }),
    ).rejects.toThrow(/yönetme yetkin yok/);
  });

  test("departman yöneticisi rol ve departman değiştiremez", async () => {
    const { as, ids } = await setup();

    await expect(
      as("manager").mutation(api.members.update, { id: ids.carol, role: "manager" }),
    ).rejects.toThrow(/yalnızca yönetici/);

    await expect(
      as("manager").mutation(api.members.update, { id: ids.carol, departmentId: ids.yazilim }),
    ).rejects.toThrow(/yalnızca yönetici/);
  });

  test("departman yöneticisi yalnızca kendi departmanına personel davet edebilir", async () => {
    const { t, as, ids } = await setup();

    await expect(
      as("manager").mutation(internal.members.createInvited, {
        email: "x@vs.com",
        role: "admin",
      }),
    ).rejects.toThrow(/yalnızca kendi departmanına personel/);

    await expect(
      as("manager").mutation(internal.members.createInvited, {
        email: "x@vs.com",
        role: "member",
        departmentId: ids.yazilim,
      }),
    ).rejects.toThrow(/yalnızca kendi departmanına personel/);

    await as("manager").mutation(internal.members.createInvited, {
      email: "X@VS.com",
      role: "member",
      departmentId: ids.satis,
    });

    const invited = await t.run((ctx) =>
      ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", "x@vs.com"))
        .unique(),
    );
    expect(invited).toMatchObject({ status: "invited", role: "member" });
  });

  test("personel kullanıcı listesini göremez ve davet edemez", async () => {
    const { as, ids } = await setup();

    await expect(as("bob").query(api.members.list, {})).rejects.toThrow(/görme yetkin yok/);
    await expect(
      as("bob").mutation(internal.members.createInvited, {
        email: "y@vs.com",
        role: "member",
        departmentId: ids.yazilim,
      }),
    ).rejects.toThrow(/davet etme yetkin yok/);
  });

  test("yönetici kendi hesabını değiştiremez, departmanları yalnız yönetici oluşturur", async () => {
    const { as, ids } = await setup();

    await expect(
      as("admin").mutation(api.members.update, { id: ids.admin, enabled: false }),
    ).rejects.toThrow(/yönetme yetkin yok/);

    await expect(
      as("manager").mutation(api.departments.create, { name: "Destek" }),
    ).rejects.toThrow(/yalnızca yönetici/);
  });
});
