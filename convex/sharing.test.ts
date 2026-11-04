import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";

import { api } from "./_generated/api";
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
const verifier = (n: number) => n.toString(16).padStart(2, "0").repeat(32);

let itemCounter = 0;
const newItemId = () => `item-${(++itemCounter).toString(16).padStart(32, "0")}`;

type Name = "admin" | "alice" | "bob" | "carol" | "manager";

async function setup() {
  const t = convexTest(schema, modules);

  const ids = await t.run(async (ctx) => {
    const now = Date.now();
    const department = (name: string) =>
      ctx.db.insert("departments", { name, keyVersion: 0, needsRotation: false, createdAt: now });

    const yazilim = await department("Yazılım");
    const satis = await department("Satış");

    const user = (
      name: string,
      role: "admin" | "manager" | "member",
      departmentId: Id<"departments"> | undefined,
      key: number,
    ) =>
      ctx.db.insert("users", {
        email: `${name}@vs.com`,
        displayName: name,
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

  const userIds: Record<Name, Id<"users">> = {
    admin: ids.admin,
    alice: ids.alice,
    bob: ids.bob,
    carol: ids.carol,
    manager: ids.manager,
  };
  const uid = (name: Name) => userIds[name];
  const nameOf = (userId: Id<"users">) =>
    Object.entries(userIds).find(([, id]) => id === userId)?.[0] ?? userId;
  const names = (rows: { userId: Id<"users"> }[]) => rows.map((r) => nameOf(r.userId)).sort();

  // Convex Auth kimliği `userId|sessionId` biçimindedir.
  const asId = (userId: Id<"users">) => t.withIdentity({ subject: `${userId}|session` });
  const as = (name: Name) => asId(uid(name));

  /** Yöneticinin cihazının yapacağı gibi bekleyen departman anahtarı işlerini tamamlar. */
  async function runDepartmentWork(actor: Name = "admin") {
    const work = await as(actor).query(api.keys.pendingWork, {});

    for (const init of work.inits) {
      await as(actor).mutation(api.keys.initDepartmentKey, {
        departmentId: init.departmentId,
        publicKey: publicKey(90),
        accesses: init.holders.map((h) => ({ userId: h.userId, access: wrapped(30) })),
      });
    }

    for (const fill of work.fills) {
      await as(actor).mutation(api.keys.addDepartmentKeys, {
        departmentId: fill.departmentId,
        keyVersion: fill.keyVersion,
        accesses: fill.recipients.map((r) => ({ userId: r.userId, access: wrapped(31) })),
      });
    }

    for (const rotation of work.rotations) {
      await as(actor).mutation(api.keys.rotateDepartmentKey, {
        departmentId: rotation.departmentId,
        keyVersion: rotation.keyVersion,
        publicKey: publicKey(91),
        accesses: rotation.holders.map((h) => ({ userId: h.userId, access: wrapped(32) })),
        itemKeys: rotation.itemKeys.map((k) => ({ item: k.item, access: wrapped(33) })),
      });
    }

    return work;
  }

  /** Kaydın sahibinin cihazının yapacağı gibi eksik paketleri tamamlar. */
  async function runItemWork(actor: Name) {
    const work = await as(actor).query(api.items.pendingWork, {});

    for (const fill of work.fills) {
      await as(actor).mutation(api.items.addAccesses, {
        id: fill.item.id,
        keyVersion: fill.item.keyVersion,
        accesses: fill.recipients.map((r, i) => ({ userId: r.userId, access: wrapped(10 + i) })),
        departmentAccesses: fill.departments.map((d) => ({
          departmentId: d.departmentId,
          keyVersion: d.keyVersion,
          access: wrapped(20),
        })),
      });
    }

    return work;
  }

  async function createItem(owner: Name) {
    return await as(owner).mutation(api.items.create, {
      itemId: newItemId(),
      metadata: sealed(1),
      secret: sealed(2),
      ownerAccess: wrapped(1),
    });
  }

  async function shareWithDepartment(owner: Name, id: Id<"items">, departmentId: Id<"departments">) {
    await as(owner).mutation(api.items.setDepartmentGrant, { id, departmentId, granted: true });
    await runItemWork(owner);
  }

  async function shareWithUser(owner: Name, id: Id<"items">, userId: Id<"users">) {
    await as(owner).mutation(api.items.setUserGrant, { id, userId, granted: true });
    await runItemWork(owner);
  }

  const visible = async (userId: Id<"users">) =>
    (await asId(userId).query(api.items.listMine, {})).map((item) => item.id);

  const directAccessNames = (id: Id<"items">) =>
    t.run(async (ctx) =>
      names(
        await ctx.db
          .query("itemAccess")
          .withIndex("by_item", (q) => q.eq("item", id))
          .collect(),
      ),
    );

  const departmentKeyNames = (departmentId: Id<"departments">) =>
    t.run(async (ctx) =>
      names(
        await ctx.db
          .query("departmentKeys")
          .withIndex("by_department_and_user", (q) => q.eq("department", departmentId))
          .collect(),
      ),
    );

  const getItem = (id: Id<"items">) => t.run(async (ctx) => ctx.db.get(id));
  const getDepartment = (id: Id<"departments">) => t.run(async (ctx) => ctx.db.get(id));

  async function inviteUser(email: string, departmentId: Id<"departments">, key: number) {
    await as("admin").mutation(api.members.invite, {
      email,
      role: "member",
      departmentId,
      publicKey: publicKey(key),
      verifier: verifier(key),
      expiresInHours: 24,
    });

    return (await t.run((ctx) =>
      ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", email))
        .unique(),
    ))!._id;
  }

  // Kayıt akışı auth.test.ts'te test edilir; burada sonucu taklit edilir.
  const activate = (userId: Id<"users">) =>
    t.run((ctx) => ctx.db.patch(userId, { status: "active", inviteVerifierHash: undefined }));

  return {
    t,
    ids,
    uid,
    as,
    asId,
    runDepartmentWork,
    runItemWork,
    createItem,
    shareWithDepartment,
    shareWithUser,
    visible,
    directAccessNames,
    departmentKeyNames,
    getItem,
    getDepartment,
    inviteUser,
    activate,
  };
}

describe("departman anahtarları", () => {
  test("yeni departmanın anahtarını yönetici üretir; üyeler ve yöneticiler alır", async () => {
    const { as, ids, runDepartmentWork, departmentKeyNames, getDepartment } = await setup();

    expect((await as("alice").query(api.keys.pendingWork, {})).inits).toHaveLength(0);

    const work = await runDepartmentWork();
    expect(work.inits).toHaveLength(2);

    expect(await departmentKeyNames(ids.yazilim)).toEqual(["admin", "alice", "bob"]);
    expect(await departmentKeyNames(ids.satis)).toEqual(["admin", "carol", "manager"]);
    expect(await getDepartment(ids.yazilim)).toMatchObject({ keyVersion: 1, publicKey: publicKey(90) });

    expect(await runDepartmentWork()).toEqual({ inits: [], fills: [], rotations: [] });
  });

  test("ilk anahtar bütün sahipleri kapsamalı ve yalnız yönetici üretebilir", async () => {
    const { as, ids, uid } = await setup();

    await expect(
      as("admin").mutation(api.keys.initDepartmentKey, {
        departmentId: ids.yazilim,
        publicKey: publicKey(90),
        accesses: [{ userId: uid("admin"), access: wrapped(1) }],
      }),
    ).rejects.toThrow(/sahipleri değişti/);

    await expect(
      as("alice").mutation(api.keys.initDepartmentKey, {
        departmentId: ids.yazilim,
        publicKey: publicKey(90),
        accesses: [],
      }),
    ).rejects.toThrow(/yalnızca yönetici/);
  });

  test("departmana paylaşılan şifreyi üyeler departman anahtarıyla görür, diğerleri görmez", async () => {
    const { ids, uid, as, runDepartmentWork, createItem, shareWithDepartment, visible } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.yazilim);

    expect(await visible(uid("bob"))).toEqual([id]);
    expect(await visible(uid("carol"))).toEqual([]);
    // Yöneticiler bütün parolaları görür.
    expect(await visible(uid("admin"))).toEqual([id]);

    const [item] = await as("bob").query(api.items.listMine, {});
    expect(item.access).toEqual({
      kind: "department",
      departmentKey: wrapped(30),
      itemKey: wrapped(20),
    });
  });

  test("departmana sonradan katılan, şifre sahibi çevrimdışıyken de erişir", async () => {
    const { ids, uid, as, runDepartmentWork, createItem, shareWithDepartment, visible } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.yazilim);

    await as("admin").mutation(api.members.update, { id: uid("carol"), departmentId: ids.yazilim });
    expect(await visible(uid("carol"))).toEqual([]);
    expect(await as("carol").query(api.items.pendingSharedCount, {})).toBe(1);

    // Alice hiçbir şey yapmaz; değişikliği yapan yöneticinin cihazı yeter.
    const work = await runDepartmentWork();
    expect(work.fills.map((f) => f.recipients.map((r) => r.userId))).toEqual([[uid("carol")]]);

    expect(await visible(uid("carol"))).toEqual([id]);
    expect(await as("carol").query(api.items.pendingSharedCount, {})).toBe(0);
  });

  test("davet edilen kullanıcı gece kaydolduğunda departman şifrelerini hemen görür", async () => {
    const { ids, runDepartmentWork, createItem, shareWithDepartment, visible, inviteUser, activate } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.yazilim);

    const dave = await inviteUser("dave@vs.com", ids.yazilim, 40);
    // Davet anında yöneticinin cihazı departman anahtarını geçici anahtara paketler.
    await runDepartmentWork();

    await activate(dave);
    expect(await visible(dave)).toEqual([id]);
  });

  test("henüz kaydolmamış kişiye tek bir şifre doğrudan paylaşılabilir", async () => {
    const { ids, as, createItem, shareWithUser, visible, inviteUser, activate, directAccessNames } =
      await setup();

    const vendor = await inviteUser("vendor@dis.com", ids.satis, 41);
    const id = await createItem("alice");

    const sharing = await as("alice").query(api.items.sharing, { id });
    expect(sharing.users.find((u) => u.userId === vendor)).toMatchObject({ status: "invited" });

    await shareWithUser("alice", id, vendor);
    // Sahip, yönetici ve davetli.
    expect(await directAccessNames(id)).toHaveLength(3);

    // Gece kaydolur; kimsenin çevrimiçi olması gerekmez.
    await activate(vendor);
    expect(await visible(vendor)).toEqual([id]);
  });

  test("departmandan çıkan üye için anahtar yenilenir ve şifreler yeniden şifrelenir", async () => {
    const {
      ids, uid, as, runDepartmentWork, createItem, shareWithDepartment, visible,
      departmentKeyNames, getDepartment, getItem,
    } = await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.yazilim);

    await as("admin").mutation(api.members.update, { id: uid("bob"), departmentId: ids.satis });

    expect(await visible(uid("bob"))).toEqual([]);
    expect(await departmentKeyNames(ids.yazilim)).toEqual(["admin", "alice"]);
    expect(await getDepartment(ids.yazilim)).toMatchObject({ needsRotation: true });
    expect((await getItem(id))!.needsRekey).toBe(true);

    const work = await runDepartmentWork();
    expect(work.rotations).toHaveLength(1);
    expect(work.rotations[0].itemKeys.map((k) => k.item)).toEqual([id]);

    expect(await getDepartment(ids.yazilim)).toMatchObject({
      keyVersion: 2,
      needsRotation: false,
      publicKey: publicKey(91),
    });
    expect(await departmentKeyNames(ids.yazilim)).toEqual(["admin", "alice"]);
    // Bob satış departmanının anahtarını da alır.
    expect(await departmentKeyNames(ids.satis)).toEqual(["admin", "bob", "carol", "manager"]);
    expect(await visible(uid("alice"))).toEqual([id]);
  });

  test("anahtar yenilemesi eksik sahip ya da eksik kayıtla kabul edilmez", async () => {
    const { ids, uid, as, runDepartmentWork, createItem, shareWithDepartment } = await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.yazilim);
    await as("admin").mutation(api.members.update, { id: uid("bob"), departmentId: ids.satis });

    const base = {
      departmentId: ids.yazilim,
      keyVersion: 1,
      publicKey: publicKey(91),
      accesses: [
        { userId: uid("admin"), access: wrapped(1) },
        { userId: uid("alice"), access: wrapped(1) },
      ],
      itemKeys: [{ item: id, access: wrapped(1) }],
    };

    await expect(
      as("admin").mutation(api.keys.rotateDepartmentKey, { ...base, accesses: base.accesses.slice(1) }),
    ).rejects.toThrow(/sahipleri değişti/);

    await expect(
      as("admin").mutation(api.keys.rotateDepartmentKey, { ...base, itemKeys: [] }),
    ).rejects.toThrow(/kayıtları değişti/);

    await expect(as("bob").mutation(api.keys.rotateDepartmentKey, base)).rejects.toThrow(
      /anahtarına sahip değilsin/,
    );

    await as("admin").mutation(api.keys.rotateDepartmentKey, base);
  });

  test("devre dışı bırakılan yöneticinin bütün departman anahtarları yenilenir", async () => {
    const { t, ids, as, runDepartmentWork, getDepartment } = await setup();
    await runDepartmentWork();

    const second = await t.run((ctx) =>
      ctx.db.insert("users", {
        email: "admin2@vs.com",
        publicKey: publicKey(6),
        role: "admin",
        status: "active",
        createdAt: 0,
        updatedAt: 0,
      }),
    );
    await runDepartmentWork();

    await as("admin").mutation(api.members.update, { id: second, enabled: false });

    expect((await getDepartment(ids.yazilim))!.needsRotation).toBe(true);
    expect((await getDepartment(ids.satis))!.needsRotation).toBe(true);
  });

  test("bütün sahipler anahtarını kaybederse yönetici yeni anahtar üretir ve paylaşım tamamlanır", async () => {
    const { ids, uid, as, runDepartmentWork, runItemWork, createItem, visible, departmentKeyNames, getDepartment } =
      await setup();
    await runDepartmentWork();

    // Satış'ın bütün anahtar sahipleri kasasını sıfırlar (yeni kimlik).
    await as("admin").mutation(api.users.setPublicKey, { publicKey: publicKey(41) });
    await as("carol").mutation(api.users.setPublicKey, { publicKey: publicKey(44) });
    await as("manager").mutation(api.users.setPublicKey, { publicKey: publicKey(45) });
    expect(await departmentKeyNames(ids.satis)).toEqual([]);

    const id = await createItem("alice");
    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.satis,
      granted: true,
    });
    await runItemWork("alice");

    // Kimse açamadığı için yönetici departman anahtarını yeniden üretir.
    const work = await runDepartmentWork();
    expect(work.inits.map((init) => init.departmentId)).toEqual([ids.satis]);
    expect(await departmentKeyNames(ids.satis)).toEqual(["admin", "carol", "manager"]);
    expect((await getDepartment(ids.satis))!.keyVersion).toBe(2);

    // Eski anahtara paketli DEK geçersiz; sahibin cihazı yeni anahtara paketler.
    expect((await runItemWork("alice")).fills).toHaveLength(1);
    expect(await visible(uid("carol"))).toEqual([id]);
    expect(await as("carol").query(api.items.pendingSharedCount, {})).toBe(0);

    expect(await runDepartmentWork()).toEqual({ inits: [], fills: [], rotations: [] });
    await expect(
      as("admin").mutation(api.keys.initDepartmentKey, {
        departmentId: ids.satis,
        publicKey: publicKey(92),
        accesses: [],
      }),
    ).rejects.toThrow(/zaten oluşturulmuş/);
  });
});

describe("kişiye paylaşım ve rekey", () => {
  test("kişi paylaşımı kaldırılınca erişim silinir ve rekey zorunlu olur", async () => {
    const { uid, as, createItem, shareWithUser, visible, directAccessNames, getItem } = await setup();
    const id = await createItem("alice");

    await shareWithUser("alice", id, uid("carol"));
    expect(await visible(uid("carol"))).toEqual([id]);

    await as("alice").mutation(api.items.setUserGrant, { id, userId: uid("carol"), granted: false });

    expect(await visible(uid("carol"))).toEqual([]);
    expect(await directAccessNames(id)).toEqual(["admin", "alice"]);
    expect((await getItem(id))!.needsRekey).toBe(true);
  });

  test("rekey kuralları: yalnız sahip, güncel sürüm, yalnız yetkililer, departmanlar dahil", async () => {
    const { ids, uid, as, runDepartmentWork, createItem, shareWithUser, shareWithDepartment, getItem } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.yazilim);
    await shareWithUser("alice", id, uid("carol"));
    await as("alice").mutation(api.items.setUserGrant, { id, userId: uid("carol"), granted: false });

    const task = (await as("alice").query(api.items.pendingWork, {})).rekeys[0];
    expect(task.recipients.map((r) => r.userId)).toEqual([uid("admin")]);
    expect(task.departments).toEqual([
      { departmentId: ids.yazilim, keyVersion: 1, publicKey: publicKey(90) },
    ]);

    const valid = {
      id,
      keyVersion: 1,
      metadata: sealed(7),
      secret: sealed(8),
      accesses: [{ userId: uid("alice"), access: wrapped(20) }],
      departmentAccesses: [{ departmentId: ids.yazilim, keyVersion: 1, access: wrapped(21) }],
    };

    await expect(as("bob").mutation(api.items.rekey, valid)).rejects.toThrow(/sahibi değilsin/);
    await expect(
      as("alice").mutation(api.items.rekey, { ...valid, keyVersion: 0 }),
    ).rejects.toThrow(/başka bir işlemle güncellendi/);
    await expect(
      as("alice").mutation(api.items.rekey, {
        ...valid,
        accesses: [...valid.accesses, { userId: uid("carol"), access: wrapped(22) }],
      }),
    ).rejects.toThrow(/erişim vermiyor/);
    await expect(
      as("alice").mutation(api.items.rekey, { ...valid, accesses: [] }),
    ).rejects.toThrow(/sahibinin erişimi kaldırılamaz/);
    await expect(
      as("alice").mutation(api.items.rekey, { ...valid, departmentAccesses: [] }),
    ).rejects.toThrow(/departmanın anahtarı eksik/);
    await expect(
      as("alice").mutation(api.items.rekey, {
        ...valid,
        departmentAccesses: [{ departmentId: ids.satis, keyVersion: 1, access: wrapped(23) }],
      }),
    ).rejects.toThrow(/bu departmana erişim vermiyor/);

    await as("alice").mutation(api.items.rekey, valid);

    expect(await getItem(id)).toMatchObject({ keyVersion: 2, needsRekey: false, metadata: sealed(7) });
    expect((await as("alice").query(api.items.pendingWork, {})).rekeys).toHaveLength(0);
  });

  test("düzenleme: yalnız sahip, yeni DEK tüm alıcılara paketlenir", async () => {
    const { ids, uid, as, runDepartmentWork, createItem, shareWithUser, shareWithDepartment, getItem, visible } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithUser("alice", id, uid("carol"));
    await shareWithDepartment("alice", id, ids.yazilim);

    await expect(as("carol").query(api.items.editTargets, { id })).rejects.toThrow(
      /sahibi değilsin/,
    );

    const targets = await as("alice").query(api.items.editTargets, { id });
    expect(targets.item.access.kind).toBe("direct");
    expect(targets.recipients.map((r) => r.userId).sort()).toEqual([uid("admin"), uid("carol")].sort());
    expect(targets.departments.map((d) => d.departmentId)).toEqual([ids.yazilim]);

    await as("alice").mutation(api.items.rekey, {
      id,
      keyVersion: targets.item.keyVersion,
      metadata: sealed(7),
      secret: sealed(8),
      accesses: [
        { userId: uid("alice"), access: wrapped(40) },
        { userId: uid("carol"), access: wrapped(41) },
      ],
      departmentAccesses: targets.departments.map((d) => ({
        departmentId: d.departmentId,
        keyVersion: d.keyVersion,
        access: wrapped(42),
      })),
    });

    expect(await getItem(id)).toMatchObject({ keyVersion: 2, metadata: sealed(7), secret: sealed(8) });
    expect(await visible(uid("carol"))).toEqual([id]);
    expect(await visible(uid("bob"))).toEqual([id]);
  });

  test("silme: yalnız sahip; kayıt, paketler ve paylaşım kuralları silinir", async () => {
    const { t, ids, uid, as, runDepartmentWork, createItem, shareWithUser, shareWithDepartment, visible } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithUser("alice", id, uid("carol"));
    await shareWithDepartment("alice", id, ids.yazilim);

    await expect(as("carol").mutation(api.items.remove, { id })).rejects.toThrow(/sahibi değilsin/);

    await as("alice").mutation(api.items.remove, { id });

    expect(await visible(uid("alice"))).toEqual([]);
    expect(await visible(uid("carol"))).toEqual([]);
    expect(await visible(uid("bob"))).toEqual([]);

    const leftovers = await t.run(async (ctx) =>
      Promise.all(
        (["itemAccess", "itemDepartmentAccess", "itemGrants"] as const).map(
          async (table) => (await ctx.db.query(table).collect()).length,
        ),
      ),
    );
    expect(leftovers).toEqual([0, 0, 0]);
  });

  test("listede paylaşım kuralları yalnız sahibe gelir; dizin kişileri ve departmanları verir", async () => {
    const { ids, uid, as, createItem, shareWithUser } = await setup();
    const id = await createItem("alice");
    await shareWithUser("alice", id, uid("carol"));
    await as("alice").mutation(api.items.setDepartmentGrant, {
      id,
      departmentId: ids.satis,
      granted: true,
    });

    const [own] = await as("alice").query(api.items.listMine, {});
    expect(own.grants).toEqual({ userIds: [uid("carol")], departmentIds: [ids.satis] });

    const [shared] = await as("carol").query(api.items.listMine, {});
    expect(shared.grants).toBeNull();

    const directory = await as("alice").query(api.items.shareDirectory, {});
    expect(directory.departments.map((d) => d.id).sort()).toEqual([ids.satis, ids.yazilim].sort());
    expect(directory.users.map((u) => u.userId)).not.toContain(uid("alice"));
  });

  test("aynı kayıt kimliği tekrar gönderilirse mevcut kayıt döner", async () => {
    const { as } = await setup();
    const payload = {
      itemId: newItemId(),
      metadata: sealed(1),
      secret: sealed(2),
      ownerAccess: wrapped(1),
    };

    const first = await as("alice").mutation(api.items.create, payload);
    expect(await as("alice").mutation(api.items.create, payload)).toBe(first);
    await expect(as("bob").mutation(api.items.create, payload)).rejects.toThrow(/zaten kullanılıyor/);
  });

  test("parola geçmişi rekey ile saklanır, erişimi olanlara gelir ve kaybedilemez", async () => {
    const { t, ids, uid, as, runDepartmentWork, runItemWork, createItem, shareWithDepartment, getItem } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithDepartment("alice", id, ids.satis);

    const rekey = async (history: { id?: Id<"itemHistory">; entry: ReturnType<typeof sealed> }[]) =>
      as("alice").mutation(api.items.rekey, {
        id,
        keyVersion: (await getItem(id))!.keyVersion,
        metadata: sealed(5),
        secret: sealed(6),
        history,
        accesses: [{ userId: uid("alice"), access: wrapped(7) }],
        departmentAccesses: [{ departmentId: ids.satis, keyVersion: 1, access: wrapped(8) }],
      });
    const records = async (name: "alice" | "carol" | "admin" | "bob") =>
      (await as(name).query(api.items.history, { id })).history;

    // Sınır yok: her düzenleme bir kayıt ekler.
    for (let n = 1; n <= 25; n++) {
      const existing = await records("alice");
      await rekey([...existing.map((r) => ({ id: r.id, entry: sealed(n) })), { entry: sealed(n) }]);
    }

    // Departman üyesi (carol) ve yönetici geçmişi görür; erişimi olmayan (bob) göremez.
    const carolView = await as("carol").query(api.items.history, { id });
    expect(carolView.item.access.kind).toBe("department");
    expect(carolView.history).toHaveLength(25);
    // Rekey'de yöneticinin paketi eksik kaldı; sahibin cihazı tamamlar.
    await runItemWork("alice");
    expect(await records("admin")).toHaveLength(25);
    await expect(records("bob")).rejects.toThrow(/erişimin yok/);

    // Geçmiş silinemez, yerine başka kayıt konamaz, iki yeni kayıt eklenemez.
    const existing = await records("alice");
    await expect(rekey([])).rejects.toThrow(/geçmişi eksik/);
    await expect(rekey(existing.slice(1))).rejects.toThrow(/geçmişi eksik/);
    await expect(rekey([...existing, existing[0]])).rejects.toThrow(/geçmişi değişti/);
    await expect(rekey([...existing, { entry: sealed(1) }, { entry: sealed(2) }])).rejects.toThrow(
      /geçmişi eksik/,
    );
    await expect(
      as("alice").mutation(api.items.rekey, {
        id,
        keyVersion: (await getItem(id))!.keyVersion,
        metadata: sealed(5),
        secret: sealed(6),
        accesses: [{ userId: uid("alice"), access: wrapped(7) }],
        departmentAccesses: [{ departmentId: ids.satis, keyVersion: 1, access: wrapped(8) }],
      }),
    ).rejects.toThrow(/geçmişi eksik/);

    // Kayıt silinince geçmişi de silinir.
    await as("alice").mutation(api.items.remove, { id });
    expect(await t.run((ctx) => ctx.db.query("itemHistory").collect())).toEqual([]);
  });

  test("yöneticiler paylaşılmamış parolaları da görür; yöneticilik kalkınca erişim gider", async () => {
    const { t, ids, as, asId, createItem, runItemWork, visible, directAccessNames, getItem } =
      await setup();

    const second = await t.run((ctx) =>
      ctx.db.insert("users", {
        email: "admin2@vs.com",
        publicKey: publicKey(6),
        role: "admin",
        status: "active",
        createdAt: 0,
        updatedAt: 0,
      }),
    );

    const id = await createItem("alice");

    // Anahtar sahibin cihazında üretilene kadar "hazırlanıyor" sayılır.
    expect(await asId(second).query(api.items.pendingSharedCount, {})).toBe(1);

    await runItemWork("alice");
    expect(await directAccessNames(id)).toEqual(expect.arrayContaining(["admin", "alice", second]));
    expect(await visible(second)).toEqual([id]);
    expect(await asId(second).query(api.items.pendingSharedCount, {})).toBe(0);
    expect(
      (await as("alice").query(api.items.sharing, { id })).users.find((u) => u.userId === second),
    ).toMatchObject({ isAdmin: true, hasKey: true, direct: false });

    await as("admin").mutation(api.members.update, {
      id: second,
      role: "member",
      departmentId: ids.satis,
    });

    expect(await visible(second)).toEqual([]);
    expect((await getItem(id))!.needsRekey).toBe(true);
  });

  test("rekey beklerken eski anahtar dağıtılmaz", async () => {
    const { uid, as, createItem, shareWithUser } = await setup();
    const id = await createItem("alice");

    await shareWithUser("alice", id, uid("bob"));
    await as("alice").mutation(api.items.setUserGrant, { id, userId: uid("carol"), granted: true });
    await as("alice").mutation(api.items.setUserGrant, { id, userId: uid("bob"), granted: false });

    const work = await as("alice").query(api.items.pendingWork, {});
    expect(work.fills).toHaveLength(0);
    expect(work.rekeys).toHaveLength(1);
  });

  test("addAccesses: erişimi olmayan anahtar ekleyemez, kurala uymayana anahtar verilemez", async () => {
    const { ids, uid, as, createItem } = await setup();
    const id = await createItem("alice");

    await as("alice").mutation(api.items.setUserGrant, { id, userId: uid("bob"), granted: true });

    const entry = (userId: Id<"users">) => ({
      id,
      keyVersion: 1,
      accesses: [{ userId, access: wrapped(9) }],
      departmentAccesses: [],
    });

    await expect(as("carol").mutation(api.items.addAccesses, entry(uid("bob")))).rejects.toThrow(
      /erişimin yok/,
    );
    await expect(as("alice").mutation(api.items.addAccesses, entry(uid("carol")))).rejects.toThrow(
      /erişim vermiyor/,
    );
    await expect(
      as("alice").mutation(api.items.addAccesses, { ...entry(uid("bob")), keyVersion: 99 }),
    ).rejects.toThrow(/başka bir işlemle güncellendi/);
    await expect(
      as("alice").mutation(api.items.addAccesses, {
        id,
        keyVersion: 1,
        accesses: [],
        departmentAccesses: [{ departmentId: ids.yazilim, keyVersion: 0, access: wrapped(9) }],
      }),
    ).rejects.toThrow(/bu departmana erişim vermiyor/);
  });

  test("devre dışı bırakılan kullanıcının erişimi silinir ve API'ye erişemez", async () => {
    const { ids, uid, as, runDepartmentWork, createItem, shareWithUser, directAccessNames, departmentKeyNames } =
      await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithUser("alice", id, uid("carol"));

    await as("admin").mutation(api.members.update, { id: uid("carol"), enabled: false });

    expect(await directAccessNames(id)).toEqual(["admin", "alice"]);
    expect(await departmentKeyNames(ids.satis)).toEqual(["admin", "manager"]);
    await expect(as("carol").query(api.items.listMine, {})).rejects.toThrow(/erişim yetkisi yok/);
  });

  test("açık anahtarı değişen kullanıcının eski paketleri silinir ve yeniden doldurulur", async () => {
    const {
      ids, uid, as, runDepartmentWork, runItemWork, createItem, shareWithUser,
      directAccessNames, departmentKeyNames,
    } = await setup();
    await runDepartmentWork();

    const id = await createItem("alice");
    await shareWithUser("alice", id, uid("carol"));

    await as("carol").mutation(api.users.setPublicKey, { publicKey: publicKey(9) });

    expect(await directAccessNames(id)).toEqual(["admin", "alice"]);
    expect(await departmentKeyNames(ids.satis)).toEqual(["admin", "manager"]);

    await runItemWork("alice");
    await runDepartmentWork();

    expect(await directAccessNames(id)).toEqual(["admin", "alice", "carol"]);
    expect(await departmentKeyNames(ids.satis)).toEqual(["admin", "carol", "manager"]);
  });

  test("paylaşımı yalnızca sahip görür ve yönetir", async () => {
    const { ids, uid, as, createItem, shareWithUser } = await setup();
    const id = await createItem("alice");

    await shareWithUser("alice", id, uid("bob"));

    await expect(as("bob").query(api.items.sharing, { id })).rejects.toThrow(/sahibi değilsin/);
    await expect(
      as("bob").mutation(api.items.setUserGrant, { id, userId: uid("carol"), granted: true }),
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

describe("davetten kalıcı anahtara geçiş", () => {
  test("kullanıcı geçici anahtarına paketlenen her şeyi kalıcı anahtarına taşır", async () => {
    const { t, ids, asId, runDepartmentWork, createItem, shareWithUser, inviteUser, activate } =
      await setup();
    await runDepartmentWork();

    const vendor = await inviteUser("vendor@dis.com", ids.satis, 41);
    await runDepartmentWork();
    const id = await createItem("alice");
    await shareWithUser("alice", id, vendor);
    await activate(vendor);

    const keys = await asId(vendor).query(api.users.myWrappedKeys, {});
    expect(keys.publicKey).toBe(publicKey(41));
    expect(keys.itemAccesses).toHaveLength(1);
    expect(keys.departmentKeys).toHaveLength(1);

    const rotation = {
      fromPublicKey: publicKey(41),
      publicKey: publicKey(42),
      itemAccesses: keys.itemAccesses.map((k) => ({ id: k.id, access: wrapped(50) })),
      departmentKeys: keys.departmentKeys.map((k) => ({ id: k.id, access: wrapped(51) })),
    };

    await expect(
      asId(vendor).mutation(api.users.rotateKey, { ...rotation, fromPublicKey: publicKey(9) }),
    ).rejects.toThrow(/açık anahtarı değişmiş/);
    await expect(
      asId(vendor).mutation(api.users.rotateKey, { ...rotation, itemAccesses: [] }),
    ).rejects.toThrow(/Anahtarların değişti/);

    await asId(vendor).mutation(api.users.rotateKey, rotation);

    const after = await t.run(async (ctx) => ({
      user: await ctx.db.get(vendor),
      access: await ctx.db.get(keys.itemAccesses[0].id),
    }));
    expect(after.user!.publicKey).toBe(publicKey(42));
    expect(after.access!.access).toEqual(wrapped(50));
  });

  test("davet yenilenince eski geçici anahtara ait paketler silinir ve yeniden doldurulur", async () => {
    const { t, ids, as, runDepartmentWork, runItemWork, createItem, shareWithUser, inviteUser } =
      await setup();
    await runDepartmentWork();

    const vendor = await inviteUser("vendor@dis.com", ids.satis, 41);
    await runDepartmentWork();
    const id = await createItem("alice");
    await shareWithUser("alice", id, vendor);

    await as("admin").mutation(api.members.renewInvite, {
      id: vendor,
      publicKey: publicKey(43),
      verifier: verifier(43),
      expiresInHours: 72,
    });

    const count = () =>
      t.run(async (ctx) => ({
        items: (
          await ctx.db
            .query("itemAccess")
            .withIndex("by_user", (q) => q.eq("userId", vendor))
            .collect()
        ).length,
        departments: (
          await ctx.db
            .query("departmentKeys")
            .withIndex("by_user", (q) => q.eq("userId", vendor))
            .collect()
        ).length,
      }));

    expect(await count()).toEqual({ items: 0, departments: 0 });

    await runDepartmentWork();
    await runItemWork("alice");

    expect(await count()).toEqual({ items: 1, departments: 1 });
  });
});

describe("kullanıcı yönetimi", () => {
  const invite = (
    email: string,
    role: "admin" | "manager" | "member",
    departmentId?: Id<"departments">,
  ) => ({
    email,
    role,
    departmentId,
    publicKey: publicKey(60),
    verifier: verifier(60),
    expiresInHours: 168,
  });

  test("departman yöneticisi yalnızca kendi departmanındaki personeli devre dışı bırakabilir", async () => {
    const { t, ids, as } = await setup();

    await as("manager").mutation(api.members.update, { id: ids.carol, enabled: false });
    expect((await t.run((ctx) => ctx.db.get(ids.carol)))!.status).toBe("disabled");

    await expect(
      as("manager").mutation(api.members.update, { id: ids.bob, enabled: false }),
    ).rejects.toThrow(/yönetme yetkin yok/);
  });

  test("departman yöneticisi rol ve departman değiştiremez", async () => {
    const { ids, as } = await setup();

    await expect(
      as("manager").mutation(api.members.update, { id: ids.carol, role: "manager" }),
    ).rejects.toThrow(/yalnızca yönetici/);

    await expect(
      as("manager").mutation(api.members.update, { id: ids.carol, departmentId: ids.yazilim }),
    ).rejects.toThrow(/yalnızca yönetici/);
  });

  test("departman yöneticisi yalnızca kendi departmanına personel davet edebilir", async () => {
    const { t, ids, as } = await setup();

    await expect(
      as("manager").mutation(api.members.invite, invite("x@vs.com", "admin")),
    ).rejects.toThrow(/yalnızca kendi departmanına personel/);

    await expect(
      as("manager").mutation(api.members.invite, invite("x@vs.com", "member", ids.yazilim)),
    ).rejects.toThrow(/yalnızca kendi departmanına personel/);

    await as("manager").mutation(api.members.invite, invite("X@VS.com", "member", ids.satis));

    const invited = await t.run((ctx) =>
      ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", "x@vs.com"))
        .unique(),
    );
    expect(invited).toMatchObject({ status: "invited", role: "member", publicKey: publicKey(60) });
    expect(invited!.inviteVerifierHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("davet süresi yalnızca izin verilen seçeneklerden olabilir", async () => {
    const { ids, as } = await setup();

    await expect(
      as("admin").mutation(api.members.invite, {
        ...invite("y@vs.com", "member", ids.satis),
        expiresInHours: 1000,
      }),
    ).rejects.toThrow(/Geçersiz davet süresi/);
  });

  test("personel kullanıcı listesini göremez ve davet edemez", async () => {
    const { ids, as } = await setup();

    await expect(as("bob").query(api.members.list, {})).rejects.toThrow(/görme yetkin yok/);
    await expect(
      as("bob").mutation(api.members.invite, invite("y@vs.com", "member", ids.yazilim)),
    ).rejects.toThrow(/davet etme yetkin yok/);
  });

  test("yönetici kendi hesabını değiştiremez, departmanları yalnız yönetici oluşturur", async () => {
    const { ids, as } = await setup();

    await expect(
      as("admin").mutation(api.members.update, { id: ids.admin, enabled: false }),
    ).rejects.toThrow(/yönetme yetkin yok/);

    await expect(
      as("manager").mutation(api.departments.create, { name: "Destek" }),
    ).rejects.toThrow(/yalnızca yönetici/);
  });
});
