import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";

import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import schema from "./schema";
import { modules } from "./test.setup";

const b64 = (bytes: number, fill: number) =>
  btoa(String.fromCharCode(...new Array<number>(bytes).fill(fill)));
const sealed = (n: number) => ({ nonce: b64(12, n), ciphertext: b64(40, n) });
const wrapped = (n: number) => ({ ephemeralPublicKey: b64(32, n), nonce: b64(12, n), ciphertext: b64(48, n) });

let counter = 0;

async function setup() {
  const t = convexTest(schema, modules);

  const ids = await t.run(async (ctx) => {
    const department = await ctx.db.insert("departments", {
      name: "Yazılım",
      keyVersion: 0,
      needsRotation: false,
      createdAt: 0,
    });
    const user = (name: string, role: "admin" | "member", key: number) =>
      ctx.db.insert("users", {
        email: `${name}@vs.com`,
        displayName: name,
        publicKey: b64(32, key),
        role,
        departmentId: role === "admin" ? undefined : department,
        status: "active",
        createdAt: 0,
        updatedAt: 0,
      });

    return {
      admin: await user("admin", "admin", 1),
      alice: await user("alice", "member", 2),
      bob: await user("bob", "member", 3),
      carol: await user("carol", "member", 4),
    };
  });

  type Name = keyof typeof ids;
  const as = (name: Name) => t.withIdentity({ subject: `${ids[name]}|session` });

  const createItem = (owner: Name, folderId?: Id<"folders">) =>
    as(owner).mutation(api.items.create, {
      itemId: `item-${(++counter).toString(16).padStart(32, "0")}`,
      metadata: sealed(1),
      secret: sealed(2),
      ownerAccess: wrapped(1),
      folderId,
    });

  const giveAccess = (itemId: Id<"items">, name: Name) =>
    t.run((ctx) => ctx.db.insert("itemAccess", { item: itemId, userId: ids[name], access: wrapped(5) }));

  const folderNames = async (name: Name) =>
    (await as(name).query(api.folders.list, {})).map((folder) => folder.name).sort();

  return { t, ids, as, createItem, giveAccess, folderNames };
}

describe("klasörler", () => {
  test("alt klasör oluşturulur, kardeş klasörlerde aynı ad olamaz", async () => {
    const { as } = await setup();

    const root = await as("alice").mutation(api.folders.create, { name: " Sunucular " });
    const child = await as("alice").mutation(api.folders.create, { name: "Prod", parentId: root });
    await as("alice").mutation(api.folders.create, { name: "Prod" });

    await expect(
      as("alice").mutation(api.folders.create, { name: "prod", parentId: root }),
    ).rejects.toThrow(/aynı isimde/);
    await expect(as("alice").mutation(api.folders.create, { name: "  " })).rejects.toThrow(
      /1-100 karakter/,
    );

    const list = await as("alice").query(api.folders.list, {});
    expect(list.find((folder) => folder.id === child)).toMatchObject({
      name: "Prod",
      parentId: root,
      isOwner: true,
      canManage: true,
    });
    expect(list.find((folder) => folder.id === root)?.name).toBe("Sunucular");
  });

  test("klasörü sahibi, içinde açabildiği parola olan ve yönetici görür", async () => {
    const { as, createItem, giveAccess, folderNames } = await setup();

    const root = await as("alice").mutation(api.folders.create, { name: "Ortak" });
    const child = await as("alice").mutation(api.folders.create, { name: "Alt", parentId: root });
    await as("alice").mutation(api.folders.create, { name: "Gizli" });

    const item = await createItem("alice", child);
    await giveAccess(item, "bob");

    expect(await folderNames("alice")).toEqual(["Alt", "Gizli", "Ortak"]);
    // Bob yalnızca parolanın yolundaki klasörleri görür, yönetemez.
    expect(await folderNames("bob")).toEqual(["Alt", "Ortak"]);
    expect((await as("bob").query(api.folders.list, {})).every((f) => !f.canManage)).toBe(true);
    expect(await folderNames("carol")).toEqual([]);
    expect(await folderNames("admin")).toEqual(["Alt", "Gizli", "Ortak"]);

    // Bob, Alice'in klasörüne ekleme yapamaz, adını değiştiremez.
    await expect(
      as("bob").mutation(api.folders.create, { name: "X", parentId: root }),
    ).rejects.toThrow(/yönetme yetkin yok/);
    await expect(createItem("bob", root)).rejects.toThrow(/ekleme yetkin yok/);
    await expect(as("bob").mutation(api.folders.rename, { id: root, name: "Y" })).rejects.toThrow(
      /yönetme yetkin yok/,
    );
    await as("admin").mutation(api.folders.rename, { id: root, name: "Ortak Alan" });
    expect(await folderNames("bob")).toEqual(["Alt", "Ortak Alan"]);
  });

  test("klasör taşınır; kendi altına taşınamaz", async () => {
    const { as } = await setup();

    const a = await as("alice").mutation(api.folders.create, { name: "A" });
    const b = await as("alice").mutation(api.folders.create, { name: "B", parentId: a });
    const c = await as("alice").mutation(api.folders.create, { name: "C" });

    await expect(as("alice").mutation(api.folders.move, { id: a, parentId: b })).rejects.toThrow(
      /kendi içine/,
    );
    await expect(as("alice").mutation(api.folders.move, { id: a, parentId: a })).rejects.toThrow(
      /kendi içine/,
    );

    await as("alice").mutation(api.folders.move, { id: a, parentId: c });
    await as("alice").mutation(api.folders.move, { id: b, parentId: null });

    const list = await as("alice").query(api.folders.list, {});
    expect(list.find((f) => f.id === a)?.parentId).toBe(c);
    expect(list.find((f) => f.id === b)?.parentId).toBeNull();
  });

  test("klasör silinince içindekiler bir üst klasöre taşınır", async () => {
    const { t, as, createItem } = await setup();

    const root = await as("alice").mutation(api.folders.create, { name: "Kök" });
    const doomed = await as("alice").mutation(api.folders.create, { name: "Silinecek", parentId: root });
    await as("alice").mutation(api.folders.create, { name: "Alt", parentId: root });
    const child = await as("alice").mutation(api.folders.create, { name: "Alt", parentId: doomed });
    const item = await createItem("alice", doomed);

    await as("alice").mutation(api.folders.remove, { id: doomed });

    const list = await as("alice").query(api.folders.list, {});
    expect(list.find((f) => f.id === child)).toMatchObject({ name: "Alt (2)", parentId: root });
    expect((await t.run((ctx) => ctx.db.get(item)))!.folderId).toBe(root);

    await as("alice").mutation(api.folders.remove, { id: root });
    expect((await t.run((ctx) => ctx.db.get(item)))!.folderId).toBeUndefined();
  });

  test("parola klasöre taşınır; silinmiş klasöre eklenen kayıt köke düşer", async () => {
    const { t, as, createItem } = await setup();

    const folder = await as("alice").mutation(api.folders.create, { name: "VPN" });
    const item = await createItem("alice");

    await expect(as("bob").mutation(api.items.move, { id: item, folderId: null })).rejects.toThrow(
      /taşıma yetkin yok/,
    );
    const bobFolder = await as("bob").mutation(api.folders.create, { name: "Bob" });
    await expect(
      as("alice").mutation(api.items.move, { id: item, folderId: bobFolder }),
    ).rejects.toThrow(/yönetme yetkin yok/);

    await as("alice").mutation(api.items.move, { id: item, folderId: folder });
    expect((await as("alice").query(api.items.listMine, {}))[0].folderId).toBe(folder);

    await as("admin").mutation(api.items.move, { id: item, folderId: null });
    expect((await t.run((ctx) => ctx.db.get(item)))!.folderId).toBeUndefined();

    // Çevrimdışı oluşturulmuş kayıt: klasör bu arada silinmiş.
    await as("alice").mutation(api.folders.remove, { id: folder });
    const late = await createItem("alice", folder);
    expect((await t.run((ctx) => ctx.db.get(late)))!.folderId).toBeUndefined();
  });
});
