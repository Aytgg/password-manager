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
    const user = (name: string, role: "admin" | "manager" | "member", key: number) =>
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
      mia: await user("mia", "manager", 2),
      max: await user("max", "manager", 3),
      alice: await user("alice", "member", 4),
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

  const folderNames = async (name: Name) =>
    (await as(name).query(api.folders.list, {})).map((folder) => folder.name).sort();

  return { t, ids, as, createItem, folderNames };
}

describe("klasörler", () => {
  test("klasörleri yöneticiler ve departman yöneticileri oluşturur; personel oluşturamaz", async () => {
    const { as } = await setup();

    await as("admin").mutation(api.folders.create, { name: "Genel" });
    const root = await as("mia").mutation(api.folders.create, { name: " Sunucular " });
    const child = await as("mia").mutation(api.folders.create, { name: "Prod", parentId: root });

    await expect(as("alice").mutation(api.folders.create, { name: "X" })).rejects.toThrow(
      /yalnızca yöneticiler ve departman yöneticileri/,
    );
    await expect(
      as("mia").mutation(api.folders.create, { name: "prod", parentId: root }),
    ).rejects.toThrow(/aynı isimde/);
    await expect(as("mia").mutation(api.folders.create, { name: "  " })).rejects.toThrow(
      /1-100 karakter/,
    );

    const list = await as("mia").query(api.folders.list, {});
    expect(list.find((folder) => folder.id === child)).toMatchObject({
      name: "Prod",
      parentId: root,
      isOwner: true,
      canManage: true,
    });
    expect(list.find((folder) => folder.name === "Genel")?.canManage).toBe(false);
  });

  test("herkes bütün klasörleri görür; departman yöneticisi yalnız kendi klasörlerini düzenler", async () => {
    const { as, folderNames } = await setup();

    const mias = await as("mia").mutation(api.folders.create, { name: "Mia" });
    const maxs = await as("max").mutation(api.folders.create, { name: "Max" });

    for (const name of ["admin", "mia", "max", "alice"] as const) {
      expect(await folderNames(name)).toEqual(["Max", "Mia"]);
    }
    expect((await as("alice").query(api.folders.list, {})).every((f) => !f.canManage)).toBe(true);

    await expect(as("max").mutation(api.folders.rename, { id: mias, name: "Y" })).rejects.toThrow(
      /yönetme yetkin yok/,
    );
    await expect(
      as("max").mutation(api.folders.create, { name: "Alt", parentId: mias }),
    ).rejects.toThrow(/yönetme yetkin yok/);
    await expect(as("max").mutation(api.folders.move, { id: maxs, parentId: mias })).rejects.toThrow(
      /yönetme yetkin yok/,
    );
    await expect(as("alice").mutation(api.folders.remove, { id: mias })).rejects.toThrow(
      /yönetme yetkin yok/,
    );

    // Yönetici her klasörü düzenler.
    await as("admin").mutation(api.folders.rename, { id: mias, name: "Mia 2" });
    await as("admin").mutation(api.folders.move, { id: maxs, parentId: mias });
    expect((await as("alice").query(api.folders.list, {})).find((f) => f.id === maxs)?.parentId).toBe(
      mias,
    );
  });

  test("klasör taşınır; kendi altına taşınamaz", async () => {
    const { as } = await setup();

    const a = await as("mia").mutation(api.folders.create, { name: "A" });
    const b = await as("mia").mutation(api.folders.create, { name: "B", parentId: a });
    const c = await as("mia").mutation(api.folders.create, { name: "C" });

    await expect(as("mia").mutation(api.folders.move, { id: a, parentId: b })).rejects.toThrow(
      /kendi içine/,
    );
    await expect(as("mia").mutation(api.folders.move, { id: a, parentId: a })).rejects.toThrow(
      /kendi içine/,
    );

    await as("mia").mutation(api.folders.move, { id: a, parentId: c });
    await as("mia").mutation(api.folders.move, { id: b, parentId: null });

    const list = await as("mia").query(api.folders.list, {});
    expect(list.find((f) => f.id === a)?.parentId).toBe(c);
    expect(list.find((f) => f.id === b)?.parentId).toBeNull();
  });

  test("klasör silinince içindekiler bir üst klasöre taşınır", async () => {
    const { t, as, createItem } = await setup();

    const root = await as("mia").mutation(api.folders.create, { name: "Kök" });
    const doomed = await as("mia").mutation(api.folders.create, { name: "Silinecek", parentId: root });
    await as("mia").mutation(api.folders.create, { name: "Alt", parentId: root });
    const child = await as("mia").mutation(api.folders.create, { name: "Alt", parentId: doomed });
    const item = await createItem("alice", doomed);

    await as("mia").mutation(api.folders.remove, { id: doomed });

    const list = await as("mia").query(api.folders.list, {});
    expect(list.find((f) => f.id === child)).toMatchObject({ name: "Alt (2)", parentId: root });
    expect((await t.run((ctx) => ctx.db.get(item)))!.folderId).toBe(root);

    await as("mia").mutation(api.folders.remove, { id: root });
    expect((await t.run((ctx) => ctx.db.get(item)))!.folderId).toBeUndefined();
  });

  test("personel kendi parolasını herhangi bir klasöre koyar; başkasınınkini taşıyamaz", async () => {
    const { t, as, createItem } = await setup();

    const folder = await as("mia").mutation(api.folders.create, { name: "VPN" });
    const item = await createItem("alice", folder);
    expect((await as("alice").query(api.items.listMine, {}))[0].folderId).toBe(folder);

    await as("alice").mutation(api.items.move, { id: item, folderId: null });
    await as("alice").mutation(api.items.move, { id: item, folderId: folder });

    await expect(as("mia").mutation(api.items.move, { id: item, folderId: null })).rejects.toThrow(
      /taşıma yetkin yok/,
    );
    await as("admin").mutation(api.items.move, { id: item, folderId: null });
    expect((await t.run((ctx) => ctx.db.get(item)))!.folderId).toBeUndefined();

    // Çevrimdışı oluşturulmuş kayıt: klasör bu arada silinmiş.
    await as("mia").mutation(api.folders.remove, { id: folder });
    const late = await createItem("alice", folder);
    expect((await t.run((ctx) => ctx.db.get(late)))!.folderId).toBeUndefined();
    await expect(as("alice").mutation(api.items.move, { id: late, folderId: folder })).rejects.toThrow(
      /Klasör bulunamadı/,
    );
  });
});
