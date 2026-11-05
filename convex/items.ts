import { ConvexError, v } from "convex/values";

import type { Doc, Id } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { mutation, query } from "./_generated/server";
import {
  assertSealedField,
  assertWrappedKey,
  type ExtraPermissions,
  grantPermissions,
  itemPermissions,
  type Permissions,
  currentDepartmentKey,
  deleteItem,
  directRecipients,
  itemGrants,
  removeDisallowedAccess,
  requireActiveUser,
} from "./lib";
import { sealedField, wrappedKey } from "./schema";

const ITEM_ID = /^item-[0-9a-f]{32}$/;

const userAccess = v.object({ userId: v.id("users"), access: wrappedKey });
const departmentAccess = v.object({
  departmentId: v.id("departments"),
  keyVersion: v.number(),
  access: wrappedKey,
});

const extraPermissions = v.object({ edit: v.boolean(), delete: v.boolean(), share: v.boolean() });

const PERMISSION_ERRORS: Record<keyof Permissions, string> = {
  view: "Bu parolaya erişimin yok.",
  edit: "Bu parolayı düzenleme yetkin yok.",
  delete: "Bu parolayı silme yetkin yok.",
  share: "Bu parolayı yetkilendirme yetkin yok.",
};

async function requirePermission(
  ctx: QueryCtx,
  user: Doc<"users">,
  id: Id<"items">,
  permission: keyof Permissions,
) {
  const item = await ctx.db.get(id);
  const permissions = item ? await itemPermissions(ctx, user, item) : null;

  if (!item || !permissions?.[permission]) {
    throw new ConvexError(PERMISSION_ERRORS[permission]);
  }

  return { item, permissions };
}

function requireKeyVersion(item: Doc<"items">, expected: number) {
  if (item.keyVersion !== expected) {
    throw new ConvexError(
      "Parola başka bir işlemle güncellendi. Tekrar deneniyor.",
    );
  }
}

async function myAccess(ctx: QueryCtx, itemId: Id<"items">, userId: Id<"users">) {
  return await ctx.db
    .query("itemAccess")
    .withIndex("by_item_and_user", (q) => q.eq("item", itemId).eq("userId", userId))
    .unique();
}

async function departmentAccessRow(
  ctx: QueryCtx,
  itemId: Id<"items">,
  departmentId: Id<"departments">,
) {
  return await ctx.db
    .query("itemDepartmentAccess")
    .withIndex("by_item_and_department", (q) =>
      q.eq("item", itemId).eq("department", departmentId),
    )
    .unique();
}

const historyRecord = v.object({ id: v.optional(v.id("itemHistory")), entry: sealedField });

async function historyRecords(ctx: QueryCtx, itemId: Id<"items">) {
  return (
    await ctx.db
      .query("itemHistory")
      .withIndex("by_item", (q) => q.eq("item", itemId))
      .collect()
  ).map((row) => ({ id: row._id, entry: row.entry }));
}

type KeyPath =
  | { kind: "direct"; access: Doc<"itemAccess">["access"] }
  | {
      kind: "department";
      departmentKey: Doc<"departmentKeys">["access"];
      itemKey: Doc<"itemDepartmentAccess">["access"];
    };

type GrantList = {
  userIds: Id<"users">[];
  departmentIds: Id<"departments">[];
  /** Kural bazında ek yetkiler; anahtar kişi ya da departman kimliği. */
  permissions: Record<string, ExtraPermissions>;
};

function serialize(
  item: Doc<"items">,
  access: KeyPath,
  userId: Id<"users">,
  permissions: Permissions,
  grants: GrantList | null = null,
) {
  return {
    id: item._id,
    itemId: item.itemId,
    ownerId: item.ownerId,
    isOwner: item.ownerId === userId,
    metadata: item.metadata,
    secret: item.secret,
    folderId: item.folderId ?? null,
    keyVersion: item.keyVersion,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    access,
    permissions,
    // Yalnızca yetkilendirebilenlere: paylaşım paneli çevrimdışıyken bundan
    // çalışır.
    grants,
  };
}

async function grantList(
  ctx: QueryCtx,
  item: Doc<"items">,
  permissions: Permissions,
): Promise<GrantList | null> {
  if (!permissions.share) {
    return null;
  }

  const result: GrantList = { userIds: [], departmentIds: [], permissions: {} };

  for (const grant of await ctx.db
    .query("itemGrants")
    .withIndex("by_item", (q) => q.eq("item", item._id))
    .collect()) {
    const target = grant.userId ?? grant.departmentId;
    if (!target) continue;

    if (grant.userId) result.userIds.push(grant.userId);
    else if (grant.departmentId) result.departmentIds.push(grant.departmentId);
    result.permissions[target] = grantPermissions(grant);
  }

  return result;
}

/** Kullanıcının kayda ulaşma yolu: doğrudan paket ya da departmanının
 * güncel anahtarı. Erişimi yoksa `null`. */
async function keyPath(ctx: QueryCtx, user: Doc<"users">, item: Doc<"items">): Promise<KeyPath | null> {
  const direct = await myAccess(ctx, item._id, user._id);

  if (direct) {
    return { kind: "direct", access: direct.access };
  }

  const department = user.departmentId ? await ctx.db.get(user.departmentId) : null;
  const departmentKey = department ? await currentDepartmentKey(ctx, department, user._id) : null;
  const row = department ? await departmentAccessRow(ctx, item._id, department._id) : null;

  if (department && departmentKey && row?.keyVersion === department.keyVersion) {
    return { kind: "department", departmentKey: departmentKey.access, itemKey: row.access };
  }

  return null;
}

/**
 * Kaydın geçmişi; kaydı açabilen herkes görebilir. Geçmiş kayıtları
 * kaydın DEK'i ile şifreli olduğu için ulaşma yolu da birlikte döner.
 */
export const history = query({
  args: { id: v.id("items") },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await ctx.db.get(args.id);
    const path = item ? await keyPath(ctx, user, item) : null;

    if (!item || !path) {
      throw new ConvexError("Bu parolaya erişimin yok.");
    }

    return {
      item: serialize(item, path, user._id, await itemPermissions(ctx, user, item)),
      history: await historyRecords(ctx, item._id),
    };
  },
});

/**
 * Kullanıcının açabildiği kayıtlar ve her birine ulaşma yolu: doğrudan
 * kendisine paketlenmiş DEK ya da departmanının anahtarı üzerinden.
 */
export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);
    const results = new Map<Id<"items">, ReturnType<typeof serialize>>();

    for (const access of await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", user._id))
      .collect()) {
      const item = await ctx.db.get(access.item);

      if (item) {
        const permissions = await itemPermissions(ctx, user, item);
        results.set(
          item._id,
          serialize(
            item,
            { kind: "direct", access: access.access },
            user._id,
            permissions,
            await grantList(ctx, item, permissions),
          ),
        );
      }
    }

    const department = user.departmentId ? await ctx.db.get(user.departmentId) : null;
    const departmentKey = department ? await currentDepartmentKey(ctx, department, user._id) : null;

    if (department && departmentKey) {
      for (const row of await ctx.db
        .query("itemDepartmentAccess")
        .withIndex("by_department", (q) => q.eq("department", department._id))
        .collect()) {
        if (row.keyVersion !== department.keyVersion || results.has(row.item)) {
          continue;
        }

        const item = await ctx.db.get(row.item);

        if (item) {
          const permissions = await itemPermissions(ctx, user, item);
          results.set(
            item._id,
            serialize(
              item,
              { kind: "department", departmentKey: departmentKey.access, itemKey: row.access },
              user._id,
              permissions,
              await grantList(ctx, item, permissions),
            ),
          );
        }
      }
    }

    return [...results.values()];
  },
});

export const create = mutation({
  args: {
    itemId: v.string(),
    metadata: sealedField,
    secret: sealedField,
    ownerAccess: wrappedKey,
    folderId: v.optional(v.id("folders")),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);

    if (!user.publicKey) {
      throw new ConvexError("Önce kasanın açık anahtarı kaydedilmeli.");
    }

    if (!ITEM_ID.test(args.itemId)) {
      throw new ConvexError("Geçersiz kayıt kimliği.");
    }

    assertSealedField(args.metadata);
    assertSealedField(args.secret);
    assertWrappedKey(args.ownerAccess);

    const duplicate = await ctx.db
      .query("items")
      .withIndex("by_item_id", (q) => q.eq("itemId", args.itemId))
      .unique();

    if (duplicate) {
      // Çevrimdışı kuyruktan tekrar gönderilen kayıt (önceki yanıt
      // kaybolmuş olabilir).
      if (duplicate.ownerId === user._id) {
        return duplicate._id;
      }

      throw new ConvexError("Bu kayıt kimliği zaten kullanılıyor.");
    }

    // Çevrimdışı kuyruktan gelen kayıtta klasör bu arada silinmiş olabilir;
    // o zaman kayıt köke konur.
    let folderId: Id<"folders"> | undefined;

    if (args.folderId) {
      folderId = (await ctx.db.get(args.folderId))?._id;
    }

    const now = Date.now();

    const id = await ctx.db.insert("items", {
      itemId: args.itemId,
      ownerId: user._id,
      folderId,
      metadata: args.metadata,
      secret: args.secret,
      keyVersion: 1,
      needsRekey: false,
      createdAt: now,
      updatedAt: now,
    });

    await ctx.db.insert("itemAccess", {
      item: id,
      userId: user._id,
      access: args.ownerAccess,
    });

    return id;
  },
});

/**
 * Kaydı bir klasöre ya da köke (`folderId: null`) taşır. Kaydın sahibi ya da
 * bir yönetici yapabilir; klasörler herkese açıktır.
 */
export const move = mutation({
  args: { id: v.id("items"), folderId: v.union(v.id("folders"), v.null()) },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await ctx.db.get(args.id);

    if (!item || (item.ownerId !== user._id && user.role !== "admin")) {
      throw new ConvexError("Parola bulunamadı ya da taşıma yetkin yok.");
    }

    if (args.folderId && !(await ctx.db.get(args.folderId))) {
      throw new ConvexError("Klasör bulunamadı.");
    }

    await ctx.db.patch(item._id, { folderId: args.folderId ?? undefined, updatedAt: Date.now() });
  },
});

/**
 * Kaydı kalıcı olarak siler. Silme yetkisi olan yapabilir; kayıtla birlikte
 * bütün anahtar paketleri, paylaşım kuralları ve geçmişi de silinir.
 */
export const remove = mutation({
  args: { id: v.id("items") },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const { item } = await requirePermission(ctx, user, args.id, "delete");

    await deleteItem(ctx, item._id);
  },
});

/**
 * Paylaşım yapılabilecek departmanlar ve kişiler. İstemci önbelleğe alır;
 * böylece yetkilendirme çevrimdışıyken de yapılıp sonra gönderilebilir.
 */
export const shareDirectory = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);

    const departments = await ctx.db.query("departments").collect();
    const departmentNames = new Map(departments.map((d) => [d._id, d.name]));

    return {
      departments: departments
        .map((department) => ({ id: department._id, name: department.name }))
        .sort((a, b) => a.name.localeCompare(b.name, "tr")),
      users: (await ctx.db.query("users").collect())
        .filter((candidate) => candidate.status !== "disabled" && candidate._id !== user._id)
        .map((candidate) => ({
          userId: candidate._id,
          email: candidate.email,
          displayName: candidate.displayName ?? candidate.email,
          status: candidate.status,
          departmentId: candidate.departmentId ?? null,
          isAdmin: candidate.role === "admin",
          departmentName: candidate.departmentId
            ? (departmentNames.get(candidate.departmentId) ?? null)
            : null,
        }))
        .sort((a, b) => a.displayName.localeCompare(b.displayName, "tr")),
    };
  },
});

/** Yetkilendirme paneli: departman ve kişi bazında paylaşım durumu.
 * Yetkilendirme yetkisi gerekir. */
export const sharing = query({
  args: { id: v.id("items") },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const { item } = await requirePermission(ctx, user, args.id, "share");
    const grants = await itemGrants(ctx, item._id);

    const directKeyUserIds = new Set(
      (
        await ctx.db
          .query("itemAccess")
          .withIndex("by_item", (q) => q.eq("item", item._id))
          .collect()
      ).map((access) => access.userId),
    );

    const departments = await ctx.db.query("departments").collect();
    const departmentNames = new Map(departments.map((d) => [d._id, d.name]));

    // Departmanı üzerinden anahtarı hazır olan: departman anahtarını tutan ve
    // kaydın departmana paketi güncel olan.
    const departmentReady = new Map<Id<"departments">, boolean>();
    for (const department of departments) {
      const row = await departmentAccessRow(ctx, item._id, department._id);
      departmentReady.set(
        department._id,
        department.keyVersion > 0 && row?.keyVersion === department.keyVersion,
      );
    }

    const users = (await ctx.db.query("users").collect()).filter(
      (candidate) => candidate.status !== "disabled" && candidate._id !== user._id,
    );

    const result = [];

    for (const candidate of users) {
      const viaDepartment =
        candidate.departmentId !== undefined && grants.departmentIds.has(candidate.departmentId);

      const hasDepartmentKey =
        viaDepartment &&
        departmentReady.get(candidate.departmentId!) === true &&
        (await currentDepartmentKey(ctx, (await ctx.db.get(candidate.departmentId!))!, candidate._id)) !==
          null;

      result.push({
        userId: candidate._id,
        email: candidate.email,
        displayName: candidate.displayName ?? candidate.email,
        status: candidate.status,
        departmentName: candidate.departmentId
          ? (departmentNames.get(candidate.departmentId) ?? null)
          : null,
        direct: grants.userIds.has(candidate._id),
        viaDepartment,
        isAdmin: candidate.role === "admin",
        hasKey: directKeyUserIds.has(candidate._id) || hasDepartmentKey,
        hasPublicKey: candidate.publicKey !== undefined,
      });
    }

    return {
      departments: departments
        .map((department) => ({
          id: department._id,
          name: department.name,
          granted: grants.departmentIds.has(department._id),
        }))
        .sort((a, b) => a.name.localeCompare(b.name, "tr")),
      users: result.sort((a, b) => a.displayName.localeCompare(b.displayName, "tr")),
    };
  },
});

/**
 * Kişiye ya da departmana verilen kuralı ekler, ek yetkilerini değiştirir ya
 * da kaldırır. Yetkilendirme yetkisi gerekir. Sahip ve yöneticiler dışındaki
 * yetkilendiriciler yalnızca kendilerinde olan yetkileri verebilir ve
 * kendilerinde olmayan bir yetki içeren kuralı değiştiremez.
 */
async function updateGrant(
  ctx: MutationCtx,
  user: Doc<"users">,
  itemId: Id<"items">,
  target: { userId: Id<"users"> } | { departmentId: Id<"departments"> },
  granted: boolean,
  permissions: ExtraPermissions | undefined,
) {
  const { item, permissions: actor } = await requirePermission(ctx, user, itemId, "share");
  const full = item.ownerId === user._id || user.role === "admin";

  // Kişi kendi erişimini dayandığı kuralı değiştiremez: kendi kuralı ya da
  // bağlı olduğu departmanın kuralı.
  if (
    !full &&
    ("userId" in target
      ? target.userId === user._id
      : user.departmentId !== undefined && target.departmentId === user.departmentId)
  ) {
    throw new ConvexError(
      "userId" in target
        ? "Kendi yetkini değiştiremezsin."
        : "Bağlı olduğun departmanın yetkisini değiştiremezsin.",
    );
  }

  const existing = (
    await ctx.db
      .query("itemGrants")
      .withIndex("by_item", (q) => q.eq("item", item._id))
      .collect()
  ).find((grant) =>
    "userId" in target ? grant.userId === target.userId : grant.departmentId === target.departmentId,
  );

  const exceeds = (wanted: ExtraPermissions) =>
    !full &&
    ((wanted.edit && !actor.edit) || (wanted.delete && !actor.delete) || (wanted.share && !actor.share));

  if (existing && exceeds(grantPermissions(existing))) {
    throw new ConvexError("Bu kuralda senin sahip olmadığın yetkiler var; değiştiremezsin.");
  }

  if (!granted) {
    if (existing) {
      await ctx.db.delete(existing._id);
      await removeDisallowedAccess(ctx, item._id);
    }
    return;
  }

  const next = permissions ??
    (existing ? grantPermissions(existing) : { edit: false, delete: false, share: false });

  if (exceeds(next)) {
    throw new ConvexError("Sahip olmadığın bir yetkiyi veremezsin.");
  }

  const fields = {
    canEdit: next.edit || undefined,
    canDelete: next.delete || undefined,
    canShare: next.share || undefined,
  };

  if (existing) {
    await ctx.db.patch(existing._id, fields);
  } else {
    await ctx.db.insert("itemGrants", { item: item._id, ...target, ...fields });
  }
}

export const setUserGrant = mutation({
  args: {
    id: v.id("items"),
    userId: v.id("users"),
    granted: v.boolean(),
    permissions: v.optional(extraPermissions),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await ctx.db.get(args.id);

    if (item && args.userId === item.ownerId) {
      throw new ConvexError("Parola sahibinin erişimi değiştirilemez.");
    }

    if (args.userId === user._id && user.role !== "admin") {
      throw new ConvexError("Kendi yetkini değiştiremezsin.");
    }

    const target = await ctx.db.get(args.userId);

    if (args.granted && target?.role === "admin") {
      throw new ConvexError("Yöneticiler zaten bütün parolalara erişir.");
    }

    if (args.granted && (!target || target.status === "disabled")) {
      throw new ConvexError("Yetki verilecek kullanıcı bulunamadı.");
    }

    await updateGrant(ctx, user, args.id, { userId: args.userId }, args.granted, args.permissions);
  },
});

export const setDepartmentGrant = mutation({
  args: {
    id: v.id("items"),
    departmentId: v.id("departments"),
    granted: v.boolean(),
    permissions: v.optional(extraPermissions),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);

    if (!(await ctx.db.get(args.departmentId))) {
      throw new ConvexError("Departman bulunamadı.");
    }

    await updateGrant(
      ctx,
      user,
      args.id,
      { departmentId: args.departmentId },
      args.granted,
      args.permissions,
    );
  },
});

/** Departman paketinin, departmanın güncel anahtarına ve paylaşım kuralına
 * uyduğunu doğrular. */
async function checkDepartmentAccess(
  ctx: QueryCtx,
  item: Doc<"items">,
  granted: Set<Id<"departments">>,
  entry: { departmentId: Id<"departments">; keyVersion: number },
) {
  if (!granted.has(entry.departmentId)) {
    throw new ConvexError("Paylaşım kuralı bu departmana erişim vermiyor.");
  }

  const department = await ctx.db.get(entry.departmentId);

  if (!department || department.keyVersion === 0 || department.keyVersion !== entry.keyVersion) {
    throw new ConvexError("Departman anahtarı değişti. Tekrar deneniyor.");
  }
}

async function upsertDepartmentAccess(
  ctx: MutationCtx,
  itemId: Id<"items">,
  entry: { departmentId: Id<"departments">; keyVersion: number; access: Doc<"itemDepartmentAccess">["access"] },
) {
  const existing = await departmentAccessRow(ctx, itemId, entry.departmentId);

  if (existing) {
    await ctx.db.patch(existing._id, { keyVersion: entry.keyVersion, access: entry.access });
  } else {
    await ctx.db.insert("itemDepartmentAccess", {
      item: itemId,
      department: entry.departmentId,
      keyVersion: entry.keyVersion,
      access: entry.access,
    });
  }
}

/**
 * Kurala göre anahtar paketi eksik olan kullanıcılar ve departmanlar için,
 * kayda doğrudan erişimi olan bir istemcinin ürettiği paketleri ekler.
 * Zaten paketi olanlar sessizce atlanır.
 */
export const addAccesses = mutation({
  args: {
    id: v.id("items"),
    keyVersion: v.number(),
    accesses: v.array(userAccess),
    departmentAccesses: v.array(departmentAccess),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const item = await ctx.db.get(args.id);

    if (!item || !(await myAccess(ctx, args.id, user._id))) {
      throw new ConvexError("Bu parolaya erişimin yok.");
    }

    requireKeyVersion(item, args.keyVersion);

    const recipients = await directRecipients(ctx, item);
    const { departmentIds } = await itemGrants(ctx, item._id);

    for (const entry of args.accesses) {
      assertWrappedKey(entry.access);

      if (!recipients.has(entry.userId)) {
        throw new ConvexError("Paylaşım kuralı bu kullanıcıya erişim vermiyor.");
      }

      if (await myAccess(ctx, args.id, entry.userId)) {
        continue;
      }

      await ctx.db.insert("itemAccess", {
        item: args.id,
        userId: entry.userId,
        access: entry.access,
      });
    }

    for (const entry of args.departmentAccesses) {
      assertWrappedKey(entry.access);
      await checkDepartmentAccess(ctx, item, departmentIds, entry);

      const existing = await departmentAccessRow(ctx, item._id, entry.departmentId);

      if (existing?.keyVersion === entry.keyVersion) {
        continue;
      }

      await upsertDepartmentAccess(ctx, item._id, entry);
    }
  },
});

/**
 * Kaydı yeni bir DEK ile şifrelenmiş haliyle değiştirir ve bütün anahtar
 * paketlerini yeniler. Yalnızca sahip yapabilir; kişi listesindeki herkesin
 * kurala göre erişimi olmalı ve anahtarı hazır her paylaşılan departman
 * listede bulunmalıdır.
 */
export const rekey = mutation({
  args: {
    id: v.id("items"),
    keyVersion: v.number(),
    metadata: sealedField,
    secret: sealedField,
    history: v.optional(v.array(historyRecord)),
    accesses: v.array(userAccess),
    departmentAccesses: v.array(departmentAccess),
  },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const { item } = await requirePermission(ctx, user, args.id, "edit");

    requireKeyVersion(item, args.keyVersion);
    assertSealedField(args.metadata);
    assertSealedField(args.secret);

    // Geçmiş eksiksiz gönderilmeli: mevcut her kayıt (yeni DEK ile) tam bir
    // kez, yeni kayıt ise en fazla bir tane. Böylece geçmiş silinemez.
    const existingHistory = new Set((await historyRecords(ctx, item._id)).map((row) => row.id));
    const seenHistory = new Set<Id<"itemHistory">>();
    let newHistory = 0;

    const historyArgs = args.history ?? [];

    for (const record of historyArgs) {
      assertSealedField(record.entry);

      if (record.id === undefined) {
        newHistory += 1;
      } else if (!existingHistory.has(record.id) || seenHistory.has(record.id)) {
        throw new ConvexError("Parola geçmişi değişti. Tekrar deneniyor.");
      } else {
        seenHistory.add(record.id);
      }
    }

    if (seenHistory.size !== existingHistory.size || newHistory > 1) {
      throw new ConvexError("Parola geçmişi eksik. Uygulamayı güncelleyip tekrar dene.");
    }

    const recipients = await directRecipients(ctx, item);
    const { departmentIds } = await itemGrants(ctx, item._id);
    const seen = new Set<Id<"users">>();

    for (const entry of args.accesses) {
      assertWrappedKey(entry.access);

      if (seen.has(entry.userId)) {
        throw new ConvexError("Erişim listesinde tekrar eden kullanıcı var.");
      }

      if (!recipients.has(entry.userId)) {
        throw new ConvexError("Paylaşım kuralı bu kullanıcıya erişim vermiyor.");
      }

      seen.add(entry.userId);
    }

    if (recipients.has(item.ownerId) && !seen.has(item.ownerId)) {
      throw new ConvexError("Parola sahibinin erişimi kaldırılamaz.");
    }

    const seenDepartments = new Set<Id<"departments">>();

    for (const entry of args.departmentAccesses) {
      assertWrappedKey(entry.access);

      if (seenDepartments.has(entry.departmentId)) {
        throw new ConvexError("Erişim listesinde tekrar eden departman var.");
      }

      await checkDepartmentAccess(ctx, item, departmentIds, entry);
      seenDepartments.add(entry.departmentId);
    }

    // Anahtarı hazır bir departman listede yoksa o departman erişimini
    // kaybederdi.
    for (const departmentId of departmentIds) {
      const department = await ctx.db.get(departmentId);

      if (department && department.keyVersion > 0 && !seenDepartments.has(departmentId)) {
        throw new ConvexError("Paylaşılan bir departmanın anahtarı eksik. Tekrar deneniyor.");
      }
    }

    await ctx.db.patch(item._id, {
      metadata: args.metadata,
      secret: args.secret,
      keyVersion: item.keyVersion + 1,
      needsRekey: false,
      updatedAt: Date.now(),
    });

    for (const record of historyArgs) {
      if (record.id === undefined) {
        await ctx.db.insert("itemHistory", {
          item: item._id,
          entry: record.entry,
          createdAt: Date.now(),
        });
      } else {
        await ctx.db.patch(record.id, { entry: record.entry });
      }
    }

    for (const access of await ctx.db
      .query("itemAccess")
      .withIndex("by_item", (q) => q.eq("item", item._id))
      .collect()) {
      await ctx.db.delete(access._id);
    }

    for (const access of await ctx.db
      .query("itemDepartmentAccess")
      .withIndex("by_item", (q) => q.eq("item", item._id))
      .collect()) {
      await ctx.db.delete(access._id);
    }

    for (const entry of args.accesses) {
      await ctx.db.insert("itemAccess", {
        item: item._id,
        userId: entry.userId,
        access: entry.access,
      });
    }

    for (const entry of args.departmentAccesses) {
      await upsertDepartmentAccess(ctx, item._id, entry);
    }
  },
});

/** Kaydın anahtar paketlerini kimlerin alması gerektiği ve şu an kimlerde
 * olduğu. */
async function keyTargets(ctx: QueryCtx, item: Doc<"items">) {
  const recipients = await directRecipients(ctx, item);
  const { departmentIds } = await itemGrants(ctx, item._id);

  const currentUsers = new Set(
    (
      await ctx.db
        .query("itemAccess")
        .withIndex("by_item", (q) => q.eq("item", item._id))
        .collect()
    ).map((row) => row.userId),
  );

  const departments = [];
  for (const departmentId of departmentIds) {
    const department = await ctx.db.get(departmentId);

    if (department && department.keyVersion > 0 && department.publicKey) {
      departments.push({
        departmentId,
        keyVersion: department.keyVersion,
        publicKey: department.publicKey,
        hasCurrentKey:
          (await departmentAccessRow(ctx, item._id, departmentId))?.keyVersion ===
          department.keyVersion,
      });
    }
  }

  return { recipients, currentUsers, departments };
}

/** Yeni bir DEK'in paketlenmesi gerekenler: kaydın sahibi, anahtarı hâlâ
 * kurala uyan kişiler (eksikler sonra doldurulur) ve anahtarı hazır bütün
 * departmanlar. */
async function rekeyRecipients(ctx: QueryCtx, item: Doc<"items">) {
  const { recipients, currentUsers, departments } = await keyTargets(ctx, item);
  const userIds = new Set([...currentUsers].filter((id) => recipients.has(id)));

  if (recipients.has(item.ownerId)) {
    userIds.add(item.ownerId);
  }

  return {
    recipients: [...userIds].map((id) => ({ userId: id, publicKey: recipients.get(id)!.publicKey })),
    departments: departments.map(({ departmentId, keyVersion, publicKey }) => ({
      departmentId,
      keyVersion,
      publicKey,
    })),
  };
}

/**
 * Düzenleme için: kaydın güncel hali (çağıranın ulaşma yoluyla) ve yeni
 * DEK'in paketleneceği alıcılar. Düzenleme yetkisi gerekir; düzenleme
 * `rekey` ile kaydedilir.
 */
export const editTargets = query({
  args: { id: v.id("items") },
  handler: async (ctx, args) => {
    const user = await requireActiveUser(ctx);
    const { item, permissions } = await requirePermission(ctx, user, args.id, "edit");
    const path = await keyPath(ctx, user, item);

    if (!path) {
      throw new ConvexError("Bu parolanın anahtarı henüz sende yok; birazdan tekrar dene.");
    }

    return {
      item: serialize(item, path, user._id, permissions),
      history: await historyRecords(ctx, item._id),
      ...(await rekeyRecipients(ctx, item)),
    };
  },
});

/**
 * Kayıtlarla ilgili, istemcinin arka planda yapması gereken şifreleme işleri:
 * - fills: doğrudan erişimim olan kayıtlarda, kurala göre paketi eksik
 *   kullanıcılar ve departmanlar (paketleri ben üretirim).
 * - rekeys: sahibi olduğum ve erişimi kaldırılmış kayıtlar (yeni DEK).
 */
export const pendingWork = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);

    const fills = [];
    const rekeys = [];

    for (const access of await ctx.db
      .query("itemAccess")
      .withIndex("by_user", (q) => q.eq("userId", user._id))
      .collect()) {
      const item = await ctx.db.get(access.item);

      if (!item) {
        continue;
      }

      const { recipients, currentUsers, departments } = await keyTargets(ctx, item);

      const serialized = serialize(
        item,
        { kind: "direct", access: access.access },
        user._id,
        await itemPermissions(ctx, user, item),
      );

      if (item.needsRekey) {
        if (item.ownerId === user._id) {
          rekeys.push({
            item: serialized,
            history: await historyRecords(ctx, item._id),
            ...(await rekeyRecipients(ctx, item)),
          });
        }

        // Eski DEK artık dağıtılmamalı; eksikler rekey sonrası yeni DEK
        // ile tamamlanır.
        continue;
      }

      const missingUsers = [...recipients.values()].filter(
        (candidate) => !currentUsers.has(candidate._id),
      );
      const missingDepartments = departments.filter((department) => !department.hasCurrentKey);

      if (missingUsers.length > 0 || missingDepartments.length > 0) {
        fills.push({
          item: serialized,
          recipients: missingUsers.map((candidate) => ({
            userId: candidate._id,
            publicKey: candidate.publicKey,
          })),
          departments: missingDepartments.map(({ departmentId, keyVersion, publicKey }) => ({
            departmentId,
            keyVersion,
            publicKey,
          })),
        });
      }
    }

    return { fills, rekeys };
  },
});

// Paylaşım kuralı gereği kullanıcının görmesi gereken fakat anahtarına henüz
// ulaşamadığı kayıtların sayısı. Paketler, işlemi yapan kişinin cihazında
// birkaç saniye içinde üretilir; uzun sürerse ilgili kişi çevrimdışıdır.
export const pendingSharedCount = query({
  args: {},
  handler: async (ctx) => {
    const user = await requireActiveUser(ctx);

    const department = user.departmentId ? await ctx.db.get(user.departmentId) : null;
    const departmentKey = department ? await currentDepartmentKey(ctx, department, user._id) : null;

    const grants = [
      ...(await ctx.db
        .query("itemGrants")
        .withIndex("by_user", (q) => q.eq("userId", user._id))
        .collect()),
      ...(department
        ? await ctx.db
            .query("itemGrants")
            .withIndex("by_department", (q) => q.eq("departmentId", department._id))
            .collect()
        : []),
    ];

    // Yöneticiler bütün kayıtları görür.
    const itemIds =
      user.role === "admin"
        ? (await ctx.db.query("items").collect()).map((item) => item._id)
        : grants.map((grant) => grant.item);

    let count = 0;

    for (const itemId of new Set(itemIds)) {
      const item = await ctx.db.get(itemId);

      if (!item || item.ownerId === user._id || (await myAccess(ctx, itemId, user._id))) {
        continue;
      }

      const viaDepartment =
        department !== null &&
        departmentKey !== null &&
        (await departmentAccessRow(ctx, itemId, department._id))?.keyVersion ===
          department.keyVersion;

      if (!viaDepartment) {
        count += 1;
      }
    }

    return count;
  },
});
