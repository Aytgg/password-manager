import { invoke } from "@tauri-apps/api/core";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { ConvexError } from "convex/values";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api } from "../convex/_generated/api";
import type { Id } from "../convex/_generated/dataModel";
import { errorMessage } from "./errors";

export type ServerItem = FunctionReturnType<typeof api.items.listMine>[number];
export type ShareDirectory = FunctionReturnType<typeof api.items.shareDirectory>;
export type Folder = FunctionReturnType<typeof api.folders.list>[number];

type SealedField = { nonce: string; ciphertext: string };
type WrappedKey = { ephemeralPublicKey: string; nonce: string; ciphertext: string };

export type NewItem = {
  itemId: string;
  metadata: SealedField;
  secret: SealedField;
  ownerAccess: WrappedKey;
};

// Rust tarafındaki `EncryptedItem`; `access` doğrudan ya da departman
// anahtarı üzerinden DEK'e ulaşma yoludur.
export type EncryptedItem = {
  itemId: string;
  ownerId: string;
  metadata: SealedField;
  secret: SealedField;
  access: ServerItem["access"];
};

/** Kaydın bir önceki hali; Rust tarafındaki `HistoryRecord`. Yeni eklenen
 * (henüz sunucuya gitmemiş) kayıtta `id` yoktur. */
export type HistoryRecord = { id?: Id<"itemHistory">; entry: SealedField };

/** Görüntülemenin yanında verilebilen ek yetkiler. */
export type ExtraPermissions = { edit: boolean; delete: boolean; share: boolean };
export type Permissions = ExtraPermissions & { view: boolean };

export const NO_EXTRA: ExtraPermissions = { edit: false, delete: false, share: false };
const ALL: Permissions = { view: true, edit: true, delete: true, share: true };

export type Grants = {
  userIds: Id<"users">[];
  departmentIds: Id<"departments">[];
  /** Kural bazında ek yetkiler (anahtar kişi ya da departman kimliği). Eski
   * önbellekte yoktur; yoksa yalnızca görüntüleme. */
  permissions?: Record<string, ExtraPermissions>;
};

export function targetId(target: GrantTarget) {
  return target.kind === "user" ? target.userId : target.departmentId;
}

/** Kuralın ek yetkileri; kural yoksa `null`. */
export function grantOf(grants: Grants | null, target: GrantTarget): ExtraPermissions | null {
  return hasGrant(grants, target) ? (grants?.permissions?.[targetId(target)] ?? NO_EXTRA) : null;
}

export type GrantTarget =
  | { kind: "user"; userId: Id<"users"> }
  | { kind: "department"; departmentId: Id<"departments"> };

/** Çevrimdışıyken yapılıp bağlantı gelince sırayla gönderilen işlemler.
 * Kayıtlar istemcide üretilen `itemId` ile anılır; böylece henüz
 * gönderilmemiş bir kayıt da yetkilendirilebilir. */
export type QueuedOp =
  | { kind: "create"; item: NewItem; folderId?: Id<"folders"> | null }
  | {
      kind: "grant";
      itemId: string;
      target: GrantTarget;
      granted: boolean;
      /** Eski sürümün kuyruğunda yoktur; yoksa mevcut ek yetkiler korunur. */
      permissions?: ExtraPermissions;
    };

type CacheContent = {
  version: 1;
  syncedAt: number | null;
  items: ServerItem[];
  directory: ShareDirectory | null;
  /** Eski sürümün önbelleğinde yoktur. */
  folders?: Folder[];
  queue: QueuedOp[];
};

export type VaultItem = {
  itemId: string;
  /** Sunucudaki kimlik; kayıt henüz gönderilmediyse `null`. */
  id: Id<"items"> | null;
  isOwner: boolean;
  /** Kullanıcının bu kayıt üzerindeki yetkileri. */
  permissions: Permissions;
  /** Bulunduğu klasör; `null` ise kökte. */
  folderId: Id<"folders"> | null;
  encrypted: EncryptedItem;
  /** Sahibin kayıtlarında, kuyruktaki değişikliklerle birlikte paylaşım. */
  grants: Grants | null;
  /** Kayıt ya da paylaşım değişikliği henüz sunucuya gönderilmedi. */
  pendingSync: boolean;
};

const EMPTY: CacheContent = { version: 1, syncedAt: null, items: [], directory: null, queue: [] };

const sameTarget = (a: GrantTarget, b: GrantTarget) =>
  a.kind === "user" && b.kind === "user"
    ? a.userId === b.userId
    : a.kind === "department" && b.kind === "department" && a.departmentId === b.departmentId;

function hasGrant(grants: Grants | null, target: GrantTarget) {
  if (!grants) return false;
  return target.kind === "user"
    ? grants.userIds.includes(target.userId)
    : grants.departmentIds.includes(target.departmentId);
}

function applyGrant(
  grants: Grants,
  target: GrantTarget,
  granted: boolean,
  permissions: ExtraPermissions | undefined,
): Grants {
  const key = targetId(target);
  const map = { ...(grants.permissions ?? {}) };

  if (granted) map[key] = permissions ?? map[key] ?? NO_EXTRA;
  else delete map[key];

  if (target.kind === "user") {
    const others = grants.userIds.filter((id) => id !== target.userId);
    return { ...grants, permissions: map, userIds: granted ? [...others, target.userId] : others };
  }

  const others = grants.departmentIds.filter((id) => id !== target.departmentId);
  return {
    ...grants,
    permissions: map,
    departmentIds: granted ? [...others, target.departmentId] : others,
  };
}

const samePermissions = (a: ExtraPermissions | null, b: ExtraPermissions | null) =>
  a === b || (a !== null && b !== null && a.edit === b.edit && a.delete === b.delete && a.share === b.share);

export function toEncryptedItem(item: ServerItem): EncryptedItem {
  return {
    itemId: item.itemId,
    ownerId: item.ownerId,
    metadata: item.metadata,
    secret: item.secret,
    access: item.access,
  };
}

/**
 * Kasanın kayıtları; çevrimdışı öncelikli.
 *
 * Kayıtlar (sunucudaki şifreli halleriyle) ve paylaşım dizini cihazda
 * şifreli önbellekte tutulur; liste internet olmadan da görüntülenir.
 * Bağlantı varken önbellek sunucudan güncellenir: yeni ve değişen kayıtlar
 * yazılır, silinen ya da erişimi kaldırılanlar önbellekten de çıkar.
 * Yeni kayıt ve yetkilendirme çevrimdışıyken kuyruğa alınır, bağlantı
 * gelince gönderilir. Düzenleme ve silme yalnızca çevrimiçi yapılır.
 */
export function useVaultData({ ownerId, isOnline }: { ownerId: string | null; isOnline: boolean }) {
  const live = ownerId !== null && isOnline;
  const serverItems = useQuery(api.items.listMine, live ? {} : "skip");
  const serverDirectory = useQuery(api.items.shareDirectory, live ? {} : "skip");
  const serverFolders = useQuery(api.folders.list, live ? {} : "skip");

  const createItem = useMutation(api.items.create);
  const setUserGrant = useMutation(api.items.setUserGrant);
  const setDepartmentGrant = useMutation(api.items.setDepartmentGrant);

  const [cache, setCache] = useState<CacheContent | null>(null);
  const [cacheError, setCacheError] = useState("");
  const [syncErrors, setSyncErrors] = useState<string[]>([]);

  useEffect(() => {
    setCache(null);

    if (!ownerId) {
      return;
    }

    let cancelled = false;

    invoke<CacheContent | null>("load_items_cache")
      .then((content) => {
        if (!cancelled) setCache(content?.version === 1 ? content : EMPTY);
      })
      .catch((error: unknown) => {
        // Bozuk önbellek sunucudan yeniden doldurulur.
        if (!cancelled) {
          setCacheError(`Yerel önbellek okunamadı: ${errorMessage(error)}`);
          setCache(EMPTY);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [ownerId]);

  // Sunucu verisi önbellek diskten okunmadan gelirse, okunduktan sonra yazılır.
  const loaded = cache !== null;

  useEffect(() => {
    if (loaded && live && serverItems !== undefined) {
      setCache((current) => current && { ...current, items: serverItems, syncedAt: Date.now() });
    }
  }, [live, loaded, serverItems]);

  useEffect(() => {
    if (loaded && live && serverDirectory !== undefined) {
      setCache((current) => current && { ...current, directory: serverDirectory });
    }
  }, [live, loaded, serverDirectory]);

  useEffect(() => {
    if (loaded && live && serverFolders !== undefined) {
      setCache((current) => current && { ...current, folders: serverFolders });
    }
  }, [live, loaded, serverFolders]);

  useEffect(() => {
    if (!cache) return;

    invoke("save_items_cache", { content: cache }).catch((error: unknown) =>
      setCacheError(`Yerel önbellek yazılamadı: ${errorMessage(error)}`),
    );
  }, [cache]);

  // Kuyruk: işlemler sırayla, tek tek gönderilir. Sunucu bir yetkilendirmeyi
  // reddederse (ör. kişi devre dışı) işlem atılır ve bildirilir. Yeni kayıt
  // hiçbir zaman atılmaz; başarısız olursa sonra tekrar denenir.
  const serverIdsRef = useRef(new Map<string, Id<"items">>());
  const runningRef = useRef(false);
  const [retryTick, setRetryTick] = useState(0);

  useEffect(() => {
    for (const item of serverItems ?? []) {
      serverIdsRef.current.set(item.itemId, item.id);
    }
  }, [serverItems]);

  useEffect(() => {
    const op = cache?.queue[0];

    if (!live || !op || runningRef.current) {
      return;
    }

    runningRef.current = true;

    // Çalışırken kuyruk değişmiş olabilir; işlem kendi referansıyla çıkarılır.
    const removeFirst = () =>
      setCache((current) => current && { ...current, queue: current.queue.filter((o) => o !== op) });
    const report = (message: string) =>
      setSyncErrors((errors) => (errors.includes(message) ? errors : [...errors, message]));

    void (async () => {
      try {
        if (op.kind === "create") {
          serverIdsRef.current.set(
            op.item.itemId,
            await createItem({ ...op.item, folderId: op.folderId ?? undefined }),
          );
          removeFirst();
          return;
        }

        const id = serverIdsRef.current.get(op.itemId);

        if (!id) {
          // Kayıt bu arada silinmiş ya da erişim kalkmış.
          removeFirst();
          return;
        }

        if (op.target.kind === "user") {
          await setUserGrant({
            id,
            userId: op.target.userId,
            granted: op.granted,
            permissions: op.permissions,
          });
        } else {
          await setDepartmentGrant({
            id,
            departmentId: op.target.departmentId,
            granted: op.granted,
            permissions: op.permissions,
          });
        }

        removeFirst();
      } catch (error) {
        if (op.kind === "grant" && error instanceof ConvexError) {
          report(`Çevrimdışı yapılan bir yetkilendirme uygulanamadı: ${errorMessage(error)}`);
          removeFirst();
        } else {
          report(`Gönderilemedi, tekrar denenecek: ${errorMessage(error)}`);
          window.setTimeout(() => setRetryTick((tick) => tick + 1), 30_000);
        }
      } finally {
        runningRef.current = false;
      }
    })();
  }, [cache?.queue, createItem, live, retryTick, setDepartmentGrant, setUserGrant]);

  const baseItems = live && serverItems !== undefined ? serverItems : (cache?.items ?? []);
  const queue = useMemo(() => cache?.queue ?? [], [cache?.queue]);

  const items = useMemo<VaultItem[]>(() => {
    const result = new Map<string, VaultItem>();

    for (const item of baseItems) {
      result.set(item.itemId, {
        itemId: item.itemId,
        id: item.id,
        isOwner: item.isOwner,
        // Eski önbellekte yoktur: sahibe her şey, diğerlerine görüntüleme.
        permissions: item.permissions ?? (item.isOwner ? ALL : { ...NO_EXTRA, view: true }),
        folderId: item.folderId ?? null,
        encrypted: toEncryptedItem(item),
        grants: item.grants,
        pendingSync: false,
      });
    }

    for (const op of queue) {
      if (op.kind === "create" && !result.has(op.item.itemId) && ownerId) {
        result.set(op.item.itemId, {
          itemId: op.item.itemId,
          id: null,
          isOwner: true,
          permissions: ALL,
          folderId: op.folderId ?? null,
          encrypted: {
            itemId: op.item.itemId,
            ownerId,
            metadata: op.item.metadata,
            secret: op.item.secret,
            access: { kind: "direct", access: op.item.ownerAccess },
          },
          grants: { userIds: [], departmentIds: [] },
          pendingSync: true,
        });
      } else if (op.kind === "grant") {
        const item = result.get(op.itemId);

        if (item?.grants) {
          result.set(op.itemId, {
            ...item,
            grants: applyGrant(item.grants, op.target, op.granted, op.permissions),
            pendingSync: true,
          });
        }
      }
    }

    return [...result.values()];
  }, [baseItems, ownerId, queue]);

  const addItem = useCallback((item: NewItem, folderId: Id<"folders"> | null = null) => {
    setCache(
      (current) =>
        current && { ...current, queue: [...current.queue, { kind: "create", item, folderId }] },
    );
  }, []);

  /** Kuralı ekler/kaldırır; `permissions` verilirse ek yetkileri de ayarlar. */
  const setGrant = useCallback(
    (itemId: string, target: GrantTarget, granted: boolean, permissions?: ExtraPermissions) => {
      setCache((current) => {
        if (!current) return current;

        const queue = current.queue.filter(
          (op) => !(op.kind === "grant" && op.itemId === itemId && sameTarget(op.target, target)),
        );

        // Geri alınan bir değişiklik kuyruktan düşer; sunucudaki hali zaten bu.
        const base = current.items.find((item) => item.itemId === itemId);
        const before = base ? grantOf(base.grants, target) : undefined;
        const after = granted ? (permissions ?? before ?? NO_EXTRA) : null;
        const unchanged = before !== undefined && samePermissions(before, after);

        return {
          ...current,
          queue: unchanged
            ? queue
            : [...queue, { kind: "grant", itemId, target, granted, permissions }],
        };
      });
    },
    [],
  );

  return {
    loaded,
    items,
    directory: (live ? serverDirectory : undefined) ?? cache?.directory ?? null,
    folders: (live ? serverFolders : undefined) ?? cache?.folders ?? [],
    syncedAt: cache?.syncedAt ?? null,
    queue,
    errors: [cacheError, ...syncErrors].filter(Boolean),
    dismissErrors: () => {
      setCacheError("");
      setSyncErrors([]);
    },
    addItem,
    setGrant,
  };
}

export type VaultData = ReturnType<typeof useVaultData>;
