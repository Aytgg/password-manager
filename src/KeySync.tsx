import { invoke } from "@tauri-apps/api/core";
import { useConvex, useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useEffect, useRef, useState } from "react";

import { api } from "../convex/_generated/api";
import type { Id } from "../convex/_generated/dataModel";
import { errorMessage } from "./errors";

type WrappedKey = { ephemeralPublicKey: string; nonce: string; ciphertext: string };
type UserAccess = { userId: Id<"users">; access: WrappedKey };
type DepartmentAccess = { departmentId: Id<"departments">; keyVersion: number; access: WrappedKey };

type ItemWork = FunctionReturnType<typeof api.items.pendingWork>;
type DepartmentWork = FunctionReturnType<typeof api.keys.pendingWork>;
type ServerItem = ItemWork["fills"][number]["item"];

function toEncryptedItem(item: ServerItem) {
  return {
    itemId: item.itemId,
    ownerId: item.ownerId,
    metadata: item.metadata,
    secret: item.secret,
    access: item.access,
  };
}

/**
 * Sunucudaki iş listesini, aynı anda tek çalışma olacak şekilde işler. Hata
 * olursa sonsuz döngüye girmemek için bir sonraki sunucu değişikliği beklenir.
 */
function useWorker<T>(
  work: T | undefined,
  isEmpty: (work: T) => boolean,
  run: (work: T) => Promise<void>,
  onError: (message: string) => void,
) {
  const runningRef = useRef(false);
  const [tick, setTick] = useState(0);
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    if (!work || runningRef.current || isEmpty(work)) {
      return;
    }

    runningRef.current = true;

    runRef
      .current(work)
      .then(() => {
        onError("");
        setTick((value) => value + 1);
      })
      .catch((error: unknown) => onError(errorMessage(error)))
      .finally(() => {
        runningRef.current = false;
      });
    // isEmpty ve onError sabit kabul edilir.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [work, tick]);
}

type Props = {
  /** Sunucu oturumu açık ve kasanın sahibiyle eşleşiyor. */
  enabled: boolean;
  serverPublicKey: string | null;
  /** Son hata; başarılı bir çalışmadan sonra boş metinle temizlenir. */
  onError: (message: string) => void;
};

/**
 * Arka plan anahtar işleri. Uygulama açık olduğu sürece (hangi ekranda
 * olursa olsun) çalışır:
 * 1. Bu cihazın kimliğini sunucuya kaydeder; davetle kaydolan kullanıcıda,
 *    davet koduna paketlenmiş anahtarları kalıcı kimliğe taşır.
 * 2. Departman anahtarlarını oluşturur, yeni sahiplere dağıtır, bir sahip
 *    çıkarıldığında yeniler.
 * 3. Kayıt anahtarlarını kurala göre eksik kişi ve departmanlara paketler;
 *    erişimi kaldırılmış kayıtları yeni bir DEK ile yeniden şifreler.
 */
export default function KeySync({ enabled, serverPublicKey, onError }: Props) {
  const convex = useConvex();
  const setPublicKey = useMutation(api.users.setPublicKey);
  const rotateKey = useMutation(api.users.rotateKey);

  const initDepartmentKey = useMutation(api.keys.initDepartmentKey);
  const addDepartmentKeys = useMutation(api.keys.addDepartmentKeys);
  const rotateDepartmentKey = useMutation(api.keys.rotateDepartmentKey);
  const addAccesses = useMutation(api.items.addAccesses);
  const rekeyItem = useMutation(api.items.rekey);

  const [identityReady, setIdentityReady] = useState(false);

  useEffect(() => {
    if (!enabled) {
      setIdentityReady(false);
      return;
    }

    let cancelled = false;

    async function syncIdentity() {
      const localPublicKey = await invoke<string>("get_identity_public_key");
      const invitePublicKey = await invoke<string | null>("pending_invite_key");

      if (invitePublicKey && serverPublicKey === invitePublicKey) {
        // Davetle kayıt: geçici anahtara paketlenmiş her şey kalıcı kimliğe
        // taşınır. Liste eksiksiz olmalı; arada yeni paylaşım olursa sunucu
        // reddeder ve bir sonraki çalışmada tekrar denenir.
        const keys = await convex.query(api.users.myWrappedKeys, {});
        const rewrapped = await invoke<{ id: string; access: WrappedKey }[]>("rewrap_invite_keys", {
          keys: [...keys.itemAccesses, ...keys.departmentKeys],
        });
        const byId = new Map(rewrapped.map((entry) => [entry.id, entry.access]));

        await rotateKey({
          fromPublicKey: invitePublicKey,
          publicKey: localPublicKey,
          itemAccesses: keys.itemAccesses.map((entry) => ({ id: entry.id, access: byId.get(entry.id)! })),
          departmentKeys: keys.departmentKeys.map((entry) => ({
            id: entry.id,
            access: byId.get(entry.id)!,
          })),
        });
        await invoke("finish_invite_rotation");
        return;
      }

      if (invitePublicKey) {
        // Taşıma tamamlanmış ya da davet yenilenmiş; geçici kimlik artık
        // işe yaramaz.
        await invoke("finish_invite_rotation");
      }

      if (serverPublicKey !== localPublicKey) {
        await setPublicKey({ publicKey: localPublicKey });
        return;
      }

      if (!cancelled) {
        onError("");
        setIdentityReady(true);
      }
    }

    syncIdentity().catch((error: unknown) => {
      if (!cancelled) onError(`Kimlik anahtarı eşitlenemedi: ${errorMessage(error)}`);
    });

    return () => {
      cancelled = true;
    };
  }, [convex, enabled, onError, rotateKey, serverPublicKey, setPublicKey]);

  const active = enabled && identityReady;
  const departmentWork = useQuery(api.keys.pendingWork, active ? {} : "skip");
  const itemWork = useQuery(api.items.pendingWork, active ? {} : "skip");

  useWorker<DepartmentWork>(
    departmentWork,
    (work) => work.inits.length + work.fills.length + work.rotations.length === 0,
    async (work) => {
      for (const task of work.inits) {
        const created = await invoke<{ publicKey: string; accesses: UserAccess[] }>(
          "create_department_key",
          { holders: task.holders },
        );

        await initDepartmentKey({ departmentId: task.departmentId, ...created });
      }

      for (const task of work.fills) {
        const accesses = await invoke<UserAccess[]>("wrap_department_key", {
          key: task.key,
          recipients: task.recipients,
        });

        await addDepartmentKeys({
          departmentId: task.departmentId,
          keyVersion: task.keyVersion,
          accesses,
        });
      }

      for (const task of work.rotations) {
        const rotated = await invoke<{
          publicKey: string;
          accesses: UserAccess[];
          itemKeys: { item: Id<"items">; access: WrappedKey }[];
        }>("rotate_department_key", {
          key: task.key,
          holders: task.holders,
          itemKeys: task.itemKeys,
        });

        await rotateDepartmentKey({
          departmentId: task.departmentId,
          keyVersion: task.keyVersion,
          ...rotated,
        });
      }
    },
    (message) => onError(`Departman anahtarı eşitlenemedi: ${message}`),
  );

  useWorker<ItemWork>(
    itemWork,
    (work) => work.fills.length + work.rekeys.length === 0,
    async (work) => {
      for (const task of work.rekeys) {
        const rekeyed = await invoke<{
          metadata: ServerItem["metadata"];
          secret: ServerItem["secret"];
          accesses: UserAccess[];
          departmentAccesses: DepartmentAccess[];
        }>("rekey_item", {
          item: toEncryptedItem(task.item),
          recipients: task.recipients,
          departmentRecipients: task.departments,
        });

        await rekeyItem({ id: task.item.id, keyVersion: task.item.keyVersion, ...rekeyed });
      }

      for (const task of work.fills) {
        const item = toEncryptedItem(task.item);
        const accesses: UserAccess[] = [];
        const departmentAccesses: DepartmentAccess[] = [];

        for (const recipient of task.recipients) {
          accesses.push({
            userId: recipient.userId,
            access: await invoke<WrappedKey>("wrap_item_key_for_recipient", {
              item,
              recipientPublicKey: recipient.publicKey,
            }),
          });
        }

        for (const department of task.departments) {
          departmentAccesses.push({
            departmentId: department.departmentId,
            keyVersion: department.keyVersion,
            access: await invoke<WrappedKey>("wrap_item_key_for_recipient", {
              item,
              recipientPublicKey: department.publicKey,
            }),
          });
        }

        await addAccesses({
          id: task.item.id,
          keyVersion: task.item.keyVersion,
          accesses,
          departmentAccesses,
        });
      }
    },
    (message) => onError(`Anahtar paylaşımı başarısız: ${message}`),
  );

  return null;
}
