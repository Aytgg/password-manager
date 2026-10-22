import { useCallback, useEffect, useMemo, useState } from "react";
import type React from "react";
import { invoke } from "@tauri-apps/api/core";
import { useConvexAuth, useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";

import { api } from "../convex/_generated/api";
import type { Id } from "../convex/_generated/dataModel";

type ServerItem = FunctionReturnType<typeof api.items.listMine>[number];

type SealedField = { nonce: string; ciphertext: string };

type WrappedKey = {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
};

// Rust komutlarının beklediği şekil (vault/items.rs: EncryptedItem).
type EncryptedItem = {
  itemId: string;
  ownerId: string;
  metadata: SealedField;
  secret: SealedField;
  access: WrappedKey;
};

type NewItem = {
  itemId: string;
  metadata: SealedField;
  secret: SealedField;
  ownerAccess: WrappedKey;
};

type RekeyedItem = {
  metadata: SealedField;
  secret: SealedField;
  accesses: { userId: string; access: WrappedKey }[];
};

type DecryptedMetadata = {
  itemId: string;
  title: string | null;
  username: string | null;
  error: string | null;
};

type PasswordItem = {
  id: Id<"items">;
  title: string;
  username: string | null;
  is_owner: boolean;
  decryptError: string | null;
  server: ServerItem;
};

type PasswordAccessUser = {
  id: string;
  email: string;
  display_name: string;
  has_access: boolean;
};

type PasswordManagerProps = {
  isUnlocked: boolean;
  getSessionToken: () => Promise<string>;
};

function toEncryptedItem(item: ServerItem): EncryptedItem {
  return {
    itemId: item.itemId,
    ownerId: item.ownerId,
    metadata: item.metadata,
    secret: item.secret,
    access: item.access,
  };
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    background: "#111318",
    color: "#e5e7eb",
    border: "1px solid #292d36",
    borderRadius: 14,
    padding: 24,
    marginTop: 24,
  },
  input: {
    width: "100%",
    boxSizing: "border-box",
    background: "#1b1f27",
    color: "#f3f4f6",
    border: "1px solid #353b48",
    borderRadius: 8,
    padding: "11px 12px",
    marginTop: 6,
    marginBottom: 14,
  },
  button: {
    background: "#6366f1",
    color: "#fff",
    border: 0,
    borderRadius: 8,
    padding: "10px 16px",
    cursor: "pointer",
  },
  secondaryButton: {
    background: "#292d36",
    color: "#e5e7eb",
    border: "1px solid #353b48",
    borderRadius: 8,
    padding: "9px 12px",
    cursor: "pointer",
  },
  card: {
    background: "#1b1f27",
    border: "1px solid #353b48",
    borderRadius: 10,
    padding: 16,
  },
  muted: {
    color: "#9ca3af",
  },
  error: {
    color: "#f87171",
    overflowWrap: "anywhere",
  },
  success: {
    color: "#4ade80",
    overflowWrap: "anywhere",
  },
};

export default function PasswordManager({
  isUnlocked,
  getSessionToken,
}: PasswordManagerProps) {
  // Convex oturumu Clerk token'ı ile kurulana kadar sorgular bekletilir;
  // aksi halde sunucu kimliksiz isteği reddeder.
  const { isAuthenticated: isConvexAuthenticated, isLoading: isConvexAuthLoading } =
    useConvexAuth();
  const isReady = isUnlocked && isConvexAuthenticated;

  // Convex sorguları canlıdır; sunucudaki değişiklikler otomatik gelir.
  const serverItems = useQuery(api.items.listMine, isReady ? {} : "skip");
  const otherUsers = useQuery(api.users.listOthers, isReady ? {} : "skip");

  const createItem = useMutation(api.items.create);
  const grantAccess = useMutation(api.items.grant);
  const rekeyItem = useMutation(api.items.rekey);

  const [metadataByItemId, setMetadataByItemId] = useState<
    Record<string, DecryptedMetadata>
  >({});
  const [decryptVersion, setDecryptVersion] = useState(0);

  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [copyingPasswordId, setCopyingPasswordId] = useState<string | null>(
    null,
  );

  const [openAuthorizationPasswordId, setOpenAuthorizationPasswordId] =
    useState<Id<"items"> | null>(null);

  const openAccessList = useQuery(
    api.items.accessList,
    isReady && openAuthorizationPasswordId
      ? { id: openAuthorizationPasswordId }
      : "skip",
  );

  // Sunucuya henüz kaydedilmemiş erişim kaldırma seçimleri.
  const [pendingRevocationsByPassword, setPendingRevocationsByPassword] =
    useState<Record<string, string[]>>({});

  const [updatingAccessKeys, setUpdatingAccessKeys] = useState<string[]>([]);
  const [savingRekeyPasswordId, setSavingRekeyPasswordId] = useState<
    string | null
  >(null);

  // Başlık ve kullanıcı adı şifreli geldiği için liste her değiştiğinde
  // meta veri Rust tarafında çözülür. Parolaların kendisi çözülmez.
  useEffect(() => {
    if (!isReady || !serverItems) {
      setMetadataByItemId({});
      return;
    }

    let cancelled = false;

    async function decryptMetadata() {
      try {
        const result = await invoke<DecryptedMetadata[]>(
          "decrypt_items_metadata",
          {
            sessionToken: await getSessionToken(),
            items: serverItems!.map(toEncryptedItem),
          },
        );

        if (!cancelled) {
          setMetadataByItemId(
            Object.fromEntries(result.map((entry) => [entry.itemId, entry])),
          );
        }
      } catch (err) {
        if (!cancelled) {
          setError(String(err));
        }
      }
    }

    void decryptMetadata();

    return () => {
      cancelled = true;
    };
  }, [decryptVersion, getSessionToken, isReady, serverItems]);

  const items = useMemo<PasswordItem[]>(() => {
    if (!serverItems) {
      return [];
    }

    return serverItems
      .map((item) => {
        const metadata = metadataByItemId[item.itemId];

        return {
          id: item.id,
          title: metadata?.title ?? (metadata?.error ? "Çözülemedi" : "…"),
          username: metadata?.username ?? null,
          is_owner: item.isOwner,
          decryptError: metadata?.error ?? null,
          server: item,
        };
      })
      .sort(
        (a, b) =>
          a.title.localeCompare(b.title, "tr", { sensitivity: "base" }) ||
          a.id.localeCompare(b.id),
      );
  }, [metadataByItemId, serverItems]);

  const accessUsersByPassword = useMemo<
    Record<string, PasswordAccessUser[]>
  >(() => {
    if (!openAuthorizationPasswordId || !openAccessList || !otherUsers) {
      return {};
    }

    return {
      [openAuthorizationPasswordId]: otherUsers.map((user) => ({
        id: user.userId,
        email: user.email,
        display_name: user.displayName,
        has_access: openAccessList.includes(user.userId),
      })),
    };
  }, [openAccessList, openAuthorizationPasswordId, otherUsers]);

  const loadingAccessPasswordId =
    openAuthorizationPasswordId &&
    (openAccessList === undefined || otherUsers === undefined)
      ? openAuthorizationPasswordId
      : null;

  const findItem = useCallback(
    (passwordId: string) => items.find((item) => item.id === passwordId),
    [items],
  );

  const refreshPasswords = useCallback(async () => {
    setError("");
    setDecryptVersion((version) => version + 1);
  }, []);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!title.trim() || !password) {
      setError("Başlık ve parola alanları zorunludur.");
      return;
    }

    setLoading(true);
    setError("");
    setSuccess("");

    try {
      const sessionToken = await getSessionToken();

      // Şifreleme Rust'ta yapılır; Convex'e yalnızca şifreli veri gider.
      const encrypted = await invoke<NewItem>("encrypt_new_item", {
        sessionToken,
        title: title.trim(),
        username: username.trim() || null,
        password,
      });

      await createItem(encrypted);

      setTitle("");
      setUsername("");
      setPassword("");

      setSuccess("Parola şifrelenerek kasaya kaydedildi.");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleCopyPassword(passwordId: string) {
    if (copyingPasswordId !== null) {
      return;
    }

    const item = findItem(passwordId);

    if (!item) {
      setError("Parola bulunamadı.");
      return;
    }

    setCopyingPasswordId(passwordId);
    setError("");
    setSuccess("");

    try {
      const sessionToken = await getSessionToken();

      await invoke("copy_item_password_to_clipboard", {
        sessionToken,
        item: toEncryptedItem(item.server),
      });

      setSuccess(
        "Parola panoya kopyalandı. 30 saniye sonra otomatik temizlenmesi denenecek.",
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setCopyingPasswordId(null);
    }
  }

  function handleOpenAuthorization(passwordId: Id<"items">) {
    const currentOpenId = openAuthorizationPasswordId;

    if (currentOpenId === passwordId) {
      const pending = pendingRevocationsByPassword[passwordId] ?? [];

      if (pending.length > 0) {
        setError(
          "Kaydedilmemiş erişim kaldırmaları var. Önce Kaydet veya Vazgeç seçeneğini kullan.",
        );
        return;
      }

      setOpenAuthorizationPasswordId(null);
      setError("");
      return;
    }

    if (currentOpenId) {
      const currentPending = pendingRevocationsByPassword[currentOpenId] ?? [];

      if (currentPending.length > 0) {
        setError(
          "Önce mevcut parola için bekleyen erişim değişikliklerini kaydet veya iptal et.",
        );
        return;
      }
    }

    setOpenAuthorizationPasswordId(passwordId);
    setError("");
    setSuccess("");
  }

  async function handleAccessToggle(
    passwordId: string,
    recipientUserId: string,
    grantAccess_: boolean,
  ) {
    const updateKey = `${passwordId}:${recipientUserId}`;

    if (
      updatingAccessKeys.includes(updateKey) ||
      savingRekeyPasswordId === passwordId
    ) {
      return;
    }

    const targetUser = accessUsersByPassword[passwordId]?.find(
      (user) => user.id === recipientUserId,
    );
    const recipient = otherUsers?.find((user) => user.userId === recipientUserId);
    const item = findItem(passwordId);

    if (!targetUser || !recipient || !item) {
      setError("Kullanıcının mevcut erişim durumu bulunamadı.");
      return;
    }

    setError("");
    setSuccess("");

    // Hâlihazırda erişimi olan kullanıcı için değişiklik taslak olarak tutulur.
    if (targetUser.has_access) {
      setPendingRevocationsByPassword((previous) => {
        const current = previous[passwordId] ?? [];

        const next = grantAccess_
          ? current.filter((id) => id !== recipientUserId)
          : current.includes(recipientUserId)
            ? current
            : [...current, recipientUserId];

        return {
          ...previous,
          [passwordId]: next,
        };
      });

      return;
    }

    // Erişimi olmayan bir kullanıcının kutucuğu tekrar kapatılmışsa işlem yok.
    if (!grantAccess_) {
      return;
    }

    // Yetki verme hemen uygulanır: Rust, kaydın DEK'ini alıcının açık
    // anahtarına paketler; Convex'e yalnızca paketlenmiş anahtar gider.
    setUpdatingAccessKeys((previous) => [...previous, updateKey]);

    try {
      const sessionToken = await getSessionToken();

      const access = await invoke<WrappedKey>("wrap_item_key_for_recipient", {
        sessionToken,
        item: toEncryptedItem(item.server),
        recipientPublicKey: recipient.publicKey,
      });

      await grantAccess({
        id: item.id,
        keyVersion: item.server.keyVersion,
        recipientId: recipientUserId,
        access,
      });

      setSuccess(`${targetUser.display_name} için erişim etkinleştirildi.`);
    } catch (err) {
      setError(String(err));
    } finally {
      setUpdatingAccessKeys((previous) =>
        previous.filter((key) => key !== updateKey),
      );
    }
  }

  async function handleSaveRevocations(passwordId: string) {
    if (savingRekeyPasswordId !== null) {
      return;
    }

    const revokedUserIds = pendingRevocationsByPassword[passwordId] ?? [];
    const item = findItem(passwordId);

    if (revokedUserIds.length === 0 || !item || !openAccessList || !otherUsers) {
      return;
    }

    setSavingRekeyPasswordId(passwordId);
    setError("");
    setSuccess("");

    try {
      // Erişimi kalacak kullanıcılar ve açık anahtarları.
      const recipients = openAccessList
        .filter((userId) => !revokedUserIds.includes(userId))
        .map((userId) => {
          const user = otherUsers.find((candidate) => candidate.userId === userId);

          if (!user) {
            throw new Error(`${userId} kullanıcısının açık anahtarı bulunamadı.`);
          }

          return { userId, publicKey: user.publicKey };
        });

      const sessionToken = await getSessionToken();

      // Parola yeni bir DEK ile yeniden şifrelenir; kaldırılan kullanıcıların
      // elindeki eski anahtar yeni veriyi açamaz.
      const rekeyed = await invoke<RekeyedItem>("rekey_item", {
        sessionToken,
        item: toEncryptedItem(item.server),
        recipients,
      });

      await rekeyItem({
        id: item.id,
        keyVersion: item.server.keyVersion,
        ...rekeyed,
      });

      setPendingRevocationsByPassword((previous) => ({
        ...previous,
        [passwordId]: [],
      }));

      setSuccess(
        `${revokedUserIds.length} erişim kaldırıldı. Parola yeni bir DEK ile yeniden şifrelendi. Kaldırılan kişiler parolayı daha önce görmüş olabilir; gerekirse parolanın kendisini de değiştir.`,
      );
    } catch (err) {
      // Taslak seçimleri koru; kullanıcı tekrar deneyebilir.
      setError(
        `Erişimler kaldırılamadı. Değişiklikler kaydedilmedi: ${String(err)}`,
      );
    } finally {
      setSavingRekeyPasswordId(null);
    }
  }

  function handleDiscardRevocations(passwordId: string) {
    if (savingRekeyPasswordId === passwordId) {
      return;
    }

    setPendingRevocationsByPassword((previous) => ({
      ...previous,
      [passwordId]: [],
    }));

    setError("");
    setSuccess("Kaydedilmemiş erişim kaldırma seçimleri iptal edildi.");
  }

  if (!isUnlocked) {
    return (
      <section style={styles.page}>
        Kasayı açtıktan sonra parola yönetimini kullanabilirsin.
      </section>
    );
  }

  if (!isConvexAuthenticated) {
    return (
      <section style={styles.page}>
        {isConvexAuthLoading
          ? "Sunucu bağlantısı kuruluyor..."
          : "Sunucu oturumu doğrulanamadı. Clerk'teki Convex entegrasyonunu kontrol et."}
      </section>
    );
  }

  return (
    <section style={styles.page}>
      <h2 style={{ marginTop: 0 }}>Parola kasası</h2>

      <p style={styles.muted}>
        Parolalar bu cihazda şifrelenir; sunucuya yalnızca şifreli veri gönderilir.
      </p>

      <form onSubmit={handleSubmit}>
        <label htmlFor="password-title">Başlık</label>
        <input
          id="password-title"
          style={styles.input}
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Örn. E-posta"
          required
        />

        <label htmlFor="password-username">Kullanıcı adı (isteğe bağlı)</label>
        <input
          id="password-username"
          style={styles.input}
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          placeholder="kullanici@example.com"
        />

        <label htmlFor="password-value">Parola</label>
        <input
          id="password-value"
          type="password"
          autoComplete="new-password"
          style={styles.input}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />

        <button
          style={{
            ...styles.button,
            opacity: loading ? 0.6 : 1,
          }}
          type="submit"
          disabled={loading}
        >
          {loading ? "Kaydediliyor..." : "Parolayı kaydet"}
        </button>
      </form>

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}

      {success && (
        <p role="status" style={styles.success}>
          {success}
        </p>
      )}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 12,
          flexWrap: "wrap",
          marginTop: 32,
        }}
      >
        <h3 style={{ margin: 0 }}>Kayıtlı parolalar ({items.length})</h3>

        <button
          type="button"
          style={styles.secondaryButton}
          onClick={() => void refreshPasswords()}
        >
          Yenile
        </button>
      </div>

      {items.length === 0 ? (
        <p style={styles.muted}>Henüz erişimin olan bir parola yok.</p>
      ) : (
        <div style={{ display: "grid", gap: 12, marginTop: 16 }}>
          {items.map((item) => {
            const isAuthorizationOpen = openAuthorizationPasswordId === item.id;

            const accessUsers = accessUsersByPassword[item.id] ?? [];
            const isLoadingAccess = loadingAccessPasswordId === item.id;

            const pendingRevocations =
              pendingRevocationsByPassword[item.id] ?? [];

            const isSavingRekey = savingRekeyPasswordId === item.id;

            return (
              <article key={item.id} style={styles.card}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    flexWrap: "wrap",
                    gap: 12,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <strong>{item.title}</strong>

                    <p style={{ ...styles.muted, marginBottom: 0 }}>
                      {item.username || "Kullanıcı adı belirtilmemiş"}
                    </p>

                    {!item.is_owner && (
                      <p
                        style={{
                          color: "#a5b4fc",
                          fontSize: 12,
                          marginBottom: 0,
                        }}
                      >
                        Seninle paylaşılmış
                      </p>
                    )}
                  </div>

                  <div
                    style={{
                      display: "flex",
                      gap: 8,
                      flexWrap: "wrap",
                    }}
                  >
                    <button
                      type="button"
                      style={{
                        ...styles.secondaryButton,
                        opacity: copyingPasswordId !== null ? 0.6 : 1,
                        cursor: copyingPasswordId !== null ? "wait" : "pointer",
                      }}
                      onClick={() => void handleCopyPassword(item.id)}
                      disabled={copyingPasswordId !== null}
                    >
                      {copyingPasswordId === item.id
                        ? "Kopyalanıyor..."
                        : "Use Password"}
                    </button>

                    {item.is_owner && (
                      <button
                        type="button"
                        style={{
                          ...styles.button,
                          background: isAuthorizationOpen
                            ? "#4b5563"
                            : "#6366f1",
                        }}
                        onClick={() => handleOpenAuthorization(item.id)}
                        aria-expanded={isAuthorizationOpen}
                      >
                        Yetkilendirme
                      </button>
                    )}
                  </div>
                </div>

                {item.is_owner && isAuthorizationOpen && (
                  <div
                    style={{
                      marginTop: 18,
                      paddingTop: 16,
                      borderTop: "1px solid #353b48",
                    }}
                  >
                    <h4 style={{ marginTop: 0, marginBottom: 8 }}>
                      Parolayı kullanabilecek kişiler
                    </h4>

                    <p style={{ ...styles.muted, fontSize: 13 }}>
                      Yetki verme hemen uygulanır. Yetki kaldırma seçimleri
                      Kaydet düğmesine basılana kadar bekletilir.
                    </p>

                    {isLoadingAccess ? (
                      <p style={styles.muted}>Erişim listesi yükleniyor...</p>
                    ) : accessUsers.length === 0 ? (
                      <p style={styles.muted}>
                        Yetkilendirilebilecek başka kullanıcı yok.
                      </p>
                    ) : (
                      <div style={{ display: "grid", gap: 12 }}>
                        {accessUsers.map((user) => {
                          const updateKey = `${item.id}:${user.id}`;

                          const isUpdating =
                            updatingAccessKeys.includes(updateKey);

                          const isPendingRevocation =
                            pendingRevocations.includes(user.id);

                          const isChecked =
                            user.has_access && !isPendingRevocation;

                          return (
                            <div
                              key={user.id}
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                gap: 12,
                                padding: "12px 0",
                                borderBottom: "1px solid #292d36",
                              }}
                            >
                              <div style={{ minWidth: 0 }}>
                                <div>{user.display_name}</div>

                                <div
                                  style={{
                                    ...styles.muted,
                                    fontSize: 12,
                                    overflowWrap: "anywhere",
                                  }}
                                >
                                  {user.email}
                                </div>

                                <div
                                  style={{
                                    color: isUpdating
                                      ? "#fbbf24"
                                      : isPendingRevocation
                                        ? "#fbbf24"
                                        : user.has_access
                                          ? "#4ade80"
                                          : "#9ca3af",
                                    fontSize: 12,
                                    marginTop: 4,
                                  }}
                                >
                                  {isUpdating
                                    ? "Güncelleniyor..."
                                    : isPendingRevocation
                                      ? "Erişimi kaldırılacak — kaydedilmedi"
                                      : user.has_access
                                        ? "Erişim açık"
                                        : "Erişim kapalı"}
                                </div>
                              </div>

                              <label
                                style={{
                                  position: "relative",
                                  display: "inline-flex",
                                  alignItems: "center",
                                  flexShrink: 0,
                                  cursor:
                                    isUpdating || isSavingRekey
                                      ? "wait"
                                      : "pointer",
                                  opacity:
                                    isUpdating || isSavingRekey ? 0.6 : 1,
                                }}
                                title={
                                  isChecked
                                    ? "Yetki kaldırma işlemini taslak olarak işaretle"
                                    : isPendingRevocation
                                      ? "Bekleyen kaldırma işlemini iptal et"
                                      : "Yetki ver"
                                }
                              >
                                <input
                                  type="checkbox"
                                  role="switch"
                                  aria-label={`${user.display_name} için parola erişimi`}
                                  checked={isChecked}
                                  disabled={isUpdating || isSavingRekey}
                                  onChange={(event) =>
                                    void handleAccessToggle(
                                      item.id,
                                      user.id,
                                      event.target.checked,
                                    )
                                  }
                                  style={{
                                    position: "absolute",
                                    opacity: 0,
                                    width: 1,
                                    height: 1,
                                    margin: 0,
                                  }}
                                />

                                <span
                                  aria-hidden="true"
                                  style={{
                                    width: 44,
                                    height: 25,
                                    borderRadius: 999,
                                    padding: 3,
                                    boxSizing: "border-box",
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: isChecked
                                      ? "flex-end"
                                      : "flex-start",
                                    background: isChecked
                                      ? "#6366f1"
                                      : "#4b5563",
                                    border: "1px solid #606777",
                                    transition: "background 150ms ease",
                                  }}
                                >
                                  <span
                                    style={{
                                      display: "block",
                                      width: 17,
                                      height: 17,
                                      background: "#ffffff",
                                      borderRadius: "50%",
                                      boxShadow: "0 1px 3px #0006",
                                    }}
                                  />
                                </span>
                              </label>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {pendingRevocations.length > 0 && (
                      <div
                        style={{
                          marginTop: 18,
                          padding: 14,
                          background: "#292419",
                          border: "1px solid #66512b",
                          borderRadius: 9,
                        }}
                      >
                        <p
                          style={{
                            color: "#fbbf24",
                            fontSize: 13,
                            marginTop: 0,
                            marginBottom: 12,
                          }}
                        >
                          {pendingRevocations.length} kullanıcının erişimi
                          kaldırılmak üzere. Kaydet işleminde parola yeni bir
                          DEK ile yeniden şifrelenecek.
                        </p>

                        <div
                          style={{
                            display: "flex",
                            gap: 8,
                            flexWrap: "wrap",
                          }}
                        >
                          <button
                            type="button"
                            style={{
                              ...styles.button,
                              opacity: isSavingRekey ? 0.6 : 1,
                              cursor: isSavingRekey ? "wait" : "pointer",
                            }}
                            disabled={isSavingRekey}
                            onClick={() => void handleSaveRevocations(item.id)}
                          >
                            {isSavingRekey
                              ? "Re-keying yapılıyor..."
                              : "Değişiklikleri kaydet"}
                          </button>

                          <button
                            type="button"
                            style={{
                              ...styles.secondaryButton,
                              opacity: isSavingRekey ? 0.6 : 1,
                            }}
                            disabled={isSavingRekey}
                            onClick={() => handleDiscardRevocations(item.id)}
                          >
                            Vazgeç
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
