import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type React from "react";
import { invoke } from "@tauri-apps/api/core";
import { useConvexAuth, useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";

import { api } from "../convex/_generated/api";
import type { Id } from "../convex/_generated/dataModel";
import { errorMessage } from "./errors";

type ServerItem = FunctionReturnType<typeof api.items.listMine>[number];

type SealedField = { nonce: string; ciphertext: string };

type WrappedKey = {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
};

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
  isOwner: boolean;
  server: ServerItem;
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
  accessRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
    padding: "12px 0",
    borderBottom: "1px solid #292d36",
  },
};

function Toggle({
  checked,
  disabled,
  label,
  onChange,
}: {
  checked: boolean;
  disabled: boolean;
  label: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
        flexShrink: 0,
        cursor: disabled ? "wait" : "pointer",
        opacity: disabled ? 0.6 : 1,
      }}
    >
      <input
        type="checkbox"
        role="switch"
        aria-label={label}
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
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
          justifyContent: checked ? "flex-end" : "flex-start",
          background: checked ? "#6366f1" : "#4b5563",
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
  );
}

/**
 * Bir parolanın departman ve kişi bazındaki paylaşım kuralları. Değişiklikler
 * hemen uygulanır; anahtar dağıtımı ve erişim kaldırıldığında yeniden
 * şifreleme arka planda otomatik yapılır.
 */
function SharingPanel({ id }: { id: Id<"items"> }) {
  const sharing = useQuery(api.items.sharing, { id });
  const setUserGrant = useMutation(api.items.setUserGrant);
  const setDepartmentGrant = useMutation(api.items.setDepartmentGrant);

  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function update(key: string, granted: boolean, task: () => Promise<unknown>) {
    if (busyKey) return;

    setBusyKey(key);
    setError("");
    setNotice("");

    try {
      await task();

      if (!granted) {
        setNotice(
          "Erişim kaldırıldı; parola yeni bir anahtarla yeniden şifreleniyor. Kaldırılan kişi parolayı daha önce görmüş olabilir; gerekirse parolanın kendisini değiştir.",
        );
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusyKey(null);
    }
  }

  if (sharing === undefined) {
    return <p style={styles.muted}>Erişim listesi yükleniyor...</p>;
  }

  return (
    <div>
      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}
      {notice && (
        <p role="status" style={{ ...styles.muted, fontSize: 13 }}>
          {notice}
        </p>
      )}

      <h4 style={{ marginTop: 0, marginBottom: 4 }}>Departmanlar</h4>
      <p style={{ ...styles.muted, fontSize: 13, marginTop: 0 }}>
        Departmana verilen erişim, departmana sonradan katılanları da kapsar.
      </p>

      {sharing.departments.length === 0 ? (
        <p style={styles.muted}>Henüz departman tanımlanmamış.</p>
      ) : (
        sharing.departments.map((department) => {
          const key = `department:${department.id}`;

          return (
            <div key={department.id} style={styles.accessRow}>
              <div>{department.name}</div>
              <Toggle
                checked={department.granted}
                disabled={busyKey !== null}
                label={`${department.name} departmanı için parola erişimi`}
                onChange={(granted) =>
                  void update(key, granted, () =>
                    setDepartmentGrant({ id, departmentId: department.id, granted }),
                  )
                }
              />
            </div>
          );
        })
      )}

      <h4 style={{ marginTop: 20, marginBottom: 4 }}>Kişiler</h4>

      {sharing.users.length === 0 ? (
        <p style={styles.muted}>Yetkilendirilebilecek başka kullanıcı yok.</p>
      ) : (
        sharing.users.map((user) => {
          const key = `user:${user.userId}`;
          const allowed = user.direct || user.viaDepartment;

          const status = user.hasKey
            ? user.direct
              ? "Erişim açık"
              : "Departman üzerinden erişim açık"
            : allowed
              ? user.hasPublicKey
                ? "Anahtar hazırlanıyor..."
                : "Kasasını ilk açtığında erişecek"
              : "Erişim kapalı";

          return (
            <div key={user.userId} style={styles.accessRow}>
              <div style={{ minWidth: 0 }}>
                <div>{user.displayName}</div>
                <div
                  style={{
                    ...styles.muted,
                    fontSize: 12,
                    overflowWrap: "anywhere",
                  }}
                >
                  {user.email}
                  {user.departmentName ? ` · ${user.departmentName}` : ""}
                </div>
                <div
                  style={{
                    color: user.hasKey ? "#4ade80" : allowed ? "#fbbf24" : "#9ca3af",
                    fontSize: 12,
                    marginTop: 4,
                  }}
                >
                  {status}
                </div>
              </div>

              <Toggle
                checked={user.direct}
                disabled={busyKey !== null}
                label={`${user.displayName} için doğrudan parola erişimi`}
                onChange={(granted) =>
                  void update(key, granted, () =>
                    setUserGrant({ id, userId: user.userId, granted }),
                  )
                }
              />
            </div>
          );
        })
      )}
    </div>
  );
}

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
  const pendingWork = useQuery(api.items.pendingWork, isReady ? {} : "skip");
  const pendingSharedCount = useQuery(
    api.items.pendingSharedCount,
    isReady ? {} : "skip",
  );

  const createItem = useMutation(api.items.create);
  const addAccesses = useMutation(api.items.addAccesses);
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
  const [syncError, setSyncError] = useState("");

  const [copyingPasswordId, setCopyingPasswordId] = useState<string | null>(
    null,
  );

  const [openAuthorizationPasswordId, setOpenAuthorizationPasswordId] =
    useState<Id<"items"> | null>(null);

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
          setError(errorMessage(err));
        }
      }
    }

    void decryptMetadata();

    return () => {
      cancelled = true;
    };
  }, [decryptVersion, getSessionToken, isReady, serverItems]);

  // Arka plan anahtar eşitlemesi: paylaşım kuralına göre erişimi olması
  // gereken kişilere anahtar paketlenir; sahibi olunan ve erişimi
  // kaldırılmış kayıtlar yeni bir DEK ile yeniden şifrelenir.
  const syncRunningRef = useRef(false);
  const [syncTick, setSyncTick] = useState(0);

  useEffect(() => {
    if (!isReady || !pendingWork || syncRunningRef.current) {
      return;
    }

    if (pendingWork.fills.length === 0 && pendingWork.rekeys.length === 0) {
      setSyncError("");
      return;
    }

    syncRunningRef.current = true;

    void (async () => {
      let failed = false;

      try {
        const sessionToken = await getSessionToken();

        for (const task of pendingWork.rekeys) {
          try {
            const rekeyed = await invoke<RekeyedItem>("rekey_item", {
              sessionToken,
              item: toEncryptedItem(task.item),
              recipients: task.recipients,
            });

            await rekeyItem({
              id: task.item.id,
              keyVersion: task.item.keyVersion,
              ...rekeyed,
            });
          } catch (err) {
            failed = true;
            setSyncError(`Yeniden şifreleme başarısız: ${errorMessage(err)}`);
          }
        }

        for (const task of pendingWork.fills) {
          try {
            const accesses = [];

            for (const recipient of task.recipients) {
              const access = await invoke<WrappedKey>(
                "wrap_item_key_for_recipient",
                {
                  sessionToken,
                  item: toEncryptedItem(task.item),
                  recipientPublicKey: recipient.publicKey,
                },
              );

              accesses.push({ userId: recipient.userId, access });
            }

            await addAccesses({
              id: task.item.id,
              keyVersion: task.item.keyVersion,
              accesses,
            });
          } catch (err) {
            failed = true;
            setSyncError(`Anahtar paylaşımı başarısız: ${errorMessage(err)}`);
          }
        }
      } catch (err) {
        failed = true;
        setSyncError(errorMessage(err));
      } finally {
        syncRunningRef.current = false;

        // Çalışırken gelen yeni işler için tekrar kontrol et. Hata olduysa
        // sonsuz döngüye girmemek için bir sonraki sunucu değişikliğini bekle.
        if (!failed) {
          setSyncError("");
          setSyncTick((tick) => tick + 1);
        }
      }
    })();
  }, [addAccesses, getSessionToken, isReady, pendingWork, rekeyItem, syncTick]);

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
          isOwner: item.isOwner,
          server: item,
        };
      })
      .sort(
        (a, b) =>
          a.title.localeCompare(b.title, "tr", { sensitivity: "base" }) ||
          a.id.localeCompare(b.id),
      );
  }, [metadataByItemId, serverItems]);

  const refreshPasswords = useCallback(() => {
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
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleCopyPassword(item: PasswordItem) {
    if (copyingPasswordId !== null) {
      return;
    }

    setCopyingPasswordId(item.id);
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
      setError(errorMessage(err));
    } finally {
      setCopyingPasswordId(null);
    }
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

      {syncError && (
        <p role="alert" style={styles.error}>
          {syncError}
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
          onClick={refreshPasswords}
        >
          Yenile
        </button>
      </div>

      {pendingSharedCount !== undefined && pendingSharedCount > 0 && (
        <p
          role="status"
          style={{
            marginTop: 16,
            padding: 12,
            background: "#292419",
            border: "1px solid #66512b",
            borderRadius: 9,
            color: "#fbbf24",
            fontSize: 13,
          }}
        >
          Seninle paylaşılmış {pendingSharedCount} parola henüz açılmadı. Parolaya
          erişimi olan biri uygulamayı açtığında otomatik olarak listene
          eklenecek.
        </p>
      )}

      {serverItems === undefined ? (
        <p style={styles.muted}>Parolalar yükleniyor...</p>
      ) : items.length === 0 ? (
        <p style={styles.muted}>Henüz erişimin olan bir parola yok.</p>
      ) : (
        <div style={{ display: "grid", gap: 12, marginTop: 16 }}>
          {items.map((item) => {
            const isAuthorizationOpen = openAuthorizationPasswordId === item.id;

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

                    {!item.isOwner && (
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
                      onClick={() => void handleCopyPassword(item)}
                      disabled={copyingPasswordId !== null}
                    >
                      {copyingPasswordId === item.id
                        ? "Kopyalanıyor..."
                        : "Copy Password"}
                    </button>

                    {item.isOwner && (
                      <button
                        type="button"
                        style={{
                          ...styles.button,
                          background: isAuthorizationOpen
                            ? "#4b5563"
                            : "#6366f1",
                        }}
                        onClick={() =>
                          setOpenAuthorizationPasswordId(
                            isAuthorizationOpen ? null : item.id,
                          )
                        }
                        aria-expanded={isAuthorizationOpen}
                      >
                        Yetkilendirme
                      </button>
                    )}
                  </div>
                </div>

                {item.isOwner && isAuthorizationOpen && (
                  <div
                    style={{
                      marginTop: 18,
                      paddingTop: 16,
                      borderTop: "1px solid #353b48",
                    }}
                  >
                    <SharingPanel id={item.id} />
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
