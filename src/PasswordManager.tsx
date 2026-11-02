import { useCallback, useEffect, useMemo, useState } from "react";
import type React from "react";
import { invoke } from "@tauri-apps/api/core";
import { useConvex, useMutation, useQuery } from "convex/react";
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

// Rust tarafındaki `EncryptedItem`; `access` doğrudan ya da departman
// anahtarı üzerinden DEK'e ulaşma yoludur.
type EncryptedItem = {
  itemId: string;
  ownerId: string;
  metadata: SealedField;
  secret: SealedField;
  access: ServerItem["access"];
};

type NewItem = {
  itemId: string;
  metadata: SealedField;
  secret: SealedField;
  ownerAccess: WrappedKey;
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
  /** Başlık ve kullanıcı adı çözüldü; düzenleme ancak o zaman açılır. */
  decrypted: boolean;
  isOwner: boolean;
  server: ServerItem;
};

type PasswordManagerProps = {
  /** Sunucu oturumu açık ve kasanın sahibiyle eşleşiyor. */
  isServerReady: boolean;
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

          const access = user.hasKey
            ? user.direct
              ? "Erişim açık"
              : "Departman üzerinden erişim açık"
            : allowed
              ? "Anahtar hazırlanıyor..."
              : "Erişim kapalı";

          // Davet edilen kişi henüz kaydolmamış olsa da paylaşım yapılabilir;
          // kaydolduğunda kimsenin çevrimiçi olması gerekmeden erişir.
          const status =
            user.status === "invited" ? `${access} · henüz kaydolmadı` : access;

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

type RekeyedItem = {
  metadata: SealedField;
  secret: SealedField;
  accesses: { userId: Id<"users">; access: WrappedKey }[];
  departmentAccesses: { departmentId: Id<"departments">; keyVersion: number; access: WrappedKey }[];
};

/**
 * Kaydın başlığını, kullanıcı adını ve parolasını değiştirir. Yalnızca sahip
 * düzenleyebilir. Her düzenleme yeni bir DEK ile yapılır ve erişimi olan
 * herkese yeniden paketlenir; parola alanı boş bırakılırsa mevcut parola
 * korunur.
 */
function EditItemForm({
  item,
  onCancel,
  onSaved,
  onDeleted,
}: {
  item: PasswordItem;
  onCancel: () => void;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  const convex = useConvex();
  const rekeyItem = useMutation(api.items.rekey);
  const removeItem = useMutation(api.items.remove);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const [title, setTitle] = useState(item.title);
  const [username, setUsername] = useState(item.username ?? "");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
    event.preventDefault();

    if (saving) return;

    if (!title.trim()) {
      setError("Başlık boş olamaz.");
      return;
    }

    setSaving(true);
    setError("");

    try {
      // Alıcılar düzenleme anında sunucudan alınır; liste eskiyse sunucu
      // reddeder ve kullanıcı tekrar dener.
      const targets = await convex.query(api.items.editTargets, { id: item.id });

      const edited = await invoke<RekeyedItem>("edit_item", {
        item: toEncryptedItem(targets.item),
        recipients: targets.recipients,
        departmentRecipients: targets.departments,
        title: title.trim(),
        username: username.trim() || null,
        password: password || null,
      });

      await rekeyItem({ id: item.id, keyVersion: targets.item.keyVersion, ...edited });

      setPassword("");
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (saving) return;

    setSaving(true);
    setError("");

    try {
      await removeItem({ id: item.id });
      onDeleted();
    } catch (err) {
      setError(errorMessage(err));
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <label htmlFor={`edit-title-${item.id}`}>Başlık</label>
      <input
        id={`edit-title-${item.id}`}
        style={styles.input}
        value={title}
        onChange={(event) => setTitle(event.target.value)}
        disabled={saving}
        required
      />

      <label htmlFor={`edit-username-${item.id}`}>Kullanıcı adı (isteğe bağlı)</label>
      <input
        id={`edit-username-${item.id}`}
        style={styles.input}
        value={username}
        onChange={(event) => setUsername(event.target.value)}
        disabled={saving}
      />

      <label htmlFor={`edit-password-${item.id}`}>Yeni parola</label>
      <input
        id={`edit-password-${item.id}`}
        type="password"
        autoComplete="new-password"
        style={styles.input}
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        placeholder="Değiştirmeyeceksen boş bırak"
        disabled={saving}
      />

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}

      <div style={{ display: "flex", gap: 8 }}>
        <button type="submit" style={{ ...styles.button, opacity: saving ? 0.6 : 1 }} disabled={saving}>
          {saving ? "Kaydediliyor..." : "Değişiklikleri kaydet"}
        </button>
        <button type="button" style={styles.secondaryButton} onClick={onCancel} disabled={saving}>
          Vazgeç
        </button>
      </div>

      <div style={{ marginTop: 18, paddingTop: 14, borderTop: "1px solid #353b48" }}>
        {confirmingDelete ? (
          <>
            <p style={{ ...styles.error, marginTop: 0 }}>
              Kayıt, paylaşılan herkes için kalıcı olarak silinecek. Bu işlem geri alınamaz.
            </p>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                style={{ ...styles.button, background: "#dc2626" }}
                onClick={() => void handleDelete()}
                disabled={saving}
              >
                {saving ? "Siliniyor..." : "Evet, kalıcı olarak sil"}
              </button>
              <button
                type="button"
                style={styles.secondaryButton}
                onClick={() => setConfirmingDelete(false)}
                disabled={saving}
              >
                Vazgeç
              </button>
            </div>
          </>
        ) : (
          <button
            type="button"
            style={{ ...styles.secondaryButton, color: "#f87171" }}
            onClick={() => setConfirmingDelete(true)}
            disabled={saving}
          >
            Kaydı sil
          </button>
        )}
      </div>
    </form>
  );
}

export default function PasswordManager({ isServerReady: isReady }: PasswordManagerProps) {
  // Convex sorguları canlıdır; sunucudaki değişiklikler otomatik gelir.
  const serverItems = useQuery(api.items.listMine, isReady ? {} : "skip");
  const pendingSharedCount = useQuery(
    api.items.pendingSharedCount,
    isReady ? {} : "skip",
  );

  const createItem = useMutation(api.items.create);

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

  // Bir kartta aynı anda tek panel açık olur: yetkilendirme ya da düzenleme.
  const [openPanel, setOpenPanel] = useState<{
    id: Id<"items">;
    kind: "sharing" | "edit";
  } | null>(null);

  const togglePanel = (id: Id<"items">, kind: "sharing" | "edit") =>
    setOpenPanel((current) =>
      current?.id === id && current.kind === kind ? null : { id, kind },
    );

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
  }, [decryptVersion, isReady, serverItems]);

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
          decrypted: typeof metadata?.title === "string",
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
      // Şifreleme Rust'ta yapılır; Convex'e yalnızca şifreli veri gider.
      const encrypted = await invoke<NewItem>("encrypt_new_item", {
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
      await invoke("copy_item_password_to_clipboard", {
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

  // Çevrimdışı erişim (yerel şifreli önbellek) bir sonraki adımda eklenecek.
  if (!isReady) {
    return <section style={styles.page}>Sunucu bağlantısı bekleniyor...</section>;
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
          Seninle paylaşılmış {pendingSharedCount} parolanın anahtarı hazırlanıyor.
          Genellikle birkaç saniye sürer; uzarsa paylaşımı yapan kişi ya da bir
          yönetici uygulamayı açtığında tamamlanır.
        </p>
      )}

      {serverItems === undefined ? (
        <p style={styles.muted}>Parolalar yükleniyor...</p>
      ) : items.length === 0 ? (
        <p style={styles.muted}>Henüz erişimin olan bir parola yok.</p>
      ) : (
        <div style={{ display: "grid", gap: 12, marginTop: 16 }}>
          {items.map((item) => {
            const isAuthorizationOpen =
              openPanel?.id === item.id && openPanel.kind === "sharing";
            const isEditOpen = openPanel?.id === item.id && openPanel.kind === "edit";

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
                          ...styles.secondaryButton,
                          background: isEditOpen ? "#4b5563" : styles.secondaryButton.background,
                        }}
                        onClick={() => togglePanel(item.id, "edit")}
                        disabled={!item.decrypted}
                        aria-expanded={isEditOpen}
                      >
                        Düzenle
                      </button>
                    )}

                    {item.isOwner && (
                      <button
                        type="button"
                        style={{
                          ...styles.button,
                          background: isAuthorizationOpen
                            ? "#4b5563"
                            : "#6366f1",
                        }}
                        onClick={() => togglePanel(item.id, "sharing")}
                        aria-expanded={isAuthorizationOpen}
                      >
                        Yetkilendirme
                      </button>
                    )}
                  </div>
                </div>

                {item.isOwner && isEditOpen && (
                  <div
                    style={{
                      marginTop: 18,
                      paddingTop: 16,
                      borderTop: "1px solid #353b48",
                    }}
                  >
                    <EditItemForm
                      item={item}
                      onCancel={() => setOpenPanel(null)}
                      onSaved={() => {
                        setOpenPanel(null);
                        setError("");
                        setSuccess("Parola güncellendi.");
                      }}
                      onDeleted={() => {
                        setOpenPanel(null);
                        setError("");
                        setSuccess("Kayıt silindi.");
                      }}
                    />
                  </div>
                )}

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
