import { useEffect, useMemo, useState } from "react";
import type React from "react";
import { invoke } from "@tauri-apps/api/core";
import { useConvex, useMutation, useQuery } from "convex/react";

import { api } from "../convex/_generated/api";
import type { Id } from "../convex/_generated/dataModel";
import { errorMessage } from "./errors";
import {
  toEncryptedItem,
  type GrantTarget,
  type HistoryRecord,
  type NewItem,
  type QueuedOp,
  type VaultData,
  type VaultItem,
} from "./vaultData";

type SealedField = { nonce: string; ciphertext: string };

type WrappedKey = {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
};

type DecryptedMetadata = {
  itemId: string;
  title: string | null;
  username: string | null;
  error: string | null;
};

type PasswordItem = {
  vault: VaultItem;
  title: string;
  username: string | null;
  /** Başlık ve kullanıcı adı çözüldü; düzenleme ancak o zaman açılır. */
  decrypted: boolean;
};

type PasswordManagerProps = {
  data: VaultData;
  /** Sunucuya bağlı ve oturum kasanın sahibiyle eşleşiyor. */
  isOnline: boolean;
};

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
 * Bir parolanın departman ve kişi bazındaki paylaşım kuralları. Çevrimdışıyken
 * de değiştirilebilir: değişiklik kuyruğa alınır ve bağlantı gelince
 * gönderilir. Anahtar dağıtımı ve erişim kaldırıldığında yeniden şifreleme
 * arka planda otomatik yapılır.
 */
function SharingPanel({
  item,
  data,
  isOnline,
}: {
  item: VaultItem;
  data: VaultData;
  isOnline: boolean;
}) {
  // Anahtar durumu (erişim açık mı, hazırlanıyor mu) yalnızca sunucudan
  // öğrenilebilir.
  const live = useQuery(api.items.sharing, isOnline && item.id ? { id: item.id } : "skip");
  const keyStatus = new Map(live?.users.map((user) => [user.userId, user.hasKey]) ?? []);

  const directory = data.directory;
  const grants = item.grants ?? { userIds: [], departmentIds: [] };

  const toggle = (target: GrantTarget, granted: boolean) =>
    data.setGrant(item.itemId, target, granted);

  if (!directory) {
    return (
      <p style={styles.muted}>
        Kişi ve departman listesi henüz bu cihaza indirilmedi; bir kez çevrimiçi olunca
        çevrimdışı da yetkilendirme yapabilirsin.
      </p>
    );
  }

  return (
    <div>
      {item.pendingSync && (
        <p role="status" style={{ ...styles.muted, fontSize: 13, color: "#fbbf24" }}>
          {isOnline
            ? "Değişiklikler sunucuya gönderiliyor..."
            : "Çevrimdışısın; değişiklikler bağlantı gelince uygulanacak. Erişimi kaldırılan kişi o zamana kadar kendi cihazındaki kopyayı görmeye devam edebilir."}
        </p>
      )}

      <p style={{ ...styles.muted, fontSize: 13 }}>
        Erişim kaldırıldığında parola yeni bir anahtarla yeniden şifrelenir. Kaldırılan kişi
        parolayı daha önce görmüş olabilir; gerekirse parolanın kendisini değiştir.
      </p>

      <h4 style={{ marginTop: 0, marginBottom: 4 }}>Departmanlar</h4>
      <p style={{ ...styles.muted, fontSize: 13, marginTop: 0 }}>
        Departmana verilen erişim, departmana sonradan katılanları da kapsar.
      </p>

      {directory.departments.length === 0 ? (
        <p style={styles.muted}>Henüz departman tanımlanmamış.</p>
      ) : (
        directory.departments.map((department) => (
          <div key={department.id} style={styles.accessRow}>
            <div>{department.name}</div>
            <Toggle
              checked={grants.departmentIds.includes(department.id)}
              disabled={false}
              label={`${department.name} departmanı için parola erişimi`}
              onChange={(granted) =>
                toggle({ kind: "department", departmentId: department.id }, granted)
              }
            />
          </div>
        ))
      )}

      <h4 style={{ marginTop: 20, marginBottom: 4 }}>Kişiler</h4>

      {directory.users.length === 0 ? (
        <p style={styles.muted}>Yetkilendirilebilecek başka kullanıcı yok.</p>
      ) : (
        directory.users.map((user) => {
          const direct = grants.userIds.includes(user.userId);
          const viaDepartment =
            user.departmentId !== null && grants.departmentIds.includes(user.departmentId);
          // Yöneticiler bütün parolaları görür; ayrıca yetki gerekmez.
          const viaAdmin = user.isAdmin === true;
          const allowed = direct || viaDepartment || viaAdmin;
          const hasKey = keyStatus.get(user.userId);
          const route = direct ? "" : viaDepartment ? "Departman üzerinden " : viaAdmin ? "Yönetici olarak " : "";

          const access = !allowed
            ? "Erişim kapalı"
            : hasKey === undefined || item.pendingSync
              ? route
                ? `${route}erişim verildi`
                : "Erişim verildi"
              : hasKey
                ? route
                  ? `${route}erişim açık`
                  : "Erişim açık"
                : "Anahtar hazırlanıyor...";

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
                    color: hasKey && allowed ? "#4ade80" : allowed ? "#fbbf24" : "#9ca3af",
                    fontSize: 12,
                    marginTop: 4,
                  }}
                >
                  {status}
                </div>
              </div>

              <Toggle
                checked={direct}
                disabled={false}
                label={`${user.displayName} için doğrudan parola erişimi`}
                onChange={(granted) => toggle({ kind: "user", userId: user.userId }, granted)}
              />
            </div>
          );
        })
      )}
    </div>
  );
}

type PanelKind = "sharing" | "edit" | "history";

type HistoryInfo = {
  id: Id<"itemHistory">;
  replacedAt: number;
  title: string;
  username: string | null;
  titleChanged: boolean;
  usernameChanged: boolean;
  passwordChanged: boolean;
};

const historyDateFormat = new Intl.DateTimeFormat("tr-TR", {
  dateStyle: "medium",
  timeStyle: "short",
});

function describeChange(entry: HistoryInfo) {
  const changes = [
    entry.titleChanged && "başlık",
    entry.usernameChanged && "kullanıcı adı",
    entry.passwordChanged && "parola",
  ].filter(Boolean);

  return changes.length > 0 ? `${changes.join(", ")} değişti` : "değişiklik yok";
}

/**
 * Kaydın önceki halleri; kaydı açabilen herkes görür. Geçmiş sunucudan
 * istenir (çevrimiçi). Başlık ve kullanıcı adı gösterilir; eski parolalar
 * güncel parola gibi yalnızca panoya kopyalanır (açık metin React'e gelmez).
 */
function PasswordHistoryPanel({ id, onCopied }: { id: Id<"items">; onCopied: () => void }) {
  const server = useQuery(api.items.history, { id });
  const [entries, setEntries] = useState<HistoryInfo[] | null>(null);
  const [copyingId, setCopyingId] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!server) return;

    let cancelled = false;

    invoke<HistoryInfo[]>("item_password_history", {
      item: toEncryptedItem(server.item),
      history: server.history,
    })
      .then((result) => {
        if (!cancelled) {
          setEntries(result);
          setError("");
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err));
      });

    return () => {
      cancelled = true;
    };
  }, [server]);

  async function handleCopy(entryId: Id<"itemHistory">) {
    const record = server?.history.find((candidate) => candidate.id === entryId);

    if (!server || !record || copyingId !== null) return;

    setCopyingId(entryId);
    setError("");

    try {
      await invoke("copy_item_history_password_to_clipboard", {
        item: toEncryptedItem(server.item),
        record,
      });
      onCopied();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCopyingId(null);
    }
  }

  return (
    <div>
      <strong>Geçmiş</strong>

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}

      {entries === null ? (
        !error && <p style={styles.muted}>Geçmiş yükleniyor...</p>
      ) : entries.length === 0 ? (
        <p style={styles.muted}>Bu kayıt hiç değiştirilmemiş.</p>
      ) : (
        <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
          {entries.map((entry) => (
            <div
              key={entry.id}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 14 }}>
                  {entry.title}
                  <span style={{ ...styles.muted, marginLeft: 8, fontSize: 12 }}>
                    {entry.username || "Kullanıcı adı yok"}
                  </span>
                </div>
                <div style={{ ...styles.muted, fontSize: 12, marginTop: 2 }}>
                  {historyDateFormat.format(new Date(entry.replacedAt))} · {describeChange(entry)}
                </div>
              </div>

              <button
                type="button"
                style={{
                  ...styles.secondaryButton,
                  opacity: copyingId !== null ? 0.6 : 1,
                  cursor: copyingId !== null ? "wait" : "pointer",
                }}
                onClick={() => void handleCopy(entry.id)}
                disabled={copyingId !== null}
              >
                {copyingId === entry.id ? "Kopyalanıyor..." : "O zamanki parolayı kopyala"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type RekeyedItem = {
  metadata: SealedField;
  secret: SealedField;
  history: HistoryRecord[];
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
  item: { id: Id<"items">; title: string; username: string | null };
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
        history: targets.history,
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

/**
 * Çevrimdışıyken yapılıp sunucuya gönderilmeyi bekleyen işlemler; bağlantı
 * gelince listedeki sırayla gönderilir.
 */
function PendingOperations({
  queue,
  directory,
  titleOf,
  isOnline,
}: {
  queue: QueuedOp[];
  directory: VaultData["directory"];
  titleOf: (itemId: string) => string;
  isOnline: boolean;
}) {
  const targetName = (target: GrantTarget) =>
    target.kind === "user"
      ? (directory?.users.find((user) => user.userId === target.userId)?.displayName ??
        "bilinmeyen kişi")
      : `${directory?.departments.find((d) => d.id === target.departmentId)?.name ?? "bilinmeyen"} departmanı`;

  const describe = (op: QueuedOp) =>
    op.kind === "create"
      ? `Yeni kayıt: ${titleOf(op.item.itemId)}`
      : `${op.granted ? "Yetki verildi" : "Yetki kaldırıldı"}: ${titleOf(op.itemId)} → ${targetName(op.target)}`;

  return (
    <details
      open
      style={{
        marginBottom: 16,
        padding: 12,
        background: "#292419",
        border: "1px solid #66512b",
        borderRadius: 9,
        color: "#fbbf24",
        fontSize: 13,
      }}
    >
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>
        Bekleyen {queue.length} işlem
      </summary>

      <p style={{ margin: "8px 0", color: "#d6c08f" }}>
        {isOnline
          ? "Sunucuya gönderiliyor..."
          : "Bu cihazda yapıldı; bağlantı gelince sırayla sunucuya gönderilecek."}
      </p>

      <ol style={{ margin: 0, paddingLeft: 20, color: "#e5e7eb" }}>
        {queue.map((op, index) => (
          <li key={index} style={{ padding: "2px 0", overflowWrap: "anywhere" }}>
            {describe(op)}
          </li>
        ))}
      </ol>
    </details>
  );
}

function formatSyncedAt(timestamp: number | null) {
  if (timestamp === null) return "hiç";

  return new Date(timestamp).toLocaleString("tr-TR", {
    day: "numeric",
    month: "long",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function PasswordManager({ data, isOnline }: PasswordManagerProps) {
  const pendingSharedCount = useQuery(api.items.pendingSharedCount, isOnline ? {} : "skip");

  const [metadataByItemId, setMetadataByItemId] = useState<
    Record<string, DecryptedMetadata>
  >({});

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
    itemId: string;
    kind: PanelKind;
  } | null>(null);

  const togglePanel = (itemId: string, kind: PanelKind) =>
    setOpenPanel((current) =>
      current?.itemId === itemId && current.kind === kind ? null : { itemId, kind },
    );

  // Başlık ve kullanıcı adı şifreli geldiği için liste her değiştiğinde
  // meta veri Rust tarafında çözülür. Parolaların kendisi çözülmez.
  useEffect(() => {
    let cancelled = false;

    invoke<DecryptedMetadata[]>("decrypt_items_metadata", {
      items: data.items.map((item) => item.encrypted),
    })
      .then((result) => {
        if (!cancelled) {
          setMetadataByItemId(Object.fromEntries(result.map((entry) => [entry.itemId, entry])));
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err));
      });

    return () => {
      cancelled = true;
    };
  }, [data.items]);

  const items = useMemo<PasswordItem[]>(
    () =>
      data.items
        .map((item) => {
          const metadata = metadataByItemId[item.itemId];

          return {
            vault: item,
            title: metadata?.title ?? (metadata?.error ? "Çözülemedi" : "…"),
            username: metadata?.username ?? null,
            decrypted: typeof metadata?.title === "string",
          };
        })
        .sort(
          (a, b) =>
            a.title.localeCompare(b.title, "tr", { sensitivity: "base" }) ||
            a.vault.itemId.localeCompare(b.vault.itemId),
        ),
    [data.items, metadataByItemId],
  );

  async function handleSubmit(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
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
      // Kayıt önce bu cihazda kuyruğa alınır, bağlantı varsa hemen gönderilir.
      const encrypted = await invoke<NewItem>("encrypt_new_item", {
        title: title.trim(),
        username: username.trim() || null,
        password,
      });

      data.addItem(encrypted);

      setTitle("");
      setUsername("");
      setPassword("");

      setSuccess(
        isOnline
          ? "Parola şifrelenerek kasaya kaydedildi."
          : "Parola bu cihazda şifrelenerek kaydedildi; bağlantı gelince sunucuya gönderilecek.",
      );
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

    setCopyingPasswordId(item.vault.itemId);
    setError("");
    setSuccess("");

    try {
      await invoke("copy_item_password_to_clipboard", { item: item.vault.encrypted });

      setSuccess(
        "Parola panoya kopyalandı. 30 saniye sonra otomatik temizlenmesi denenecek.",
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCopyingPasswordId(null);
    }
  }

  return (
    <section style={styles.page}>
      <h2 style={{ marginTop: 0 }}>Parola kasası</h2>

      <p style={styles.muted}>
        Parolalar bu cihazda şifrelenir; sunucuya yalnızca şifreli veri gönderilir.
      </p>

      {!isOnline && (
        <p
          role="status"
          style={{
            padding: 12,
            background: "#1e2433",
            border: "1px solid #353b48",
            borderRadius: 9,
            fontSize: 13,
          }}
        >
          Çevrimdışısın; liste bu cihazdaki kopyadan gösteriliyor (son eşitleme:{" "}
          {formatSyncedAt(data.syncedAt)}). Parolaları görüntüleyip kopyalayabilir, yeni
          kayıt ekleyebilir ve yetkilendirme yapabilirsin. Düzenleme ve silme için bağlantı
          gerekli.
        </p>
      )}

      {data.queue.length > 0 && (
        <PendingOperations
          queue={data.queue}
          directory={data.directory}
          titleOf={(itemId) => metadataByItemId[itemId]?.title ?? "Adı çözülemeyen kayıt"}
          isOnline={isOnline}
        />
      )}

      {data.errors.map((message) => (
        <p key={message} role="alert" style={styles.error}>
          {message}
        </p>
      ))}

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
          disabled={loading || !data.loaded}
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

      <h3 style={{ marginTop: 32, marginBottom: 0 }}>Kayıtlı parolalar ({items.length})</h3>

      {isOnline && pendingSharedCount !== undefined && pendingSharedCount > 0 && (
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

      {!data.loaded ? (
        <p style={styles.muted}>Parolalar yükleniyor...</p>
      ) : items.length === 0 ? (
        <p style={styles.muted}>
          {isOnline || data.syncedAt !== null
            ? "Henüz erişimin olan bir parola yok."
            : "Bu cihazda henüz eşitlenmiş parola yok; bir kez çevrimiçi olunca çevrimdışı da erişebilirsin."}
        </p>
      ) : (
        <div style={{ display: "grid", gap: 12, marginTop: 16 }}>
          {items.map((item) => {
            const { itemId, id, isOwner } = item.vault;
            const isAuthorizationOpen =
              openPanel?.itemId === itemId && openPanel.kind === "sharing";
            const canEdit = isOnline && id !== null && item.decrypted;
            const isEditOpen = canEdit && openPanel?.itemId === itemId && openPanel.kind === "edit";
            const canViewHistory = isOnline && id !== null;
            const isHistoryOpen =
              canViewHistory && openPanel?.itemId === itemId && openPanel.kind === "history";

            return (
              <article key={itemId} style={styles.card}>
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

                    {!isOwner && (
                      <p style={{ color: "#a5b4fc", fontSize: 12, marginBottom: 0 }}>
                        Seninle paylaşılmış
                      </p>
                    )}

                    {item.vault.pendingSync && (
                      <p style={{ color: "#fbbf24", fontSize: 12, marginBottom: 0 }}>
                        {id === null
                          ? "Sunucuya gönderilmeyi bekliyor"
                          : "Paylaşım değişikliği gönderilmeyi bekliyor"}
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
                      {copyingPasswordId === itemId ? "Kopyalanıyor..." : "Parolayı kopyala"}
                    </button>

                    <button
                      type="button"
                      style={{
                        ...styles.secondaryButton,
                        background: isHistoryOpen ? "#4b5563" : styles.secondaryButton.background,
                        opacity: canViewHistory ? 1 : 0.5,
                      }}
                      onClick={() => togglePanel(itemId, "history")}
                      disabled={!canViewHistory}
                      title={isOnline ? undefined : "Geçmiş için bağlantı gerekli"}
                      aria-expanded={isHistoryOpen}
                    >
                      Geçmiş
                    </button>

                    {isOwner && (
                      <button
                        type="button"
                        style={{
                          ...styles.secondaryButton,
                          background: isEditOpen ? "#4b5563" : styles.secondaryButton.background,
                          opacity: canEdit ? 1 : 0.5,
                        }}
                        onClick={() => togglePanel(itemId, "edit")}
                        disabled={!canEdit}
                        title={isOnline ? undefined : "Düzenleme ve silme için bağlantı gerekli"}
                        aria-expanded={isEditOpen}
                      >
                        Düzenle
                      </button>
                    )}

                    {isOwner && (
                      <button
                        type="button"
                        style={{
                          ...styles.button,
                          background: isAuthorizationOpen ? "#4b5563" : "#6366f1",
                        }}
                        onClick={() => togglePanel(itemId, "sharing")}
                        aria-expanded={isAuthorizationOpen}
                      >
                        Yetkilendirme
                      </button>
                    )}
                  </div>
                </div>

                {isHistoryOpen && id !== null && (
                  <div
                    style={{
                      marginTop: 18,
                      paddingTop: 16,
                      borderTop: "1px solid #353b48",
                    }}
                  >
                    <PasswordHistoryPanel
                      id={id}
                      onCopied={() => {
                        setError("");
                        setSuccess(
                          "Eski parola panoya kopyalandı. 30 saniye sonra otomatik temizlenmesi denenecek.",
                        );
                      }}
                    />
                  </div>
                )}

                {isEditOpen && id !== null && (
                  <div
                    style={{
                      marginTop: 18,
                      paddingTop: 16,
                      borderTop: "1px solid #353b48",
                    }}
                  >
                    <EditItemForm
                      item={{ id, title: item.title, username: item.username }}
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

                {isOwner && isAuthorizationOpen && (
                  <div
                    style={{
                      marginTop: 18,
                      paddingTop: 16,
                      borderTop: "1px solid #353b48",
                    }}
                  >
                    <SharingPanel item={item.vault} data={data} isOnline={isOnline} />
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
