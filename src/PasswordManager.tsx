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

function Icon({ children, size = 16 }: { children: React.ReactNode; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={{ flexShrink: 0 }}
    >
      {children}
    </svg>
  );
}

const icons = {
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.85 12.15 8.65-8.65" />
      <path d="m16.5 6.5 2.5 2.5" />
    </>
  ),
  user: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21a8 8 0 0 1 16 0" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20a6.5 6.5 0 0 1 13 0" />
      <path d="M16 4.6a3.5 3.5 0 0 1 0 6.8" />
      <path d="M18.5 14.2A6.5 6.5 0 0 1 21.5 20" />
    </>
  ),
  shield: <path d="M12 3 4.5 6v6c0 4.5 3.2 7.8 7.5 9 4.3-1.2 7.5-4.5 7.5-9V6Z" />,
  plus: (
    <>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </>
  ),
  chevron: <path d="m9 6 6 6-6 6" />,
  expand: (
    <>
      <path d="m7 15 5 5 5-5" />
      <path d="m7 9 5-5 5 5" />
    </>
  ),
  collapse: (
    <>
      <path d="m7 20 5-5 5 5" />
      <path d="m7 4 5 5 5-5" />
    </>
  ),
  check: <path d="m5 12 5 5 9-10" />,
  dash: <path d="M6 12h12" />,
};

/** Üç durumlu kutucuk: işaretli, kısmi (`mixed`) ya da boş. */
function Checkbox({
  state,
  disabled = false,
  label,
  title,
  onChange,
}: {
  state: boolean | "mixed";
  disabled?: boolean;
  label: string;
  title?: string;
  onChange?: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      className="pm-checkbox"
      aria-checked={state}
      aria-label={label}
      title={title}
      disabled={disabled}
      onClick={() => onChange?.(state !== true)}
    >
      {state === true && <Icon size={12}>{icons.check}</Icon>}
      {state === "mixed" && <Icon size={12}>{icons.dash}</Icon>}
    </button>
  );
}

function Chevron({ open, onToggle, label }: { open: boolean; onToggle: () => void; label: string }) {
  return (
    <button
      type="button"
      className={`pm-chevron${open ? " open" : ""}`}
      onClick={onToggle}
      aria-expanded={open}
      aria-label={label}
    >
      <Icon size={14}>{icons.chevron}</Icon>
    </button>
  );
}

/** Ağaçta bir düğümün altındaki yetki satırı. Şimdilik tek yetki var. */
function PermissionRow({
  checked,
  disabled,
  label,
  title,
  onChange,
}: {
  checked: boolean;
  disabled: boolean;
  label: string;
  title?: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div
      className="pm-tree-row"
      style={{ marginLeft: 26, paddingLeft: 12, borderLeft: "1px solid #3f3f46" }}
    >
      <Checkbox state={checked} disabled={disabled} label={label} title={title} onChange={onChange} />
      <span>Yetkilendir</span>
    </div>
  );
}

type Directory = NonNullable<VaultData["directory"]>;
type DirectoryUser = Directory["users"][number];

/**
 * Seçili parolanın yetkilendirme ağacı: departmanlar ve altında üyeleri,
 * ayrıca yöneticiler. Her düğümün altında yetki satırı ("Yetkilendir")
 * vardır; düğümün kutucuğu bu yetkileri özetler. Çevrimdışıyken de
 * değiştirilebilir: değişiklik kuyruğa alınır ve bağlantı gelince
 * gönderilir. Anahtar dağıtımı ve erişim kaldırıldığında yeniden şifreleme
 * arka planda otomatik yapılır.
 */
function AuthorizationTree({
  item,
  directory,
  isOnline,
  search,
  expanded,
  setExpanded,
  onToggle,
}: {
  item: VaultItem;
  directory: Directory;
  isOnline: boolean;
  search: string;
  expanded: Set<string>;
  setExpanded: (update: (current: Set<string>) => Set<string>) => void;
  onToggle: (target: GrantTarget, granted: boolean) => void;
}) {
  // Anahtar durumu (erişim açık mı, hazırlanıyor mu) yalnızca sunucudan
  // öğrenilebilir.
  const live = useQuery(api.items.sharing, isOnline && item.id ? { id: item.id } : "skip");
  const keyStatus = new Map(live?.users.map((user) => [user.userId, user.hasKey]) ?? []);
  const grants = item.grants ?? { userIds: [], departmentIds: [] };

  const query = search.trim().toLocaleLowerCase("tr");
  const matches = (user: DirectoryUser) =>
    !query ||
    user.displayName.toLocaleLowerCase("tr").includes(query) ||
    user.email.toLocaleLowerCase("tr").includes(query);

  // Arama varken eşleşen her düğüm açık gösterilir.
  const isOpen = (key: string) => (query ? true : expanded.has(key));
  const flip = (key: string) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const admins = directory.users.filter((user) => user.isAdmin === true);
  const others = directory.users.filter((user) => user.isAdmin !== true);

  function keyColor(user: DirectoryUser, allowed: boolean) {
    const hasKey = keyStatus.get(user.userId);
    if (!allowed) return "#71717a";
    if (hasKey === undefined || item.pendingSync) return "#a1a1aa";
    return hasKey ? "#4ade80" : "#fbbf24";
  }

  function statusText(user: DirectoryUser, allowed: boolean) {
    const hasKey = keyStatus.get(user.userId);
    const parts = [];
    if (allowed && hasKey === false && !item.pendingSync) parts.push("anahtar hazırlanıyor");
    if (user.status === "invited") parts.push("henüz kaydolmadı");
    return parts.join(" · ");
  }

  function userNode(user: DirectoryUser, viaDepartment: boolean, depth: number) {
    const direct = grants.userIds.includes(user.userId);
    const allowed = direct || viaDepartment;
    const key = `user:${user.userId}`;
    const open = expanded.has(key);
    const status = statusText(user, allowed);

    return (
      <div key={user.userId} style={{ marginLeft: depth * 22 }}>
        <div className="pm-tree-row">
          <Chevron open={open} onToggle={() => flip(key)} label={`${user.displayName} yetkileri`} />
          <Checkbox
            state={direct ? true : viaDepartment ? "mixed" : false}
            label={`${user.displayName} için yetki`}
            title={!direct && viaDepartment ? "Departman üzerinden yetkili" : undefined}
            onChange={(granted) => onToggle({ kind: "user", userId: user.userId }, granted)}
          />
          <span style={{ color: keyColor(user, allowed), display: "inline-flex" }}>
            <Icon size={15}>{icons.user}</Icon>
          </span>
          <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {user.displayName}
          </span>
          {status && <span style={{ ...styles.muted, fontSize: 11, whiteSpace: "nowrap" }}>{status}</span>}
        </div>

        {open && (
          <PermissionRow
            checked={direct}
            disabled={false}
            label={`${user.displayName} için Yetkilendir`}
            onChange={(granted) => onToggle({ kind: "user", userId: user.userId }, granted)}
          />
        )}
      </div>
    );
  }

  const departmentNodes = directory.departments
    .map((department) => {
      const members = others.filter((user) => user.departmentId === department.id);
      const visibleMembers = members.filter(matches);
      const nameMatches = !query || department.name.toLocaleLowerCase("tr").includes(query);

      if (!nameMatches && visibleMembers.length === 0) return null;

      const granted = grants.departmentIds.includes(department.id);
      const anyMember = members.some((user) => grants.userIds.includes(user.userId));
      const key = `department:${department.id}`;
      const open = isOpen(key);

      return (
        <div key={department.id}>
          <div className="pm-tree-row">
            <Chevron open={open} onToggle={() => flip(key)} label={`${department.name} departmanı`} />
            <Checkbox
              state={granted ? true : anyMember ? "mixed" : false}
              label={`${department.name} departmanı için yetki`}
              onChange={(value) =>
                onToggle({ kind: "department", departmentId: department.id }, value)
              }
            />
            <span style={{ color: granted ? "#4ade80" : "#a78bfa", display: "inline-flex" }}>
              <Icon size={15}>{icons.users}</Icon>
            </span>
            <span>{department.name}</span>
            <span style={{ ...styles.muted, fontSize: 11 }}>{members.length}</span>
          </div>

          {open && (
            <>
              <PermissionRow
                checked={granted}
                disabled={false}
                label={`${department.name} departmanı için Yetkilendir`}
                title="Departmana sonradan katılanları da kapsar"
                onChange={(value) =>
                  onToggle({ kind: "department", departmentId: department.id }, value)
                }
              />
              {(nameMatches && !query ? members : visibleMembers).map((user) =>
                userNode(user, granted, 1),
              )}
            </>
          )}
        </div>
      );
    })
    .filter(Boolean);

  const visibleAdmins = admins.filter(matches);
  const adminsOpen = isOpen("admins");

  return (
    <div>
      {item.pendingSync && (
        <p role="status" style={{ ...styles.muted, fontSize: 12, color: "#fbbf24", margin: "4px 6px 8px" }}>
          {isOnline
            ? "Değişiklikler sunucuya gönderiliyor..."
            : "Çevrimdışısın; değişiklikler bağlantı gelince uygulanacak."}
        </p>
      )}

      {departmentNodes}

      {visibleAdmins.length > 0 && (
        <div>
          <div className="pm-tree-row">
            <Chevron open={adminsOpen} onToggle={() => flip("admins")} label="Yöneticiler" />
            <Checkbox
              state={true}
              disabled
              label="Yöneticiler için yetki"
              title="Yöneticiler bütün parolalara erişir"
            />
            <span style={{ color: "#4ade80", display: "inline-flex" }}>
              <Icon size={15}>{icons.shield}</Icon>
            </span>
            <span>Yöneticiler</span>
            <span style={{ ...styles.muted, fontSize: 11 }}>{admins.length}</span>
          </div>

          {adminsOpen &&
            visibleAdmins.map((user) => (
              <div key={user.userId} className="pm-tree-row" style={{ marginLeft: 22 }}>
                <span style={{ width: 18 }} />
                <Checkbox
                  state={true}
                  disabled
                  label={`${user.displayName} için yetki`}
                  title="Yöneticiler bütün parolalara erişir"
                />
                <span style={{ color: keyColor(user, true), display: "inline-flex" }}>
                  <Icon size={15}>{icons.user}</Icon>
                </span>
                <span>{user.displayName}</span>
                {statusText(user, true) && (
                  <span style={{ ...styles.muted, fontSize: 11 }}>{statusText(user, true)}</span>
                )}
              </div>
            ))}
        </div>
      )}

      {departmentNodes.length === 0 && visibleAdmins.length === 0 && (
        <p style={{ ...styles.muted, fontSize: 13, padding: "8px 6px" }}>
          {query ? "Eşleşen kullanıcı yok." : "Henüz departman ya da kullanıcı yok."}
        </p>
      )}

      <p style={{ ...styles.muted, fontSize: 12, padding: "12px 6px 0", lineHeight: 1.5 }}>
        Erişim kaldırıldığında parola yeni bir anahtarla yeniden şifrelenir. Kaldırılan kişi
        parolayı daha önce görmüş olabilir; gerekirse parolanın kendisini değiştir.
      </p>
    </div>
  );
}

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
 * istenir (çevrimiçi). Başlık, kullanıcı adı ve neyin değiştiği gösterilir;
 * eski parolalar gösterilmez.
 */
function PasswordHistoryPanel({ id }: { id: Id<"items"> }) {
  const server = useQuery(api.items.history, { id });
  const [entries, setEntries] = useState<HistoryInfo[] | null>(null);
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

const bannerStyle: React.CSSProperties = {
  margin: "0 0 14px",
  padding: 12,
  background: "#292419",
  border: "1px solid #66512b",
  borderRadius: 9,
  color: "#fbbf24",
  fontSize: 13,
};

function formatSyncedAt(timestamp: number | null) {
  if (timestamp === null) return "hiç";

  return new Date(timestamp).toLocaleString("tr-TR", {
    day: "numeric",
    month: "long",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Yeni parola formu; kayıt önce bu cihazda kuyruğa alınır. */
function NewItemForm({
  data,
  isOnline,
  onCreated,
  onCancel,
}: {
  data: VaultData;
  isOnline: boolean;
  onCreated: (itemId: string, message: string) => void;
  onCancel: () => void;
}) {
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
    event.preventDefault();

    if (!title.trim() || !password) {
      setError("Başlık ve parola alanları zorunludur.");
      return;
    }

    setSaving(true);
    setError("");

    try {
      // Şifreleme Rust'ta yapılır; Convex'e yalnızca şifreli veri gider.
      const encrypted = await invoke<NewItem>("encrypt_new_item", {
        title: title.trim(),
        username: username.trim() || null,
        password,
      });

      data.addItem(encrypted);
      onCreated(
        encrypted.itemId,
        isOnline
          ? "Parola şifrelenerek kasaya kaydedildi."
          : "Parola bu cihazda şifrelenerek kaydedildi; bağlantı gelince sunucuya gönderilecek.",
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ maxWidth: 520 }}>
      <h3 style={{ marginTop: 0 }}>Yeni parola</h3>

      <label htmlFor="password-title">Başlık</label>
      <input
        id="password-title"
        style={styles.input}
        value={title}
        onChange={(event) => setTitle(event.target.value)}
        placeholder="Örn. E-posta"
        required
        autoFocus
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

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}

      <div style={{ display: "flex", gap: 8 }}>
        <button
          type="submit"
          style={{ ...styles.button, opacity: saving ? 0.6 : 1 }}
          disabled={saving || !data.loaded}
        >
          {saving ? "Kaydediliyor..." : "Parolayı kaydet"}
        </button>
        <button type="button" style={styles.secondaryButton} onClick={onCancel} disabled={saving}>
          Vazgeç
        </button>
      </div>
    </form>
  );
}

type Tab = "personal" | "shared";

export default function PasswordManager({ data, isOnline }: PasswordManagerProps) {
  const pendingSharedCount = useQuery(api.items.pendingSharedCount, isOnline ? {} : "skip");

  const [metadataByItemId, setMetadataByItemId] = useState<
    Record<string, DecryptedMetadata>
  >({});

  const [tab, setTab] = useState<Tab>("personal");
  const [itemSearch, setItemSearch] = useState("");
  const [userSearch, setUserSearch] = useState("");
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [mode, setMode] = useState<"view" | "edit" | "create">("view");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [copying, setCopying] = useState(false);

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

  const personalCount = items.filter((item) => item.vault.isOwner).length;
  const query = itemSearch.trim().toLocaleLowerCase("tr");
  const listed = items.filter(
    (item) =>
      item.vault.isOwner === (tab === "personal") &&
      (!query ||
        item.title.toLocaleLowerCase("tr").includes(query) ||
        (item.username ?? "").toLocaleLowerCase("tr").includes(query)),
  );

  const selected = items.find((item) => item.vault.itemId === selectedItemId) ?? null;

  function select(itemId: string) {
    setSelectedItemId(itemId);
    setMode("view");
    setError("");
    setSuccess("");
  }

  async function handleCopyPassword(item: PasswordItem) {
    if (copying) return;

    setCopying(true);
    setError("");
    setSuccess("");

    try {
      await invoke("copy_item_password_to_clipboard", { item: item.vault.encrypted });
      setSuccess("Parola panoya kopyalandı. 30 saniye sonra otomatik temizlenmesi denenecek.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCopying(false);
    }
  }

  const allTreeKeys = [
    ...(data.directory?.departments.map((department) => `department:${department.id}`) ?? []),
    ...(data.directory?.users.map((user) => `user:${user.userId}`) ?? []),
    "admins",
  ];

  const banners = (
    <>
      {!isOnline && (
        <p role="status" style={{ ...bannerStyle, background: "#1e2433", borderColor: "#353b48" }}>
          Çevrimdışısın; liste bu cihazdaki kopyadan gösteriliyor (son eşitleme:{" "}
          {formatSyncedAt(data.syncedAt)}). Parolaları kopyalayabilir, yeni kayıt ekleyebilir ve
          yetkilendirme yapabilirsin. Düzenleme, silme ve geçmiş için bağlantı gerekli.
        </p>
      )}

      {isOnline && pendingSharedCount !== undefined && pendingSharedCount > 0 && (
        <p role="status" style={bannerStyle}>
          Seninle paylaşılmış {pendingSharedCount} parolanın anahtarı hazırlanıyor. Genellikle
          birkaç saniye sürer; uzarsa paylaşımı yapan kişi ya da bir yönetici uygulamayı
          açtığında tamamlanır.
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
    </>
  );

  const canEdit = selected !== null && isOnline && selected.vault.id !== null && selected.decrypted;

  return (
    <div className="pm-layout">
      {/* Sol: parola listesi */}
      <section className="pm-panel" aria-label="Parolalar">
        <div className="pm-tabs" role="tablist">
          {(
            [
              ["shared", "Paylaşılanlar", icons.users, items.length - personalCount],
              ["personal", "Kişisel", icons.user, personalCount],
            ] as const
          ).map(([value, label, icon, count]) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={tab === value}
              className={`pm-tab${tab === value ? " active" : ""}`}
              onClick={() => setTab(value)}
            >
              <Icon size={15}>{icon}</Icon>
              {label}
              <span style={{ ...styles.muted, fontSize: 11 }}>{count}</span>
            </button>
          ))}
        </div>

        <div className="pm-panel-header">
          <span>Parolalar</span>
          <button
            type="button"
            className="pm-icon-button"
            title="Yeni parola"
            aria-label="Yeni parola"
            onClick={() => {
              setMode("create");
              setSelectedItemId(null);
              setError("");
              setSuccess("");
            }}
            disabled={!data.loaded}
          >
            <Icon>{icons.plus}</Icon>
          </button>
        </div>

        <div style={{ padding: "8px 8px 0" }}>
          <input
            className="pm-search"
            value={itemSearch}
            onChange={(event) => setItemSearch(event.target.value)}
            placeholder="Parola ara..."
            aria-label="Parola ara"
          />
        </div>

        <div className="pm-panel-body">
          {!data.loaded ? (
            <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>Parolalar yükleniyor...</p>
          ) : listed.length === 0 ? (
            <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>
              {query
                ? "Eşleşen parola yok."
                : tab === "personal"
                  ? "Henüz kendi parolan yok. Eklemek için + düğmesine bas."
                  : isOnline || data.syncedAt !== null
                    ? "Seninle paylaşılmış parola yok."
                    : "Bu cihazda henüz eşitlenmiş parola yok."}
            </p>
          ) : (
            listed.map((item) => (
              <button
                key={item.vault.itemId}
                type="button"
                className={`pm-row${item.vault.itemId === selectedItemId ? " selected" : ""}`}
                onClick={() => select(item.vault.itemId)}
              >
                <span style={{ color: item.vault.isOwner ? "#f59e0b" : "#a78bfa", display: "inline-flex" }}>
                  <Icon size={15}>{icons.key}</Icon>
                </span>
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {item.title}
                  </span>
                  {item.username && (
                    <span style={{ display: "block", ...styles.muted, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {item.username}
                    </span>
                  )}
                </span>
                {item.vault.pendingSync && (
                  <span title="Sunucuya gönderilmeyi bekliyor" style={{ width: 7, height: 7, borderRadius: "50%", background: "#fbbf24" }} />
                )}
              </button>
            ))
          )}
        </div>
      </section>

      {/* Orta: seçili parolanın detayı ve geçmişi */}
      <section className="pm-panel" aria-label="Parola detayı">
        <div className="pm-panel-header">
          <span>{mode === "create" ? "Yeni parola" : (selected?.title ?? "Detay")}</span>
          {selected && mode === "view" && (
            <div style={{ display: "flex", gap: 6 }}>
              <button
                type="button"
                style={styles.secondaryButton}
                onClick={() => void handleCopyPassword(selected)}
                disabled={copying}
              >
                {copying ? "Kopyalanıyor..." : "Parolayı kopyala"}
              </button>
              {selected.vault.isOwner && (
                <button
                  type="button"
                  style={{ ...styles.secondaryButton, opacity: canEdit ? 1 : 0.5 }}
                  onClick={() => setMode("edit")}
                  disabled={!canEdit}
                  title={isOnline ? undefined : "Düzenleme ve silme için bağlantı gerekli"}
                >
                  Düzenle
                </button>
              )}
            </div>
          )}
        </div>

        <div className="pm-panel-body" style={{ padding: 18 }}>
          {banners}

          {mode === "create" ? (
            <NewItemForm
              data={data}
              isOnline={isOnline}
              onCreated={(itemId, message) => {
                setTab("personal");
                setSelectedItemId(itemId);
                setMode("view");
                setSuccess(message);
              }}
              onCancel={() => setMode("view")}
            />
          ) : !selected ? (
            <div className="pm-empty" style={{ minHeight: 240 }}>
              Detaylarını ve geçmişini görmek için soldan bir parola seç.
            </div>
          ) : mode === "edit" && selected.vault.id !== null ? (
            <EditItemForm
              key={selected.vault.itemId}
              item={{ id: selected.vault.id, title: selected.title, username: selected.username }}
              onCancel={() => setMode("view")}
              onSaved={() => {
                setMode("view");
                setError("");
                setSuccess("Parola güncellendi.");
              }}
              onDeleted={() => {
                setMode("view");
                setSelectedItemId(null);
                setError("");
                setSuccess("Kayıt silindi.");
              }}
            />
          ) : (
            <div>
              <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "8px 18px", margin: "0 0 24px", fontSize: 14 }}>
                <dt style={styles.muted}>Başlık</dt>
                <dd style={{ margin: 0 }}>{selected.title}</dd>
                <dt style={styles.muted}>Kullanıcı adı</dt>
                <dd style={{ margin: 0 }}>{selected.username || "—"}</dd>
                <dt style={styles.muted}>Parola</dt>
                <dd style={{ margin: 0, letterSpacing: 2 }}>••••••••</dd>
                <dt style={styles.muted}>Sahip</dt>
                <dd style={{ margin: 0 }}>{selected.vault.isOwner ? "Sen" : "Seninle paylaşılmış"}</dd>
                {selected.vault.pendingSync && (
                  <>
                    <dt style={styles.muted}>Durum</dt>
                    <dd style={{ margin: 0, color: "#fbbf24" }}>
                      {selected.vault.id === null
                        ? "Sunucuya gönderilmeyi bekliyor"
                        : "Paylaşım değişikliği gönderilmeyi bekliyor"}
                    </dd>
                  </>
                )}
              </dl>

              <div style={{ borderTop: "1px solid #27272a", paddingTop: 16 }}>
                {isOnline && selected.vault.id !== null ? (
                  <PasswordHistoryPanel key={selected.vault.id} id={selected.vault.id} />
                ) : (
                  <p style={styles.muted}>
                    {selected.vault.id === null
                      ? "Kayıt sunucuya gönderilince geçmiş tutulmaya başlar."
                      : "Geçmiş için bağlantı gerekli."}
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Sağ: yetkilendirme */}
      <section className="pm-panel" aria-label="Kullanıcılar ve departmanlar">
        <div className="pm-panel-header">
          <span>Kullanıcılar ve Departmanlar</span>
          <div style={{ display: "flex", gap: 2 }}>
            <button
              type="button"
              className="pm-icon-button"
              title="Hepsini aç"
              aria-label="Hepsini aç"
              onClick={() => setExpanded(new Set(allTreeKeys))}
            >
              <Icon>{icons.expand}</Icon>
            </button>
            <button
              type="button"
              className="pm-icon-button"
              title="Hepsini kapat"
              aria-label="Hepsini kapat"
              onClick={() => setExpanded(new Set())}
            >
              <Icon>{icons.collapse}</Icon>
            </button>
          </div>
        </div>

        <div style={{ padding: "8px 8px 0" }}>
          <input
            className="pm-search"
            value={userSearch}
            onChange={(event) => setUserSearch(event.target.value)}
            placeholder="Kullanıcı ara..."
            aria-label="Kullanıcı ara"
          />
        </div>

        <div className="pm-panel-body">
          {!selected ? (
            <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>
              Yetkilendirmek için soldan kendi parolalarından birini seç.
            </p>
          ) : !selected.vault.isOwner ? (
            <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>
              Bu parola seninle paylaşılmış; yalnızca sahibi yetkilendirebilir.
            </p>
          ) : !data.directory ? (
            <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>
              Kişi ve departman listesi henüz bu cihaza indirilmedi; bir kez çevrimiçi olunca
              çevrimdışı da yetkilendirme yapabilirsin.
            </p>
          ) : (
            <AuthorizationTree
              item={selected.vault}
              directory={data.directory}
              isOnline={isOnline}
              search={userSearch}
              expanded={expanded}
              setExpanded={setExpanded}
              onToggle={(target, granted) => data.setGrant(selected.vault.itemId, target, granted)}
            />
          )}
        </div>
      </section>
    </div>
  );
}
