import { useEffect, useMemo, useState } from "react";
import type React from "react";
import { invoke } from "@tauri-apps/api/core";
import { useConvex, useMutation, useQuery } from "convex/react";

import { api } from "../convex/_generated/api";
import type { Id } from "../convex/_generated/dataModel";
import { errorMessage } from "./errors";
import {
  toEncryptedItem,
  type ExtraPermissions,
  type Folder,
  grantOf,
  type GrantTarget,
  NO_EXTRA,
  type Permissions,
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
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />,
  folderPlus: (
    <>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
      <path d="M12 11v5" />
      <path d="M9.5 13.5h5" />
    </>
  ),
  keyPlus: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.85 12.15 6.15-6.15" />
      <path d="M19 3v6" />
      <path d="M16 6h6" />
    </>
  ),
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

type PermissionKey = "view" | "edit" | "delete" | "share";

const PERMISSION_LABELS: Record<PermissionKey, string> = {
  view: "Görüntüleme",
  edit: "Düzenleme",
  delete: "Silme",
  share: "Yetkilendirme",
};

const PERMISSION_KEYS: PermissionKey[] = ["view", "edit", "delete", "share"];

/** Kuralın yetkileri; kural yoksa hepsi kapalı. */
function asPermissions(extra: ExtraPermissions | null): Permissions {
  return extra ? { view: true, ...extra } : { view: false, ...NO_EXTRA };
}

function permissionState(permissions: Permissions): boolean | "mixed" {
  const on = PERMISSION_KEYS.filter((key) => permissions[key]).length;
  return on === 0 ? false : on === PERMISSION_KEYS.length ? true : "mixed";
}

/**
 * Bir kuralın yetki satırları. Görüntüleme diğerlerinin önkoşuludur: başka
 * bir yetki açılınca görüntüleme de açılır, görüntüleme kapanınca kural
 * kalkar. Çağıranda olmayan yetkiler değiştirilemez.
 */
function PermissionRows({
  name,
  current,
  actor,
  locked,
  inherited,
  onChange,
}: {
  name: string;
  current: Permissions;
  actor: Permissions;
  locked?: string;
  /** Departmandan gelen yetkiler (yalnız bilgi). */
  inherited?: Permissions | null;
  onChange: (next: Permissions) => void;
}) {
  return (
    <div style={{ marginLeft: 26, paddingLeft: 12, borderLeft: "1px solid #3f3f46" }}>
      {PERMISSION_KEYS.map((key) => {
        const allowed = !locked && (key === "view" || actor[key]);
        const fromDepartment = !current[key] && inherited?.[key];

        return (
          <div key={key} className="pm-tree-row">
            <Checkbox
              state={current[key] ? true : fromDepartment ? "mixed" : false}
              disabled={!allowed}
              label={`${name} için ${PERMISSION_LABELS[key]}`}
              title={
                locked ??
                (!allowed
                  ? "Sende olmayan bir yetkiyi veremezsin"
                  : fromDepartment
                    ? "Departmanı üzerinden açık"
                    : undefined)
              }
              onChange={(checked) =>
                onChange(
                  key === "view"
                    ? checked
                      ? { ...current, view: true }
                      : { view: false, ...NO_EXTRA }
                    : { ...current, view: current.view || checked, [key]: checked },
                )
              }
            />
            <span>{PERMISSION_LABELS[key]}</span>
            {fromDepartment && (
              <span style={{ ...styles.muted, fontSize: 11 }}>departmanından</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

type Directory = NonNullable<VaultData["directory"]>;
type DirectoryUser = Directory["users"][number];

/**
 * Sağ sütun: üstte departmanlar, altta kullanıcılar. Her satırın altında
 * yetki satırları (görüntüleme, düzenleme, silme, yetkilendirme) vardır; satırın kutucuğu bunları
 * özetler. Yalnızca yetkilendirme yetkisi olan değiştirebilir. Çevrimdışıyken
 * de değiştirilebilir: değişiklik kuyruğa alınır ve bağlantı gelince
 * gönderilir. Anahtar dağıtımı ve erişim kaldırıldığında yeniden şifreleme
 * arka planda otomatik yapılır.
 */
function AuthorizationColumn({
  item,
  data,
  isOnline,
  me,
}: {
  item: VaultItem | null;
  data: VaultData;
  isOnline: boolean;
  /** Oturumdaki kullanıcı; çevrimdışıyken bilinmez. */
  me: { role: string; departmentId: Id<"departments"> | null } | null;
}) {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const editable = item !== null && item.permissions.share && data.directory !== null;
  const actor = item?.permissions ?? { view: false, ...NO_EXTRA };
  // Sahip ve yöneticiler dışındakiler, erişimlerinin dayandığı kuralı
  // (bağlı oldukları departmanınkini) değiştiremez.
  const full = item?.isOwner === true || me?.role === "admin";

  // Anahtar durumu (erişim açık mı, hazırlanıyor mu) yalnızca sunucudan
  // öğrenilebilir.
  const live = useQuery(
    api.items.sharing,
    editable && isOnline && item.id ? { id: item.id } : "skip",
  );
  const keyStatus = new Map(live?.users.map((user) => [user.userId, user.hasKey]) ?? []);
  const grants = item?.grants ?? { userIds: [], departmentIds: [] };
  const directory = data.directory;

  const apply = (target: GrantTarget, next: Permissions) => {
    if (!item) return;
    if (!next.view) data.setGrant(item.itemId, target, false);
    else
      data.setGrant(item.itemId, target, true, {
        edit: next.edit,
        delete: next.delete,
        share: next.share,
      });
  };

  // Düğüm kutucuğu: hepsini aç (çağıranda olan yetkiler) ya da hepsini kapat.
  const applyAll = (target: GrantTarget, on: boolean) =>
    apply(
      target,
      on
        ? { view: true, edit: actor.edit, delete: actor.delete, share: actor.share }
        : { view: false, ...NO_EXTRA },
    );

  const flip = (key: string) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const setAll = (prefix: string, keys: string[], open: boolean) =>
    setExpanded((current) => {
      const next = new Set([...current].filter((key) => !key.startsWith(prefix)));
      if (open) keys.forEach((key) => next.add(key));
      return next;
    });

  const message = !item
    ? "Yetkilendirmek için soldan bir parola seç."
    : !item.permissions.share
      ? "Bu parolayı yetkilendirme yetkin yok."
      : !directory
        ? "Kişi ve departman listesi henüz bu cihaza indirilmedi; bir kez çevrimiçi olunca çevrimdışı da yetkilendirme yapabilirsin."
        : null;

  const departments = directory?.departments ?? [];
  const users = [...(directory?.users ?? [])].sort(
    (a, b) =>
      Number(b.isAdmin === true) - Number(a.isAdmin === true) ||
      a.displayName.localeCompare(b.displayName, "tr"),
  );

  const query = search.trim().toLocaleLowerCase("tr");
  const visibleUsers = users.filter(
    (user) =>
      !query ||
      user.displayName.toLocaleLowerCase("tr").includes(query) ||
      user.email.toLocaleLowerCase("tr").includes(query) ||
      (user.departmentName ?? "").toLocaleLowerCase("tr").includes(query),
  );

  function keyColor(user: DirectoryUser, allowed: boolean) {
    const hasKey = keyStatus.get(user.userId);
    if (!allowed) return "#71717a";
    if (hasKey === undefined || item?.pendingSync) return "#a1a1aa";
    return hasKey ? "#4ade80" : "#fbbf24";
  }

  const expandButtons = (prefix: string, keys: string[]) => (
    <div style={{ display: "flex", gap: 2 }}>
      <button
        type="button"
        className="pm-icon-button"
        title="Hepsini aç"
        aria-label="Hepsini aç"
        disabled={message !== null}
        onClick={() => setAll(prefix, keys, true)}
      >
        <Icon>{icons.expand}</Icon>
      </button>
      <button
        type="button"
        className="pm-icon-button"
        title="Hepsini kapat"
        aria-label="Hepsini kapat"
        disabled={message !== null}
        onClick={() => setAll(prefix, keys, false)}
      >
        <Icon>{icons.collapse}</Icon>
      </button>
    </div>
  );

  const placeholder = (text: string) => (
    <p style={{ ...styles.muted, fontSize: 13, padding: 6, margin: 0 }}>{text}</p>
  );

  return (
    <div className="pm-side">
      <section className="pm-panel" aria-label="Departmanlar">
        <div className="pm-panel-header">
          <span>Departmanlar</span>
          {expandButtons(
            "department:",
            departments.map((department) => `department:${department.id}`),
          )}
        </div>

        <div className="pm-panel-body">
          {message
            ? placeholder(message)
            : departments.length === 0
              ? placeholder("Henüz departman yok.")
              : departments.map((department) => {
                  const target: GrantTarget = { kind: "department", departmentId: department.id };
                  const current = asPermissions(grantOf(grants, target));
                  const ownDepartment = !full && me?.departmentId === department.id;
                  const granted = current.view;
                  const members = users.filter(
                    (user) => user.isAdmin !== true && user.departmentId === department.id,
                  );
                  const anyMember = members.some((user) => grants.userIds.includes(user.userId));
                  const key = `department:${department.id}`;
                  const open = expanded.has(key);

                  return (
                    <div key={department.id}>
                      <div className="pm-tree-row">
                        <Chevron
                          open={open}
                          onToggle={() => flip(key)}
                          label={`${department.name} yetkileri`}
                        />
                        <Checkbox
                          state={granted ? permissionState(current) : anyMember ? "mixed" : false}
                          label={`${department.name} departmanı için bütün yetkiler`}
                          disabled={ownDepartment}
                          title={
                            ownDepartment
                              ? "Bağlı olduğun departmanın yetkisini değiştiremezsin"
                              : !granted && anyMember
                                ? "Bazı üyelerine kişisel yetki verilmiş"
                                : undefined
                          }
                          onChange={(value) => applyAll(target, value)}
                        />
                        <span
                          style={{ color: granted ? "#4ade80" : "#a78bfa", display: "inline-flex" }}
                        >
                          <Icon size={15}>{icons.users}</Icon>
                        </span>
                        <span>{department.name}</span>
                        <span style={{ ...styles.muted, fontSize: 11 }}>
                          {members.length} kullanıcı
                        </span>
                      </div>

                      {open && (
                        <PermissionRows
                          name={`${department.name} departmanı`}
                          current={current}
                          actor={actor}
                          locked={
                            ownDepartment
                              ? "Bağlı olduğun departmanın yetkisini değiştiremezsin"
                              : undefined
                          }
                          onChange={(next) => apply(target, next)}
                        />
                      )}
                    </div>
                  );
                })}
        </div>
      </section>

      <section className="pm-panel" aria-label="Kullanıcılar">
        <div className="pm-panel-header">
          <span>Kullanıcılar</span>
          {expandButtons(
            "user:",
            users.map((user) => `user:${user.userId}`),
          )}
        </div>

        <div style={{ padding: "8px 8px 0" }}>
          <input
            className="pm-search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Kullanıcı ara..."
            aria-label="Kullanıcı ara"
            disabled={message !== null}
          />
        </div>

        <div className="pm-panel-body">
          {message
            ? placeholder(message)
            : visibleUsers.length === 0
              ? placeholder(query ? "Eşleşen kullanıcı yok." : "Başka kullanıcı yok.")
              : visibleUsers.map((user) => {
                  const isAdmin = user.isAdmin === true;
                  const isItemOwner = item !== null && user.userId === item.encrypted.ownerId;
                  const locked = isItemOwner
                    ? "Parolanın sahibi her şeyi yapabilir"
                    : isAdmin
                      ? "Yöneticiler bütün parolalarda her şeyi yapabilir"
                      : undefined;
                  const target: GrantTarget = { kind: "user", userId: user.userId };
                  const current = locked
                    ? { view: true, edit: true, delete: true, share: true }
                    : asPermissions(grantOf(grants, target));
                  const inherited =
                    user.departmentId !== null
                      ? asPermissions(
                          grantOf(grants, { kind: "department", departmentId: user.departmentId }),
                        )
                      : null;
                  const direct = current.view;
                  const viaDepartment = inherited?.view === true;
                  const allowed = direct || viaDepartment;
                  const key = `user:${user.userId}`;
                  const open = expanded.has(key);

                  const description = [
                    isItemOwner ? "Sahip" : null,
                    isAdmin ? "Yönetici" : user.departmentName,
                    user.status === "invited" ? "henüz kaydolmadı" : null,
                    allowed && keyStatus.get(user.userId) === false && !item?.pendingSync
                      ? "anahtar hazırlanıyor"
                      : null,
                  ]
                    .filter(Boolean)
                    .join(" · ");

                  return (
                    <div key={user.userId}>
                      <div className="pm-tree-row">
                        <Chevron
                          open={open}
                          onToggle={() => flip(key)}
                          label={`${user.displayName} yetkileri`}
                        />
                        <Checkbox
                          state={direct ? permissionState(current) : viaDepartment ? "mixed" : false}
                          disabled={locked !== undefined}
                          label={`${user.displayName} için bütün yetkiler`}
                          title={
                            locked ?? (!direct && viaDepartment ? "Departmanı üzerinden yetkili" : undefined)
                          }
                          onChange={(value) => applyAll(target, value)}
                        />
                        <span style={{ color: keyColor(user, allowed), display: "inline-flex" }}>
                          <Icon size={15}>{isAdmin ? icons.shield : icons.user}</Icon>
                        </span>
                        <span
                          style={{
                            minWidth: 0,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                          title={user.email}
                        >
                          {user.displayName}
                          {description && (
                            <span style={{ ...styles.muted, fontSize: 11, marginLeft: 8 }}>
                              {description}
                            </span>
                          )}
                        </span>
                      </div>

                      {open && (
                        <PermissionRows
                          name={user.displayName}
                          current={current}
                          actor={actor}
                          locked={locked}
                          inherited={locked ? null : inherited}
                          onChange={(next) => apply(target, next)}
                        />
                      )}
                    </div>
                  );
                })}
        </div>
      </section>
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

/** Silme yetkisi olup düzenleme yetkisi olmayanlar için yalnızca silme. */
function DeleteItemForm({
  id,
  onCancel,
  onDeleted,
}: {
  id: Id<"items">;
  onCancel: () => void;
  onDeleted: () => void;
}) {
  const removeItem = useMutation(api.items.remove);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  return (
    <div>
      <p style={{ ...styles.error, marginTop: 0 }}>
        Kayıt, paylaşılan herkes için kalıcı olarak silinecek. Bu işlem geri alınamaz.
      </p>
      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}
      <div style={{ display: "flex", gap: 8 }}>
        <button
          type="button"
          style={{ ...styles.button, background: "#dc2626" }}
          disabled={busy}
          onClick={() => {
            setBusy(true);
            setError("");
            removeItem({ id })
              .then(onDeleted)
              .catch((err: unknown) => {
                setError(errorMessage(err));
                setBusy(false);
              });
          }}
        >
          {busy ? "Siliniyor..." : "Evet, kalıcı olarak sil"}
        </button>
        <button type="button" style={styles.secondaryButton} onClick={onCancel} disabled={busy}>
          Vazgeç
        </button>
      </div>
    </div>
  );
}

/**
 * Kaydın başlığını, kullanıcı adını ve parolasını değiştirir. Düzenleme yetkisi olan
 * herkes düzenleyebilir. Her düzenleme yeni bir DEK ile yapılır ve erişimi olan
 * herkese yeniden paketlenir; parola alanı boş bırakılırsa mevcut parola
 * korunur.
 */
function EditItemForm({
  item,
  onCancel,
  onSaved,
  canDelete,
  onDeleted,
}: {
  item: { id: Id<"items">; title: string; username: string | null };
  onCancel: () => void;
  onSaved: () => void;
  canDelete: boolean;
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

      {canDelete && (
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
      )}
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
      : `${op.granted ? "Yetki güncellendi" : "Yetki kaldırıldı"}: ${titleOf(op.itemId)} → ${targetName(op.target)}`;

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

/** Klasör ağacı yardımcıları. */
function folderTree(folders: Folder[]) {
  const byId = new Map(folders.map((folder) => [folder.id, folder]));
  const children = new Map<Id<"folders"> | null, Folder[]>();

  for (const folder of folders) {
    const parent = folder.parentId && byId.has(folder.parentId) ? folder.parentId : null;
    children.set(parent, [...(children.get(parent) ?? []), folder]);
  }

  for (const list of children.values()) {
    list.sort((a, b) => a.name.localeCompare(b.name, "tr", { sensitivity: "base" }));
  }

  const path = (id: Id<"folders"> | null): Folder[] => {
    const chain: Folder[] = [];
    let current = id ? byId.get(id) : undefined;

    while (current && chain.length < 50) {
      chain.unshift(current);
      current = current.parentId ? byId.get(current.parentId) : undefined;
    }

    return chain;
  };

  const descendants = (id: Id<"folders">): Set<Id<"folders">> => {
    const result = new Set<Id<"folders">>([id]);
    const stack = [id];

    while (stack.length > 0) {
      for (const child of children.get(stack.pop()!) ?? []) {
        if (!result.has(child.id)) {
          result.add(child.id);
          stack.push(child.id);
        }
      }
    }

    return result;
  };

  return {
    byId,
    childrenOf: (id: Id<"folders"> | null) => children.get(id) ?? [],
    path,
    pathText: (id: Id<"folders"> | null) =>
      id && byId.has(id) ? path(id).map((folder) => folder.name).join(" / ") : "Kök",
    descendants,
  };
}

type FolderTree = ReturnType<typeof folderTree>;

/** Hedef klasör seçimi: kök ve klasörler, tam yolu ile. */
function FolderSelect({
  tree,
  value,
  exclude,
  onlyManageable = false,
  disabled,
  label,
  onChange,
}: {
  tree: FolderTree;
  value: Id<"folders"> | null;
  exclude?: Set<Id<"folders">>;
  /** Klasör taşırken yalnızca düzenlenebilen klasörler hedef olabilir. */
  onlyManageable?: boolean;
  disabled?: boolean;
  label: string;
  onChange: (folderId: Id<"folders"> | null) => void;
}) {
  const options = [...tree.byId.values()]
    .filter((folder) => (!onlyManageable || folder.canManage) && !exclude?.has(folder.id))
    .map((folder) => ({ id: folder.id, text: tree.pathText(folder.id) }))
    .sort((a, b) => a.text.localeCompare(b.text, "tr"));

  return (
    <select
      style={{ ...styles.input, marginBottom: 0, width: "auto", minWidth: 200 }}
      value={value ?? ""}
      disabled={disabled}
      aria-label={label}
      onChange={(event) => onChange((event.target.value || null) as Id<"folders"> | null)}
    >
      <option value="">Kök</option>
      {options.map((option) => (
        <option key={option.id} value={option.id}>
          {option.text}
        </option>
      ))}
    </select>
  );
}

function NewFolderForm({
  parentId,
  tree,
  onCreated,
  onCancel,
}: {
  parentId: Id<"folders"> | null;
  tree: FolderTree;
  onCreated: (id: Id<"folders">, name: string) => void;
  onCancel: () => void;
}) {
  const createFolder = useMutation(api.folders.create);
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  return (
    <form
      style={{ maxWidth: 520 }}
      onSubmit={(event) => {
        event.preventDefault();
        if (saving) return;
        setSaving(true);
        setError("");
        createFolder({ name, parentId: parentId ?? undefined })
          .then((id) => onCreated(id, name.trim()))
          .catch((err: unknown) => setError(errorMessage(err)))
          .finally(() => setSaving(false));
      }}
    >
      <h3 style={{ marginTop: 0 }}>Yeni klasör</h3>
      <p style={{ ...styles.muted, fontSize: 13 }}>Konum: {tree.pathText(parentId)}</p>

      <label htmlFor="folder-name">Klasör adı</label>
      <input
        id="folder-name"
        style={styles.input}
        value={name}
        onChange={(event) => setName(event.target.value)}
        maxLength={100}
        required
        autoFocus
      />

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}

      <div style={{ display: "flex", gap: 8 }}>
        <button type="submit" style={{ ...styles.button, opacity: saving ? 0.6 : 1 }} disabled={saving}>
          {saving ? "Oluşturuluyor..." : "Klasörü oluştur"}
        </button>
        <button type="button" style={styles.secondaryButton} onClick={onCancel} disabled={saving}>
          Vazgeç
        </button>
      </div>
    </form>
  );
}

/** Seçili klasörün bilgileri ve (yönetebiliyorsa) ad, konum, silme. */
function FolderDetail({
  folder,
  tree,
  itemCount,
  isOnline,
  onMessage,
  onDeleted,
}: {
  folder: Folder;
  tree: FolderTree;
  itemCount: number;
  isOnline: boolean;
  onMessage: (message: string) => void;
  onDeleted: () => void;
}) {
  const renameFolder = useMutation(api.folders.rename);
  const moveFolder = useMutation(api.folders.move);
  const removeFolder = useMutation(api.folders.remove);

  const [name, setName] = useState(folder.name);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setName(folder.name);
    setConfirming(false);
    setError("");
  }, [folder.id, folder.name]);

  const editable = folder.canManage && isOnline;

  function run(task: () => Promise<unknown>, message: string, after?: () => void) {
    if (busy) return;
    setBusy(true);
    setError("");
    task()
      .then(() => {
        onMessage(message);
        after?.();
      })
      .catch((err: unknown) => setError(errorMessage(err)))
      .finally(() => setBusy(false));
  }

  return (
    <div>
      <dl style={detailGrid}>
        <dt style={styles.muted}>Konum</dt>
        <dd style={{ margin: 0 }}>{tree.pathText(folder.parentId)}</dd>
        <dt style={styles.muted}>İçerik</dt>
        <dd style={{ margin: 0 }}>
          {tree.childrenOf(folder.id).length} klasör, {itemCount} parola
        </dd>
        <dt style={styles.muted}>Sahip</dt>
        <dd style={{ margin: 0 }}>{folder.isOwner ? "Sen" : "Başka bir kullanıcı"}</dd>
      </dl>

      {!folder.canManage ? (
        <p style={styles.muted}>
          Bu klasörü yalnızca oluşturan departman yöneticisi ya da bir yönetici düzenleyebilir.
          Kendi parolalarını bu klasöre koyabilirsin.
        </p>
      ) : (
        <div style={{ display: "grid", gap: 18, borderTop: "1px solid #27272a", paddingTop: 16 }}>
          {!isOnline && <p style={{ ...styles.muted, margin: 0 }}>Klasör işlemleri için bağlantı gerekli.</p>}

          <form
            style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}
            onSubmit={(event) => {
              event.preventDefault();
              run(() => renameFolder({ id: folder.id, name }), "Klasör adı güncellendi.");
            }}
          >
            <label htmlFor="folder-rename" style={{ ...styles.muted, minWidth: 70 }}>
              Ad
            </label>
            <input
              id="folder-rename"
              style={{ ...styles.input, marginBottom: 0, marginTop: 0, flex: 1, minWidth: 180 }}
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={100}
              disabled={!editable || busy}
              required
            />
            <button
              type="submit"
              style={styles.secondaryButton}
              disabled={!editable || busy || name.trim() === folder.name}
            >
              Kaydet
            </button>
          </form>

          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ ...styles.muted, minWidth: 70 }}>Taşı</span>
            <FolderSelect
              tree={tree}
              value={folder.parentId}
              exclude={tree.descendants(folder.id)}
              onlyManageable
              disabled={!editable || busy}
              label="Klasörün taşınacağı yer"
              onChange={(parentId) =>
                run(() => moveFolder({ id: folder.id, parentId }), "Klasör taşındı.")
              }
            />
          </div>

          <div>
            {confirming ? (
              <>
                <p style={{ ...styles.error, marginTop: 0 }}>
                  Klasör silinecek. İçindeki {itemCount} parola ve{" "}
                  {tree.childrenOf(folder.id).length} alt klasör "{tree.pathText(folder.parentId)}"
                  konumuna taşınır; hiçbir parola silinmez.
                </p>
                <div style={{ display: "flex", gap: 8 }}>
                  <button
                    type="button"
                    style={{ ...styles.button, background: "#dc2626" }}
                    disabled={!editable || busy}
                    onClick={() =>
                      run(() => removeFolder({ id: folder.id }), "Klasör silindi.", onDeleted)
                    }
                  >
                    {busy ? "Siliniyor..." : "Evet, klasörü sil"}
                  </button>
                  <button
                    type="button"
                    style={styles.secondaryButton}
                    onClick={() => setConfirming(false)}
                    disabled={busy}
                  >
                    Vazgeç
                  </button>
                </div>
              </>
            ) : (
              <button
                type="button"
                style={{ ...styles.secondaryButton, color: "#f87171" }}
                onClick={() => setConfirming(true)}
                disabled={!editable || busy}
              >
                Klasörü sil
              </button>
            )}
          </div>
        </div>
      )}

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}
    </div>
  );
}

const detailGrid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "max-content 1fr",
  gap: "8px 18px",
  margin: "0 0 24px",
  fontSize: 14,
};

/** Yeni parola formu; kayıt önce bu cihazda kuyruğa alınır. */
function NewItemForm({
  data,
  isOnline,
  folderId,
  tree,
  onCreated,
  onCancel,
}: {
  data: VaultData;
  isOnline: boolean;
  folderId: Id<"folders"> | null;
  tree: FolderTree;
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

      data.addItem(encrypted, folderId);
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
      <p style={{ ...styles.muted, fontSize: 13 }}>Konum: {tree.pathText(folderId)}</p>

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

export default function PasswordManager({ data, isOnline }: PasswordManagerProps) {
  const pendingSharedCount = useQuery(api.items.pendingSharedCount, isOnline ? {} : "skip");
  const me = useQuery(api.users.me, isOnline ? {} : "skip");
  // Klasörleri yalnızca yöneticiler ve departman yöneticileri oluşturur.
  const canCreateFolders = me?.role === "admin" || me?.role === "manager";

  const [metadataByItemId, setMetadataByItemId] = useState<
    Record<string, DecryptedMetadata>
  >({});

  const [itemSearch, setItemSearch] = useState("");
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [selectedFolderId, setSelectedFolderId] = useState<Id<"folders"> | null>(null);
  const [openFolders, setOpenFolders] = useState<Set<Id<"folders">>>(new Set());
  const [mode, setMode] = useState<"view" | "edit" | "create" | "createFolder">("view");
  const moveItem = useMutation(api.items.move);
  const [moving, setMoving] = useState(false);

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

  const tree = useMemo(() => folderTree(data.folders), [data.folders]);
  const selectedFolder = selectedFolderId ? (tree.byId.get(selectedFolderId) ?? null) : null;

  const query = itemSearch.trim().toLocaleLowerCase("tr");
  const listed = items.filter(
    (item) =>
      !query ||
      item.title.toLocaleLowerCase("tr").includes(query) ||
      (item.username ?? "").toLocaleLowerCase("tr").includes(query),
  );

  const selected = items.find((item) => item.vault.itemId === selectedItemId) ?? null;

  // Kayıtların klasörlere göre dağılımı; görünmeyen klasördekiler köke düşer.
  const itemsByFolder = useMemo(() => {
    const map = new Map<Id<"folders"> | null, PasswordItem[]>();
    for (const item of items) {
      const folderId = item.vault.folderId && tree.byId.has(item.vault.folderId) ? item.vault.folderId : null;
      map.set(folderId, [...(map.get(folderId) ?? []), item]);
    }
    return map;
  }, [items, tree]);

  const countInside = (id: Id<"folders">): number =>
    (itemsByFolder.get(id)?.length ?? 0) +
    tree.childrenOf(id).reduce((sum, child) => sum + countInside(child.id), 0);

  // Yeni kaydın konumu: seçili klasör ya da seçili kaydın klasörü, yoksa
  // kök. Yeni klasör yalnızca düzenlenebilen bir klasörün altına açılır.
  const contextFolderId =
    (selectedFolder?.id ?? selected?.vault.folderId ?? null) as Id<"folders"> | null;
  const itemTargetId = contextFolderId && tree.byId.has(contextFolderId) ? contextFolderId : null;
  const folderTargetId =
    contextFolderId && tree.byId.get(contextFolderId)?.canManage ? contextFolderId : null;

  function clearMessages() {
    setError("");
    setSuccess("");
  }

  function select(itemId: string) {
    setSelectedItemId(itemId);
    setSelectedFolderId(null);
    setMode("view");
    clearMessages();
  }

  function selectFolder(id: Id<"folders">) {
    setSelectedFolderId(id);
    setSelectedItemId(null);
    setMode("view");
    clearMessages();
  }

  const toggleFolder = (id: Id<"folders">) =>
    setOpenFolders((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Seçilen kaydın/klasörün yolundaki klasörler açık tutulur.
  useEffect(() => {
    if (!contextFolderId) return;
    const chain = tree.path(contextFolderId).map((folder) => folder.id);
    setOpenFolders((current) =>
      chain.every((id) => current.has(id)) ? current : new Set([...current, ...chain]),
    );
  }, [contextFolderId, tree]);

  function handleMove(item: PasswordItem, folderId: Id<"folders"> | null) {
    if (!item.vault.id || moving) return;
    setMoving(true);
    clearMessages();
    moveItem({ id: item.vault.id, folderId })
      .then(() => setSuccess(`Parola "${tree.pathText(folderId)}" konumuna taşındı.`))
      .catch((err: unknown) => setError(errorMessage(err)))
      .finally(() => setMoving(false));
  }

  const itemRow = (item: PasswordItem, depth: number, showPath = false) => (
    <button
      key={item.vault.itemId}
      type="button"
      className={`pm-row${item.vault.itemId === selectedItemId ? " selected" : ""}`}
      style={{ paddingLeft: 10 + depth * 18 + (depth > 0 ? 18 : 0) }}
      onClick={() => select(item.vault.itemId)}
    >
      <span style={{ color: item.vault.isOwner ? "#f59e0b" : "#a78bfa", display: "inline-flex" }}>
        <Icon size={15}>{icons.key}</Icon>
      </span>
      <span style={{ minWidth: 0, flex: 1 }}>
        <span style={ellipsis}>{item.title}</span>
        {(showPath || item.username) && (
          <span style={{ ...ellipsis, ...styles.muted, fontSize: 11 }}>
            {showPath ? tree.pathText(item.vault.folderId) : item.username}
          </span>
        )}
      </span>
      {item.vault.pendingSync && (
        <span
          title="Sunucuya gönderilmeyi bekliyor"
          style={{ width: 7, height: 7, borderRadius: "50%", background: "#fbbf24" }}
        />
      )}
    </button>
  );

  const renderLevel = (parentId: Id<"folders"> | null, depth: number): React.ReactNode[] => [
    ...tree.childrenOf(parentId).map((folder) => {
      const open = openFolders.has(folder.id);
      const count = countInside(folder.id);

      return (
        <div key={folder.id}>
          <div
            className={`pm-row${folder.id === selectedFolderId ? " selected" : ""}`}
            style={{ paddingLeft: 6 + depth * 18 }}
            role="button"
            tabIndex={0}
            onClick={() => selectFolder(folder.id)}
            onDoubleClick={() => toggleFolder(folder.id)}
            onKeyDown={(event) => {
              if (event.key === "Enter") selectFolder(folder.id);
            }}
          >
            <span
              onClick={(event) => {
                event.stopPropagation();
                toggleFolder(folder.id);
              }}
              style={{ display: "inline-flex" }}
            >
              <Chevron open={open} onToggle={() => undefined} label={`${folder.name} klasörünü aç`} />
            </span>
            <span style={{ color: "#f59e0b", display: "inline-flex" }}>
              <Icon size={15}>{icons.folder}</Icon>
            </span>
            <span style={{ ...ellipsis, flex: 1 }}>{folder.name}</span>
            <span style={{ ...styles.muted, fontSize: 11 }}>{count}</span>
          </div>
          {open && renderLevel(folder.id, depth + 1)}
        </div>
      );
    }),
    ...(itemsByFolder.get(parentId) ?? []).map((item) => itemRow(item, depth)),
  ];

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
        <div className="pm-panel-header">
          <span>
            Parolalar
            <span style={{ ...styles.muted, fontSize: 11, marginLeft: 8, fontWeight: 400 }}>
              {items.length}
            </span>
          </span>
          <div style={{ display: "flex", gap: 2 }}>
            <button
              type="button"
              className="pm-icon-button"
              title={`Yeni parola (${tree.pathText(itemTargetId)})`}
              aria-label="Yeni parola"
              onClick={() => {
                setMode("create");
                clearMessages();
              }}
              disabled={!data.loaded}
            >
              <Icon>{icons.keyPlus}</Icon>
            </button>
            {canCreateFolders && (
              <button
                type="button"
                className="pm-icon-button"
                title={`Yeni klasör (${tree.pathText(folderTargetId)})`}
                aria-label="Yeni klasör"
                onClick={() => {
                  setMode("createFolder");
                  clearMessages();
                }}
                disabled={!data.loaded || !isOnline}
              >
                <Icon>{icons.folderPlus}</Icon>
              </button>
            )}
          </div>
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
          ) : query ? (
            listed.length === 0 ? (
              <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>Eşleşen parola yok.</p>
            ) : (
              listed.map((item) => itemRow(item, 0, true))
            )
          ) : items.length === 0 && data.folders.length === 0 ? (
            <p style={{ ...styles.muted, fontSize: 13, padding: 6 }}>
              {isOnline || data.syncedAt !== null
                ? "Henüz parola yok. Eklemek için yukarıdaki düğmeyi kullan."
                : "Bu cihazda henüz eşitlenmiş parola yok."}
            </p>
          ) : (
            renderLevel(null, 0)
          )}
        </div>
      </section>

      {/* Orta: seçili parolanın detayı ve geçmişi */}
      <section className="pm-panel" aria-label="Parola detayı">
        <div className="pm-panel-header">
          <span style={ellipsis}>
            {mode === "create"
              ? "Yeni parola"
              : mode === "createFolder"
                ? "Yeni klasör"
                : selectedFolder
                  ? selectedFolder.name
                  : (selected?.title ?? "Detay")}
          </span>
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
              {(selected.vault.permissions.edit || selected.vault.permissions.delete) && (
                <button
                  type="button"
                  style={{ ...styles.secondaryButton, opacity: canEdit ? 1 : 0.5 }}
                  onClick={() => setMode("edit")}
                  disabled={!canEdit}
                  title={isOnline ? undefined : "Düzenleme ve silme için bağlantı gerekli"}
                >
                  {selected.vault.permissions.edit ? "Düzenle" : "Sil"}
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
              folderId={itemTargetId}
              tree={tree}
              onCreated={(itemId, message) => {
                setSelectedItemId(itemId);
                setSelectedFolderId(null);
                setMode("view");
                setSuccess(message);
              }}
              onCancel={() => setMode("view")}
            />
          ) : mode === "createFolder" ? (
            <NewFolderForm
              parentId={folderTargetId}
              tree={tree}
              onCreated={(id, name) => {
                setSelectedFolderId(id);
                setSelectedItemId(null);
                setMode("view");
                setSuccess(`"${name}" klasörü oluşturuldu.`);
              }}
              onCancel={() => setMode("view")}
            />
          ) : selectedFolder ? (
            <FolderDetail
              folder={selectedFolder}
              tree={tree}
              itemCount={itemsByFolder.get(selectedFolder.id)?.length ?? 0}
              isOnline={isOnline}
              onMessage={(message) => {
                setError("");
                setSuccess(message);
              }}
              onDeleted={() => setSelectedFolderId(null)}
            />
          ) : !selected ? (
            <div className="pm-empty" style={{ minHeight: 240 }}>
              Detaylarını ve geçmişini görmek için soldan bir parola seç.
            </div>
          ) : mode === "edit" && selected.vault.id !== null && !selected.vault.permissions.edit ? (
            <DeleteItemForm
              id={selected.vault.id}
              onCancel={() => setMode("view")}
              onDeleted={() => {
                setMode("view");
                setSelectedItemId(null);
                setError("");
                setSuccess("Kayıt silindi.");
              }}
            />
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
              canDelete={selected.vault.permissions.delete}
              onDeleted={() => {
                setMode("view");
                setSelectedItemId(null);
                setError("");
                setSuccess("Kayıt silindi.");
              }}
            />
          ) : (
            <div>
              <dl style={detailGrid}>
                <dt style={styles.muted}>Başlık</dt>
                <dd style={{ margin: 0 }}>{selected.title}</dd>
                <dt style={styles.muted}>Kullanıcı adı</dt>
                <dd style={{ margin: 0 }}>{selected.username || "—"}</dd>
                <dt style={styles.muted}>Parola</dt>
                <dd style={{ margin: 0, letterSpacing: 2 }}>••••••••</dd>
                <dt style={styles.muted}>Sahip</dt>
                <dd style={{ margin: 0 }}>{selected.vault.isOwner ? "Sen" : "Seninle paylaşılmış"}</dd>
                <dt style={styles.muted}>Yetkilerin</dt>
                <dd style={{ margin: 0 }}>
                  {PERMISSION_KEYS.filter((key) => selected.vault.permissions[key])
                    .map((key) => PERMISSION_LABELS[key])
                    .join(", ")}
                </dd>
                <dt style={{ ...styles.muted, alignSelf: "center" }}>Klasör</dt>
                <dd style={{ margin: 0 }}>
                  {selected.vault.isOwner && isOnline && selected.vault.id !== null ? (
                    <FolderSelect
                      tree={tree}
                      value={selected.vault.folderId && tree.byId.has(selected.vault.folderId) ? selected.vault.folderId : null}
                      disabled={moving}
                      label="Parolanın klasörü"
                      onChange={(folderId) => handleMove(selected, folderId)}
                    />
                  ) : (
                    tree.pathText(selected.vault.folderId)
                  )}
                </dd>
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

      {/* Sağ: yetkilendirme (departmanlar ve kullanıcılar) */}
      <AuthorizationColumn
        item={selectedFolder ? null : (selected?.vault ?? null)}
        data={data}
        isOnline={isOnline}
        me={me ? { role: me.role, departmentId: me.departmentId } : null}
      />
    </div>
  );
}

const ellipsis: React.CSSProperties = {
  display: "block",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
