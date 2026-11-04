import { invoke } from "@tauri-apps/api/core";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import type React from "react";

import { api } from "../../convex/_generated/api";
import type { Id } from "../../convex/_generated/dataModel";
import { errorMessage } from "../errors";

type Me = NonNullable<FunctionReturnType<typeof api.users.me>>;
type Role = Me["role"];

const DEFAULT_DEPARTMENTS = ["Yazılım", "Satış", "Destek", "Diğer"];

export const ROLE_LABELS: Record<Role, string> = {
  admin: "Yönetici",
  manager: "Departman Yöneticisi",
  member: "Personel",
};

// Sunucudaki `INVITE_TTL_HOURS` ile aynı.
const INVITE_DURATIONS = [
  { hours: 24, label: "24 saat" },
  { hours: 72, label: "3 gün" },
  { hours: 168, label: "7 gün" },
];

type PreparedInvite = { code: string; publicKey: string; verifier: string };

/** Davet kodunu bu cihazda üretir; sunucuya yalnızca koddan türetilen açık
 * anahtar ve doğrulayıcı gider. */
async function prepareInvite(email: string) {
  return await invoke<PreparedInvite>("prepare_invite", { email: email.trim().toLowerCase() });
}

const STATUS_LABELS = {
  invited: "Davet edildi",
  active: "Aktif",
  disabled: "Devre dışı",
} as const;

const styles: Record<string, React.CSSProperties> = {
  section: {
    background: "#111318",
    color: "#e5e7eb",
    border: "1px solid #292d36",
    borderRadius: 14,
    padding: 24,
    marginTop: 24,
  },
  input: {
    background: "#1b1f27",
    color: "#f3f4f6",
    border: "1px solid #353b48",
    borderRadius: 8,
    padding: "9px 11px",
    minWidth: 0,
  },
  button: {
    background: "#6366f1",
    color: "#fff",
    border: 0,
    borderRadius: 8,
    padding: "9px 14px",
    cursor: "pointer",
  },
  secondaryButton: {
    background: "#292d36",
    color: "#e5e7eb",
    border: "1px solid #353b48",
    borderRadius: 8,
    padding: "8px 12px",
    cursor: "pointer",
  },
  row: {
    display: "flex",
    gap: 8,
    flexWrap: "wrap",
    alignItems: "center",
  },
  muted: { color: "#9ca3af", fontSize: 13 },
  error: { color: "#f87171", overflowWrap: "anywhere" },
  success: { color: "#4ade80", overflowWrap: "anywhere" },
};

type Department = FunctionReturnType<typeof api.departments.list>[number];
type Member = FunctionReturnType<typeof api.members.list>[number];

/** Departmandaki bir kullanıcı için seçilen işlem: `move:<departmanId>` ya da `delete`. */
type Choice = string;

function choiceLabel(member: Member) {
  return member.ownedItemCount > 0
    ? `Kullanıcıyı sil (kendi ${member.ownedItemCount} parolası da silinir)`
    : "Kullanıcıyı sil";
}

/**
 * Departman silme: departmandaki her kullanıcı için başka bir departmana
 * taşıma ya da silme seçilir. Herkese aynı işlem tek seçimle de uygulanabilir.
 */
function DeleteDepartmentPanel({
  department,
  departments,
  members,
  busy,
  onCancel,
  onConfirm,
}: {
  department: Department;
  departments: Department[];
  members: Member[];
  busy: boolean;
  onCancel: () => void;
  onConfirm: (
    assignments: (
      | { userId: Id<"users">; action: "move"; departmentId: Id<"departments"> }
      | { userId: Id<"users">; action: "delete" }
    )[],
  ) => void;
}) {
  const targets = departments.filter((candidate) => candidate.id !== department.id);
  const [choices, setChoices] = useState<Record<string, Choice>>({});

  const options = (member: Member | null) => (
    <>
      <option value="">İşlem seç</option>
      {targets.map((target) => (
        <option key={target.id} value={`move:${target.id}`}>
          {target.name} departmanına taşı
        </option>
      ))}
      {(member === null || !member.isSelf) && (
        <option value="delete">{member ? choiceLabel(member) : "Kullanıcıları sil"}</option>
      )}
    </>
  );

  const applyToAll = (choice: Choice) =>
    setChoices(
      Object.fromEntries(
        members.map((member) => [
          member.id,
          choice === "delete" && member.isSelf ? (choices[member.id] ?? "") : choice,
        ]),
      ),
    );

  const complete = members.every((member) => (choices[member.id] ?? "") !== "");
  const deleting = members.filter((member) => choices[member.id] === "delete");

  return (
    <div
      style={{
        marginTop: 12,
        padding: 14,
        border: "1px solid #5b2b2b",
        borderRadius: 10,
        background: "#1f1416",
      }}
    >
      <strong>{department.name} departmanını sil</strong>

      {members.length === 0 ? (
        <p style={styles.muted}>Bu departmanda kullanıcı yok.</p>
      ) : (
        <>
          <p style={styles.muted}>
            Bu departmana bağlı {members.length} kullanıcı var. Her biri için ne yapılacağını seç.
          </p>

          <div style={{ ...styles.row, marginBottom: 12 }}>
            <span style={styles.muted}>Herkese uygula:</span>
            <select
              style={styles.input}
              value=""
              onChange={(event) => event.target.value && applyToAll(event.target.value)}
              aria-label="Bütün kullanıcılara aynı işlemi uygula"
              disabled={busy}
            >
              {options(null)}
            </select>
          </div>

          <div style={{ display: "grid", gap: 8 }}>
            {members.map((member) => (
              <div key={member.id} style={{ ...styles.row, justifyContent: "space-between" }}>
                <span style={{ overflowWrap: "anywhere" }}>
                  {member.displayName ?? member.email}
                  {member.isSelf && " (sen)"}
                  <span style={{ ...styles.muted, marginLeft: 8 }}>{member.email}</span>
                </span>
                <select
                  style={styles.input}
                  value={choices[member.id] ?? ""}
                  onChange={(event) =>
                    setChoices((current) => ({ ...current, [member.id]: event.target.value }))
                  }
                  aria-label={`${member.email} için işlem`}
                  disabled={busy}
                >
                  {options(member)}
                </select>
              </div>
            ))}
          </div>
        </>
      )}

      {deleting.length > 0 && (
        <p style={{ ...styles.error, fontSize: 13 }}>
          {deleting.length} kullanıcı ve kendi parolaları kalıcı olarak silinecek.
        </p>
      )}

      <p style={styles.muted}>
        Departmanla yapılan paylaşımlar kalkar; o parolalar sahiplerinin cihazında yeniden
        şifrelenir.
      </p>

      <div style={styles.row}>
        <button
          type="button"
          style={{ ...styles.button, background: "#dc2626", opacity: complete ? 1 : 0.5 }}
          disabled={busy || !complete}
          onClick={() =>
            onConfirm(
              members.map((member) => {
                const choice = choices[member.id];
                return choice === "delete"
                  ? { userId: member.id, action: "delete" as const }
                  : {
                      userId: member.id,
                      action: "move" as const,
                      departmentId: choice.slice("move:".length) as Id<"departments">,
                    };
              }),
            )
          }
        >
          Departmanı sil
        </button>
        <button type="button" style={styles.secondaryButton} disabled={busy} onClick={onCancel}>
          Vazgeç
        </button>
      </div>
    </div>
  );
}

export default function AdminPanel({ me }: { me: Me }) {
  const isAdmin = me.role === "admin";

  const departments = useQuery(api.departments.list);
  const members = useQuery(api.members.list);

  const createDepartment = useMutation(api.departments.create);
  const createDefaultDepartments = useMutation(api.departments.createDefaults);
  const renameDepartment = useMutation(api.departments.rename);
  const removeDepartment = useMutation(api.departments.remove);
  const inviteMember = useMutation(api.members.invite);
  const renewInvite = useMutation(api.members.renewInvite);
  const updateMember = useMutation(api.members.update);

  const [departmentName, setDepartmentName] = useState("");
  const [editingDepartment, setEditingDepartment] = useState<{
    id: Id<"departments">;
    mode: "rename" | "delete";
    name: string;
  } | null>(null);
  // "" bütün kullanıcılar, "none" departmansızlar.
  const [departmentFilter, setDepartmentFilter] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("member");
  const [inviteDepartmentId, setInviteDepartmentId] = useState<string>(
    me.departmentId ?? "",
  );
  const [inviteHours, setInviteHours] = useState(168);

  // Davet kodu yalnızca üretildiği anda gösterilir; sunucuda özeti tutulur.
  const [issuedInvite, setIssuedInvite] = useState<{
    email: string;
    code: string;
    expiresAt: number;
  } | null>(null);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function run(task: () => Promise<unknown>, message: string) {
    if (busy) return;

    setBusy(true);
    setError("");
    setSuccess("");

    try {
      await task();
      setSuccess(message);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const missingDefaults = DEFAULT_DEPARTMENTS.filter(
    (name) => !departments?.some((department) => department.name === name),
  );

  const hasDepartments = (departments?.length ?? 0) > 0;

  return (
    <>
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

      {isAdmin && (
        <section style={styles.section}>
          <h2 style={{ marginTop: 0 }}>Departmanlar</h2>

          {departments === undefined ? (
            <p style={styles.muted}>Yükleniyor...</p>
          ) : departments.length === 0 ? (
            <p style={styles.muted}>
              Kullanıcı davet etmeden önce departmanları oluştur.
            </p>
          ) : (
            <div style={{ display: "grid", gap: 8, marginBottom: 16 }}>
              {departments.map((department) => {
                const editing =
                  editingDepartment?.id === department.id ? editingDepartment : null;
                const memberCount =
                  members?.filter((member) => member.departmentId === department.id).length ?? 0;

                return (
                  <div
                    key={department.id}
                    style={{ paddingBottom: 8, borderBottom: "1px solid #292d36" }}
                  >
                    {editing?.mode === "rename" ? (
                      <form
                        style={styles.row}
                        onSubmit={(event) => {
                          event.preventDefault();
                          void run(async () => {
                            await renameDepartment({ id: department.id, name: editing.name });
                            setEditingDepartment(null);
                          }, "Departman adı güncellendi.");
                        }}
                      >
                        <input
                          style={{ ...styles.input, flex: 1 }}
                          value={editing.name}
                          onChange={(event) =>
                            setEditingDepartment({ ...editing, name: event.target.value })
                          }
                          aria-label={`${department.name} için yeni ad`}
                          maxLength={60}
                          required
                          autoFocus
                        />
                        <button type="submit" style={styles.button} disabled={busy}>
                          Kaydet
                        </button>
                        <button
                          type="button"
                          style={styles.secondaryButton}
                          disabled={busy}
                          onClick={() => setEditingDepartment(null)}
                        >
                          Vazgeç
                        </button>
                      </form>
                    ) : (
                      <div style={{ ...styles.row, justifyContent: "space-between" }}>
                        <span>
                          {department.name}
                          <span style={{ ...styles.muted, marginLeft: 8 }}>
                            {memberCount} kullanıcı
                          </span>
                        </span>
                        <div style={styles.row}>
                          <button
                            type="button"
                            style={styles.secondaryButton}
                            disabled={busy}
                            onClick={() =>
                              setEditingDepartment({
                                id: department.id,
                                mode: "rename",
                                name: department.name,
                              })
                            }
                          >
                            Yeniden adlandır
                          </button>
                          <button
                            type="button"
                            style={styles.secondaryButton}
                            disabled={busy || members === undefined}
                            onClick={() =>
                              setEditingDepartment(
                                editing?.mode === "delete"
                                  ? null
                                  : { id: department.id, mode: "delete", name: department.name },
                              )
                            }
                          >
                            Sil
                          </button>
                        </div>
                      </div>
                    )}

                    {editing?.mode === "delete" && members !== undefined && (
                      <DeleteDepartmentPanel
                        department={department}
                        departments={departments}
                        members={members.filter((member) => member.departmentId === department.id)}
                        busy={busy}
                        onCancel={() => setEditingDepartment(null)}
                        onConfirm={(assignments) =>
                          void run(async () => {
                            await removeDepartment({ id: department.id, assignments });
                            setEditingDepartment(null);
                          }, `${department.name} departmanı silindi.`)
                        }
                      />
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {missingDefaults.length > 0 && (
            <button
              type="button"
              style={{ ...styles.button, marginBottom: 16 }}
              disabled={busy}
              onClick={() =>
                void run(
                  () => createDefaultDepartments(),
                  "Varsayılan departmanlar oluşturuldu.",
                )
              }
            >
              {missingDefaults.join(", ")} departmanlarını oluştur
            </button>
          )}

          <form
            style={styles.row}
            onSubmit={(event) => {
              event.preventDefault();
              void run(async () => {
                await createDepartment({ name: departmentName });
                setDepartmentName("");
              }, "Departman oluşturuldu.");
            }}
          >
            <input
              style={{ ...styles.input, flex: 1 }}
              value={departmentName}
              onChange={(event) => setDepartmentName(event.target.value)}
              placeholder="Yeni departman adı"
              aria-label="Yeni departman adı"
              maxLength={60}
              required
            />
            <button type="submit" style={styles.secondaryButton} disabled={busy}>
              Ekle
            </button>
          </form>
        </section>
      )}

      <section style={styles.section}>
        <h2 style={{ marginTop: 0 }}>Kullanıcılar</h2>

        <form
          style={{ ...styles.row, marginBottom: 20 }}
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              const prepared = await prepareInvite(inviteEmail);
              const { expiresAt } = await inviteMember({
                email: inviteEmail,
                role: inviteRole,
                departmentId:
                  inviteRole === "admin" && !inviteDepartmentId
                    ? undefined
                    : (inviteDepartmentId as Id<"departments">),
                publicKey: prepared.publicKey,
                verifier: prepared.verifier,
                expiresInHours: inviteHours,
              });
              setIssuedInvite({
                email: inviteEmail.trim().toLowerCase(),
                code: prepared.code,
                expiresAt,
              });
              setInviteEmail("");
            }, "Kullanıcı davet edildi.");
          }}
        >
          <input
            style={{ ...styles.input, flex: 2 }}
            type="email"
            value={inviteEmail}
            onChange={(event) => setInviteEmail(event.target.value)}
            placeholder="kullanici@sirket.com"
            aria-label="Davet edilecek e-posta"
            required
          />

          <select
            style={styles.input}
            value={inviteDepartmentId}
            onChange={(event) => setInviteDepartmentId(event.target.value)}
            aria-label="Departman"
            disabled={!isAdmin}
            required={inviteRole !== "admin"}
          >
            <option value="">Departman seç</option>
            {departments?.map((department) => (
              <option key={department.id} value={department.id}>
                {department.name}
              </option>
            ))}
          </select>

          {isAdmin && (
            <select
              style={styles.input}
              value={inviteRole}
              onChange={(event) => setInviteRole(event.target.value as Role)}
              aria-label="Rol"
            >
              <option value="member">{ROLE_LABELS.member}</option>
              <option value="manager">{ROLE_LABELS.manager}</option>
              <option value="admin">{ROLE_LABELS.admin}</option>
            </select>
          )}

          <select
            style={styles.input}
            value={inviteHours}
            onChange={(event) => setInviteHours(Number(event.target.value))}
            aria-label="Davetin geçerlilik süresi"
          >
            {INVITE_DURATIONS.map((duration) => (
              <option key={duration.hours} value={duration.hours}>
                {duration.label}
              </option>
            ))}
          </select>

          <button
            type="submit"
            style={styles.button}
            disabled={busy || (!hasDepartments && inviteRole !== "admin")}
          >
            Davet et
          </button>
        </form>

        {issuedInvite && (
          <div
            role="status"
            style={{
              marginBottom: 20,
              padding: 14,
              border: "1px solid #3b3151",
              borderRadius: 10,
              background: "#191422",
            }}
          >
            <div style={styles.muted}>
              {issuedInvite.email} için davet kodu (
              {new Date(issuedInvite.expiresAt).toLocaleDateString("tr-TR")} tarihine kadar
              geçerli):
            </div>
            <div style={{ ...styles.row, marginTop: 8 }}>
              <code style={{ fontSize: 18, letterSpacing: 2 }}>{issuedInvite.code}</code>
              <button
                type="button"
                style={styles.secondaryButton}
                onClick={() => void navigator.clipboard.writeText(issuedInvite.code)}
              >
                Kopyala
              </button>
              <button
                type="button"
                style={styles.secondaryButton}
                onClick={() => setIssuedInvite(null)}
              >
                Kapat
              </button>
            </div>
            <div style={{ ...styles.muted, marginTop: 8 }}>
              Kodu kullanıcıya güvenli bir kanaldan ilet; bu ekran kapanınca tekrar
              gösterilemez, sunucuda da saklanmaz. Kullanıcı uygulamada “Davet kodum
              var” ile kaydolur. Kaydolmadan önce de ona şifre paylaşabilirsin; kodu
              bilen biri kayıttan önceki paylaşımları açabileceği için kodu yalnızca
              kullanıcıya ilet.
            </div>
          </div>
        )}

        {(departments?.length ?? 0) > 0 && (
          <div style={{ ...styles.row, marginBottom: 12 }}>
            <span style={styles.muted}>Departman:</span>
            <select
              style={styles.input}
              value={departmentFilter}
              onChange={(event) => setDepartmentFilter(event.target.value)}
              aria-label="Kullanıcıları departmana göre filtrele"
            >
              <option value="">Tümü</option>
              {departments?.map((department) => (
                <option key={department.id} value={department.id}>
                  {department.name}
                </option>
              ))}
              <option value="none">Departmanı olmayanlar</option>
            </select>
          </div>
        )}

        {members === undefined ? (
          <p style={styles.muted}>Yükleniyor...</p>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {members
              .filter((member) =>
                departmentFilter === ""
                  ? true
                  : departmentFilter === "none"
                    ? member.departmentId === null
                    : member.departmentId === departmentFilter,
              )
              .map((member) => (
              <div
                key={member.id}
                style={{
                  ...styles.row,
                  justifyContent: "space-between",
                  padding: "10px 0",
                  borderBottom: "1px solid #292d36",
                }}
              >
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ overflowWrap: "anywhere" }}>
                    {member.displayName ?? member.email}
                    {member.isSelf && " (sen)"}
                  </div>
                  <div style={styles.muted}>
                    {member.email} · {STATUS_LABELS[member.status]}
                    {member.status === "active" &&
                      !member.hasPublicKey &&
                      " · kasasını henüz açmadı"}
                    {member.inviteExpiresAt !== null &&
                      member.inviteExpiresAt < Date.now() &&
                      " · davet süresi doldu"}
                  </div>
                </div>

                <div style={styles.row}>
                  <select
                    style={styles.input}
                    value={member.departmentId ?? ""}
                    disabled={busy || !member.canManage || !isAdmin}
                    aria-label={`${member.email} departmanı`}
                    onChange={(event) =>
                      void run(
                        () =>
                          updateMember({
                            id: member.id,
                            departmentId: event.target.value as Id<"departments">,
                          }),
                        "Departman güncellendi.",
                      )
                    }
                  >
                    {member.departmentId === null && <option value="">—</option>}
                    {departments?.map((department) => (
                      <option key={department.id} value={department.id}>
                        {department.name}
                      </option>
                    ))}
                  </select>

                  <select
                    style={styles.input}
                    value={member.role}
                    disabled={busy || !member.canManage || !isAdmin}
                    aria-label={`${member.email} rolü`}
                    onChange={(event) =>
                      void run(
                        () =>
                          updateMember({
                            id: member.id,
                            role: event.target.value as Role,
                          }),
                        "Rol güncellendi.",
                      )
                    }
                  >
                    <option value="member">{ROLE_LABELS.member}</option>
                    <option value="manager">{ROLE_LABELS.manager}</option>
                    <option value="admin">{ROLE_LABELS.admin}</option>
                  </select>

                  {member.canManage && member.status === "invited" && (
                    <button
                      type="button"
                      style={styles.secondaryButton}
                      disabled={busy}
                      onClick={() =>
                        void run(async () => {
                          const prepared = await prepareInvite(member.email);
                          const { expiresAt } = await renewInvite({
                            id: member.id,
                            publicKey: prepared.publicKey,
                            verifier: prepared.verifier,
                            expiresInHours: inviteHours,
                          });
                          setIssuedInvite({ email: member.email, code: prepared.code, expiresAt });
                        }, "Yeni davet kodu üretildi; eski kod geçersiz.")
                      }
                    >
                      Yeni davet kodu
                    </button>
                  )}

                  {member.canManage && (
                    <button
                      type="button"
                      style={styles.secondaryButton}
                      disabled={busy}
                      onClick={() =>
                        void run(
                          () =>
                            updateMember({
                              id: member.id,
                              enabled: member.status === "disabled",
                            }),
                          member.status === "disabled"
                            ? "Kullanıcı etkinleştirildi."
                            : "Kullanıcı devre dışı bırakıldı; erişimleri kaldırıldı.",
                        )
                      }
                    >
                      {member.status === "disabled" ? "Etkinleştir" : "Devre dışı bırak"}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
