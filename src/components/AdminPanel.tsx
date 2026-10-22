import { useAction, useMutation, useQuery } from "convex/react";
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

export default function AdminPanel({ me }: { me: Me }) {
  const isAdmin = me.role === "admin";

  const departments = useQuery(api.departments.list);
  const members = useQuery(api.members.list);

  const createDepartment = useMutation(api.departments.create);
  const createDefaultDepartments = useMutation(api.departments.createDefaults);
  const inviteMember = useAction(api.members.invite);
  const updateMember = useMutation(api.members.update);

  const [departmentName, setDepartmentName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("member");
  const [inviteDepartmentId, setInviteDepartmentId] = useState<string>(
    me.departmentId ?? "",
  );

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
            <div style={{ ...styles.row, marginBottom: 16 }}>
              {departments.map((department) => (
                <span
                  key={department.id}
                  style={{
                    ...styles.secondaryButton,
                    cursor: "default",
                  }}
                >
                  {department.name}
                </span>
              ))}
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
              await inviteMember({
                email: inviteEmail,
                role: inviteRole,
                departmentId:
                  inviteRole === "admin" && !inviteDepartmentId
                    ? undefined
                    : (inviteDepartmentId as Id<"departments">),
              });
              setInviteEmail("");
            }, "Davet e-postası gönderildi.");
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

          <button
            type="submit"
            style={styles.button}
            disabled={busy || (!hasDepartments && inviteRole !== "admin")}
          >
            Davet gönder
          </button>
        </form>

        {members === undefined ? (
          <p style={styles.muted}>Yükleniyor...</p>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {members.map((member) => (
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
