import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import type React from "react";

import { errorMessage } from "../errors";

const MIN_LENGTH = 8;

const styles: Record<string, React.CSSProperties> = {
  section: {
    background: "#111318",
    color: "#e5e7eb",
    border: "1px solid #292d36",
    borderRadius: 14,
    padding: 24,
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
  muted: { color: "#9ca3af", fontSize: 13, marginTop: 0 },
  error: { color: "#f87171", overflowWrap: "anywhere" },
  success: { color: "#4ade80", overflowWrap: "anywhere" },
};

type Props = {
  hasVault: boolean;
  getSessionToken: () => Promise<string>;
};

/** Kasa ana parolasını değiştirir. Hesap (Clerk) şifresinden bağımsızdır. */
export default function MasterPasswordForm({ hasVault, getSessionToken }: Props) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  function clearFields() {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (saving) return;

    setError("");
    setSuccess("");

    if (newPassword.length < MIN_LENGTH) {
      setError(`Yeni ana parola en az ${MIN_LENGTH} karakter olmalı.`);
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Yeni parolalar eşleşmiyor.");
      return;
    }

    setSaving(true);

    try {
      await invoke("change_master_password", {
        sessionToken: await getSessionToken(),
        currentPassword,
        newPassword,
      });

      setSuccess(
        "Ana parola değiştirildi. Kasayı bir sonraki açışında yeni parolayı kullan.",
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      clearFields();
      setSaving(false);
    }
  }

  return (
    <section style={styles.section}>
      <h2 style={{ marginTop: 0 }}>Kasa ana parolası</h2>

      <p style={styles.muted}>
        Ana parola, bu cihazdaki kasanı şifreler ve hesap şifrenden ayrıdır.
        Unutulursa kurtarılamaz; yeni parolayı güvenli bir yerde sakla.
      </p>

      {!hasVault ? (
        <p style={styles.muted}>Bu cihazda henüz kasan yok.</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <label htmlFor="current-master-password">Mevcut ana parola</label>
          <input
            id="current-master-password"
            type="password"
            autoComplete="current-password"
            style={styles.input}
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
            disabled={saving}
            required
          />

          <label htmlFor="new-master-password">Yeni ana parola</label>
          <input
            id="new-master-password"
            type="password"
            autoComplete="new-password"
            style={styles.input}
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            minLength={MIN_LENGTH}
            placeholder={`En az ${MIN_LENGTH} karakter`}
            disabled={saving}
            required
          />

          <label htmlFor="confirm-master-password">Yeni ana parola tekrarı</label>
          <input
            id="confirm-master-password"
            type="password"
            autoComplete="new-password"
            style={styles.input}
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            minLength={MIN_LENGTH}
            disabled={saving}
            required
          />

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

          <button
            type="submit"
            style={{ ...styles.button, opacity: saving ? 0.6 : 1 }}
            disabled={saving}
          >
            {saving ? "Değiştiriliyor..." : "Ana parolayı değiştir"}
          </button>
        </form>
      )}
    </section>
  );
}
