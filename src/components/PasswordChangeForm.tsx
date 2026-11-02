import { invoke } from "@tauri-apps/api/core";
import { useAction } from "convex/react";
import { useState } from "react";
import type React from "react";

import { api } from "../../convex/_generated/api";
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
  email: string;
  isOnline: boolean;
  onChanged: (newAuthSecret: string) => void;
};

type PasswordChangeSecrets = {
  currentAuthSecret: string;
  newAuthSecret: string;
};

/**
 * Hesap parolasını değiştirir. Aynı parola kasayı da koruduğu için değişiklik
 * hem sunucuda hem bu cihazdaki kasada yapılır; bu yüzden bağlantı gerekir.
 */
export default function PasswordChangeForm({ email, isOnline, onChanged }: Props) {
  const changePassword = useAction(api.auth.changePassword);

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

  async function handleSubmit(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
    event.preventDefault();

    if (saving) return;

    setError("");
    setSuccess("");

    if (newPassword.length < MIN_LENGTH) {
      setError(`Yeni parola en az ${MIN_LENGTH} karakter olmalı.`);
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Yeni parolalar eşleşmiyor.");
      return;
    }

    setSaving(true);

    try {
      // Önce yerelde doğrulanır ve yeni koruma bellekte hazırlanır; sunucu
      // kabul edince diske yazılır. Böylece iki taraf ayrışmaz.
      const secrets = await invoke<PasswordChangeSecrets>("prepare_password_change", {
        currentPassword,
        newPassword,
      });

      await changePassword({
        currentSecret: secrets.currentAuthSecret,
        newSecret: secrets.newAuthSecret,
      });

      try {
        await invoke("commit_password_change");
      } catch (err) {
        setError(
          `Sunucudaki parolan değişti ancak bu cihazdaki kasa güncellenemedi: ${errorMessage(err)}. Çevrimdışı girişte eski parolanı kullan.`,
        );
        return;
      }

      onChanged(secrets.newAuthSecret);
      setSuccess("Parola değiştirildi. Diğer cihazlardaki oturumlar kapatıldı.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      clearFields();
      setSaving(false);
    }
  }

  return (
    <section style={styles.section}>
      <h2 style={{ marginTop: 0 }}>Parola</h2>

      <p style={styles.muted}>
        {email} hesabının parolası; hem girişi hem kasanın şifrelemesini korur.
        Unutulursa kurtarılamaz.
      </p>

      {!isOnline ? (
        <p style={styles.muted}>Parola değiştirmek için sunucu bağlantısı gerekli.</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <label htmlFor="current-account-password">Mevcut parola</label>
          <input
            id="current-account-password"
            type="password"
            autoComplete="current-password"
            style={styles.input}
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
            disabled={saving}
            required
          />

          <label htmlFor="new-account-password">Yeni parola</label>
          <input
            id="new-account-password"
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

          <label htmlFor="confirm-account-password">Yeni parola tekrarı</label>
          <input
            id="confirm-account-password"
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
            {saving ? "Değiştiriliyor..." : "Parolayı değiştir"}
          </button>
        </form>
      )}
    </section>
  );
}
