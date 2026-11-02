import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export function DevVaultResetButton({ email }: { email: string }) {
  const [confirming, setConfirming] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Never render this control in a production frontend build.
  if (!import.meta.env.DEV) {
    return null;
  }

  async function resetVault() {
    setLoading(true);
    setError(null);

    try {
      // Yalnızca bu hesabın bu cihazdaki kasası silinir.
      await invoke<void>("reset_vault", { email });

      // Reload so the application checks the new vault state.
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setLoading(false);
    }
  }

  return (
    <section
      style={{
        marginTop: "24px",
        padding: "16px",
        background: "#18181b",
        border: "1px solid #3f3f46",
        borderRadius: "12px",
        color: "#e4e4e7",
      }}
    >
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          letterSpacing: "0.08em",
          color: "#f87171",
          textTransform: "uppercase",
          marginBottom: "8px",
        }}
      >
        Geliştirme araçları
      </div>

      <p
        style={{
          margin: "0 0 12px",
          color: "#a1a1aa",
          fontSize: "13px",
          lineHeight: 1.6,
        }}
      >
        Yerel kasayı sıfırlayarak sıfırdan test yapabilirsin. Bu işlem mevcut
        yerel kasa verilerini siler.
      </p>

      <button
        type="button"
        onClick={() => {
          setError(null);
          setConfirming(true);
        }}
        disabled={loading || confirming}
        style={{
          padding: "9px 13px",
          borderRadius: "8px",
          border: "1px solid #7f1d1d",
          background: "#450a0a",
          color: "#fecaca",
          fontSize: "13px",
          fontWeight: 600,
          cursor: loading || confirming ? "not-allowed" : "pointer",
          opacity: loading || confirming ? 0.6 : 1,
        }}
      >
        Yerel kasayı sıfırla
      </button>

      {confirming && (
        <div
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="vault-reset-title"
          aria-describedby="vault-reset-description"
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            display: "grid",
            placeItems: "center",
            padding: "20px",
            background: "rgba(0, 0, 0, 0.75)",
          }}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "420px",
              padding: "24px",
              border: "1px solid #3f3f46",
              borderRadius: "14px",
              background: "#18181b",
              color: "#fafafa",
              boxShadow: "0 24px 80px rgba(0, 0, 0, 0.5)",
            }}
          >
            <h2
              id="vault-reset-title"
              style={{
                margin: "0 0 12px",
                fontSize: "18px",
                fontWeight: 700,
              }}
            >
              Yerel kasa silinsin mi?
            </h2>

            <p
              id="vault-reset-description"
              style={{
                margin: "0 0 20px",
                fontSize: "14px",
                lineHeight: 1.7,
                color: "#a1a1aa",
              }}
            >
              Bu hesabın bu cihazdaki şifrelenmiş veritabanı, Stronghold deposu, anahtar
              dosyası ve hesap bağlama bilgisi silinecek. İşlem geri alınamaz.
            </p>

            {error && (
              <p
                role="alert"
                style={{
                  margin: "0 0 16px",
                  padding: "10px",
                  borderRadius: "8px",
                  background: "#450a0a",
                  color: "#fecaca",
                  fontSize: "13px",
                  overflowWrap: "anywhere",
                }}
              >
                {error}
              </p>
            )}

            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "10px",
              }}
            >
              <button
                type="button"
                disabled={loading}
                onClick={() => setConfirming(false)}
                style={{
                  padding: "9px 13px",
                  borderRadius: "8px",
                  border: "1px solid #52525b",
                  background: "#27272a",
                  color: "#e4e4e7",
                  cursor: loading ? "not-allowed" : "pointer",
                }}
              >
                Vazgeç
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={resetVault}
                style={{
                  padding: "9px 13px",
                  borderRadius: "8px",
                  border: "1px solid #991b1b",
                  background: "#b91c1c",
                  color: "#ffffff",
                  fontWeight: 600,
                  cursor: loading ? "not-allowed" : "pointer",
                  opacity: loading ? 0.6 : 1,
                }}
              >
                {loading ? "Sıfırlanıyor..." : "Evet, sil"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
