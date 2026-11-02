import { useAuthActions } from "@convex-dev/auth/react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useConvex, useConvexAuth, useQuery } from "convex/react";
import { useCallback, useEffect, useRef, useState } from "react";
import type React from "react";

import { api } from "../convex/_generated/api";
import KeySync from "./KeySync";
import PasswordManager from "./PasswordManager";
import AdminPanel, { ROLE_LABELS } from "./components/AdminPanel";
import { DevVaultResetButton } from "./components/DevVaultResetButton";
import PasswordChangeForm from "./components/PasswordChangeForm";
import { errorMessage } from "./errors";
import { useVaultData } from "./vaultData";

type VaultOwner = { email: string; userId: string };

type UnlockedVaultInfo = VaultOwner & { authSecret: string };

function BrandIcon() {
  return (
    <span className="auth-icon" aria-hidden="true">
      <svg
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6Z" />
        <circle cx="12" cy="11" r="2" />
        <path d="M12 13v3" />
      </svg>
    </span>
  );
}

function NavIcon({ children }: { children: React.ReactNode }) {
  return (
    <svg
      className="vault-nav-icon"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

const IDLE_LOCK_MS = 5 * 60 * 1000;
const ACTIVITY_HEARTBEAT_MS = 5 * 1000;
const SERVER_RETRY_MS = 30 * 1000;
const LAST_EMAIL_KEY = "pwm:last-email";
const SIGN_OUT_TIMEOUT_MS = 3000;

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function readLastEmail() {
  try {
    return localStorage.getItem(LAST_EMAIL_KEY) ?? "";
  } catch {
    return "";
  }
}

function rememberEmail(email: string) {
  try {
    localStorage.setItem(LAST_EMAIL_KEY, email);
  } catch {
    // Yalnızca kolaylık içindir.
  }
}

/**
 * Sunucu oturumunu kapatır. Çevrimdışıyken Convex çağrısı bağlantı gelene
 * kadar bekler; o durumda token'lar diskten hemen silinir, sunucudaki oturum
 * bağlantı gelince kapanır.
 */
async function endServerSession(signOut: () => Promise<void>) {
  const finished = await Promise.race([
    signOut().then(
      () => true,
      () => true,
    ),
    new Promise<false>((resolve) => window.setTimeout(() => resolve(false), SIGN_OUT_TIMEOUT_MS)),
  ]);

  if (finished) return;

  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith("__convexAuth")) {
        localStorage.removeItem(key);
      }
    }
  } catch {
    // Depolama erişilemiyorsa token zaten kalıcı değildir.
  }
}

/** Convex WebSocket bağlantısı gerçekten açık mı. Bağlantı koptuğunda
 * sorgular son değerlerini korur; bu yüzden çevrimiçi durum buradan okunur. */
function useConnected() {
  const convex = useConvex();
  const [connected, setConnected] = useState(() => convex.connectionState().isWebSocketConnected);

  useEffect(
    () =>
      convex.subscribeToConnectionState((state) => setConnected(state.isWebSocketConnected)),
    [convex],
  );

  return connected;
}

function App() {
  const { signIn, signOut } = useAuthActions();
  const { isAuthenticated, isLoading: isAuthLoading } = useConvexAuth();

  // Açık kasanın sahibi. Kasa bu cihazda, internet olmadan açılır; sunucu
  // oturumu ayrıca, bağlantı olduğunda arka planda kurulur.
  const [vault, setVault] = useState<VaultOwner | null>(null);
  const [isCheckingVault, setIsCheckingVault] = useState(true);

  // Sunucu girişi için paroladan türetilmiş anahtar. Kasayı açmaya yetmez;
  // kasa kilitlenince bellekten silinir.
  const authSecretRef = useRef<string | null>(null);

  const [email, setEmail] = useState(readLastEmail);
  const [password, setPassword] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  // İlk girişte sunucu parolayı kabul ettikten sonra kasa oluşturulur; bunun
  // için sunucudaki kullanıcı kimliği beklenir.
  const pendingVaultRef = useRef<{
    email: string;
    password: string;
    inviteCode?: string;
  } | null>(null);
  const [pendingVaultTick, setPendingVaultTick] = useState(0);

  const [serverError, setServerError] = useState("");
  const [keySyncError, setKeySyncError] = useState("");
  const [serverRetryTick, setServerRetryTick] = useState(0);
  const [isLockingVault, setIsLockingVault] = useState(false);

  const [view, setView] = useState<"vault" | "admin" | "settings">("vault");

  const convex = useConvex();
  const me = useQuery(api.users.me, isAuthenticated ? {} : "skip");

  const expectedEmail = vault?.email ?? pendingVaultRef.current?.email ?? null;
  const serverUserMatches = !!me && me.email === expectedEmail;
  const isConnected = useConnected();
  const isServerReady =
    isConnected &&
    !!vault &&
    serverUserMatches &&
    me.id === vault.userId &&
    me.status === "active";
  const canManageUsers = isServerReady && (me.role === "admin" || me.role === "manager");

  // Kayıtların yerel önbelleği ve çevrimdışı kuyruğu; hangi ekran açık olursa
  // olsun çalışır.
  const vaultData = useVaultData({ ownerId: vault?.userId ?? null, isOnline: isServerReady });

  // Kasa hangi yoldan kilitlenirse kilitlensin (buton, hareketsizlik, hata)
  // sunucu oturumu da kapatılır; kilitliyken cihazda geçerli token kalmaz.
  const clearSession = useCallback(
    (message?: string) => {
      authSecretRef.current = null;
      setVault(null);
      setPassword("");
      setView("vault");

      if (message) {
        setFormError(message);
      }

      void endServerSession(signOut);
    },
    [signOut],
  );

  useEffect(() => {
    invoke<VaultOwner | null>("current_vault")
      .then((owner) => {
        // Uygulama yeniden yüklendiyse sunucu anahtarı bellekte değildir;
        // güvenli taraf: kasayı kilitleyip yeniden giriş istemek.
        if (owner) {
          void invoke("lock_vault");
        }
      })
      .catch((error) => console.error("Kasa durumu alınamadı:", error))
      .finally(() => setIsCheckingVault(false));

    // Kasa kapalı başladığı için önceki çalışmadan kalan sunucu oturumu da
    // kapatılır.
    void endServerSession(signOut);
    // Yalnızca açılışta çalışır.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sunucu oturumu: kasa açıkken ve oturum yoksa ya da başka bir hesaba
  // aitse, bellekteki anahtarla giriş yapılır. Bağlantı yoksa periyodik
  // olarak ve tarayıcı çevrimiçi olduğunda yeniden denenir.
  useEffect(() => {
    if (!vault || !authSecretRef.current || isAuthLoading) {
      return;
    }

    if (isAuthenticated && (me === undefined || me?.email === vault.email)) {
      setServerError("");
      return;
    }

    let cancelled = false;
    const secret = authSecretRef.current;

    signIn("password", { flow: "signIn", email: vault.email, secret }).catch(
      (error: unknown) => {
        if (cancelled) return;

        const message = errorMessage(error);
        setServerError(
          /parola yanlış/.test(message)
            ? "Sunucu parolanı kabul etmedi; parolan başka bir cihazda değiştirilmiş olabilir."
            : "Sunucuya ulaşılamıyor. Kasan bu cihazda açık; bağlantı gelince otomatik bağlanılacak.",
        );
      },
    );

    const retry = window.setTimeout(() => setServerRetryTick((tick) => tick + 1), SERVER_RETRY_MS);
    const onOnline = () => setServerRetryTick((tick) => tick + 1);
    window.addEventListener("online", onOnline);

    return () => {
      cancelled = true;
      window.clearTimeout(retry);
      window.removeEventListener("online", onOnline);
    };
  }, [isAuthLoading, isAuthenticated, me, serverRetryTick, signIn, vault]);

  // İlk giriş: signIn başarıyla döndükten ve kullanıcı kimliği geldikten
  // sonra bu cihazda kasa oluşturulur.
  useEffect(() => {
    const pending = pendingVaultRef.current;

    if (pendingVaultTick === 0 || !pending || !isAuthenticated || me === undefined) {
      return;
    }

    if (!me || me.email !== pending.email) {
      return;
    }

    pendingVaultRef.current = null;

    const credentials = { email: pending.email, password: pending.password };

    invoke("create_vault", { ...credentials, userId: me.id, inviteCode: pending.inviteCode ?? null })
      .then(() => invoke<UnlockedVaultInfo>("unlock_vault", credentials))
      .then((info) => {
        authSecretRef.current = info.authSecret;
        setVault({ email: info.email, userId: info.userId });
        setFormError("");
      })
      .catch((error: unknown) => setFormError(errorMessage(error)))
      .finally(() => {
        setPassword("");
        setIsSubmitting(false);
        setPendingVaultTick(0);
      });
  }, [isAuthenticated, me, pendingVaultTick]);

  // Kullanıcı yönetim yetkisini kaybederse kasa görünümüne dön.
  useEffect(() => {
    if (!canManageUsers) {
      setView((current) => (current === "admin" ? "vault" : current));
    }
  }, [canManageUsers]);

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;

    void listen("vault://auto-locked", () => {
      if (!cancelled) clearSession("Hareketsizlik nedeniyle kasa otomatik kilitlendi.");
    })
      .then((unsubscribe) => {
        if (cancelled) {
          unsubscribe();
        } else {
          unlisten = unsubscribe;
        }
      })
      .catch((error) => {
        console.error("Otomatik kilit olayı dinlenemedi:", error);
      });

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [clearSession]);

  useEffect(() => {
    if (!vault) {
      return;
    }

    let cancelled = false;
    let idleTimer: number | undefined;
    let lastHeartbeatAt = 0;
    let lastPointerMoveAt = 0;
    let heartbeatInProgress = false;

    async function lockForInactivity() {
      try {
        await invoke("lock_vault");
      } catch (error) {
        console.error("Otomatik kilit isteği tamamlanamadı:", error);
      } finally {
        if (!cancelled) clearSession("Hareketsizlik nedeniyle kasa otomatik kilitlendi.");
      }
    }

    async function sendActivityHeartbeat() {
      if (heartbeatInProgress || cancelled) return;

      heartbeatInProgress = true;

      try {
        await invoke("touch_vault_activity");
      } catch (error) {
        console.error("Kasa etkinliği doğrulanamadı:", error);

        try {
          await invoke("lock_vault");
        } catch (lockError) {
          console.error("Güvenlik kilidi tamamlanamadı:", lockError);
        } finally {
          if (!cancelled) {
            clearSession("Kasa etkinliği doğrulanamadı; güvenlik için kasa kilitlendi.");
          }
        }
      } finally {
        heartbeatInProgress = false;
      }
    }

    function resetIdleTimer() {
      if (idleTimer !== undefined) {
        window.clearTimeout(idleTimer);
      }

      idleTimer = window.setTimeout(() => {
        void lockForInactivity();
      }, IDLE_LOCK_MS);
    }

    const handleActivity: EventListener = (event) => {
      const now = Date.now();

      if (event.type === "pointermove") {
        if (now - lastPointerMoveAt < 1000) return;
        lastPointerMoveAt = now;
      }

      resetIdleTimer();

      if (now - lastHeartbeatAt >= ACTIVITY_HEARTBEAT_MS) {
        lastHeartbeatAt = now;
        void sendActivityHeartbeat();
      }
    };

    const activityEvents = [
      "pointerdown",
      "pointermove",
      "keydown",
      "wheel",
      "touchstart",
      "click",
    ];

    resetIdleTimer();
    void sendActivityHeartbeat();

    for (const eventName of activityEvents) {
      window.addEventListener(eventName, handleActivity, {
        passive: true,
      });
    }

    return () => {
      cancelled = true;

      if (idleTimer !== undefined) {
        window.clearTimeout(idleTimer);
      }

      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, handleActivity);
      }
    };
  }, [clearSession, vault]);

  async function handleLogin(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
    event.preventDefault();

    if (isSubmitting) return;

    const normalizedEmail = normalizeEmail(email);
    setFormError("");

    if (!normalizedEmail || !password) {
      setFormError("E-posta ve parolanı gir.");
      return;
    }

    if (isRegistering && password.length < 8) {
      setFormError("Parolan en az 8 karakter olmalı.");
      return;
    }

    setIsSubmitting(true);
    rememberEmail(normalizedEmail);

    try {
      const hasLocalVault = await invoke<boolean>("vault_exists", { email: normalizedEmail });

      if (hasLocalVault && !isRegistering) {
        const info = await invoke<UnlockedVaultInfo>("unlock_vault", {
          email: normalizedEmail,
          password,
        });

        authSecretRef.current = info.authSecret;
        setVault({ email: info.email, userId: info.userId });
        setPassword("");
        setIsSubmitting(false);
        return;
      }

      // Bu cihazda kasa yok: ilk giriş sunucu üzerinden yapılır, kasa
      // ardından oluşturulur (yukarıdaki efekt).
      const secret = await invoke<string>("derive_auth_secret", {
        email: normalizedEmail,
        password,
      });

      // Davet kodu sunucuya gönderilmez; yalnızca ondan türetilen
      // doğrulayıcı gider. Henüz yönetici yoksa (sistemde davet de yoktur)
      // ilk yöneticinin bootstrap kodu düz gönderilir.
      const code = inviteCode.trim();
      const isBootstrap =
        isRegistering && (await convex.query(api.auth.bootstrapAvailable, {}));

      const registration: Record<string, string> = !isRegistering
        ? {}
        : isBootstrap
          ? { bootstrapCode: code }
          : {
              inviteVerifier: await invoke<string>("derive_invite_verifier", {
                email: normalizedEmail,
                inviteCode: code,
              }),
            };

      await signIn("password", {
        flow: isRegistering ? "signUp" : "signIn",
        email: normalizedEmail,
        secret,
        ...registration,
      });

      pendingVaultRef.current = {
        email: normalizedEmail,
        password,
        ...(isRegistering && !isBootstrap ? { inviteCode: code } : {}),
      };
      setPendingVaultTick((tick) => tick + 1);
      setInviteCode("");
      setIsRegistering(false);
    } catch (error: unknown) {
      pendingVaultRef.current = null;
      setPassword("");
      setIsSubmitting(false);

      const message = errorMessage(error);
      setFormError(
        /Failed to fetch|NetworkError|connection/i.test(message)
          ? "Bu cihazda ilk giriş için sunucu bağlantısı gerekli."
          : message,
      );
    }
  }

  async function handleLock() {
    if (isLockingVault) return;

    setIsLockingVault(true);

    try {
      await invoke("lock_vault");
      clearSession();
    } catch (error: unknown) {
      const stillUnlocked = await invoke<VaultOwner | null>("current_vault").catch(() => null);

      if (stillUnlocked) {
        setFormError(errorMessage(error));
      } else {
        clearSession("Kasa kilitlendi; ancak bellek temizliği sırasında hata oluştu.");
      }
    } finally {
      setIsLockingVault(false);
    }
  }

  if (isCheckingVault) {
    return (
      <main className="auth-page">
        <section className="auth-panel">
          <p>Kasa kontrol ediliyor...</p>
        </section>
      </main>
    );
  }

  if (!vault) {
    return (
      <main className="auth-page">
        <section className="auth-panel">
          <div className="auth-brand">
            <BrandIcon />
            <span>Password Manager</span>
          </div>

          <div className="auth-heading">
            <h1>{isRegistering ? "Hesabını etkinleştir" : "Tekrar hoş geldin"}</h1>
            <p>
              {isRegistering
                ? "Yöneticinin verdiği davet koduyla kendi parolanı belirle."
                : "Bu cihazda daha önce giriş yaptıysan internet olmadan da kasana erişebilirsin."}
            </p>
          </div>

          <form className="vault-form" onSubmit={handleLogin}>
            <label htmlFor="login-email">E-posta</label>
            <input
              id="login-email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              disabled={isSubmitting}
              required
              autoFocus={!email}
            />

            {isRegistering && (
              <>
                <label htmlFor="login-invite">Davet kodu</label>
                <input
                  id="login-invite"
                  value={inviteCode}
                  onChange={(event) => setInviteCode(event.target.value)}
                  disabled={isSubmitting}
                  placeholder="XXXX-XXXX-XXXX"
                  autoComplete="off"
                  required
                />
              </>
            )}

            <label htmlFor="login-password">{isRegistering ? "Yeni parola" : "Parola"}</label>
            <input
              id="login-password"
              type="password"
              autoComplete={isRegistering ? "new-password" : "current-password"}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={isSubmitting}
              minLength={isRegistering ? 8 : undefined}
              required
              autoFocus={!!email}
            />

            {isRegistering && (
              <p className="auth-hint">
                Bu parola hem girişini hem de kasanın şifrelemesini korur. Unutulursa
                kasadaki veriler kurtarılamaz.
              </p>
            )}

            {formError && (
              <p className="vault-form-error" role="alert">
                {formError}
              </p>
            )}

            <button className="vault-primary" type="submit" disabled={isSubmitting}>
              {isSubmitting
                ? "Giriş yapılıyor..."
                : isRegistering
                  ? "Hesabı etkinleştir"
                  : "Giriş yap"}
            </button>

            <button
              type="button"
              className="auth-link"
              disabled={isSubmitting}
              onClick={() => {
                setIsRegistering((value) => !value);
                setFormError("");
              }}
            >
              {isRegistering ? "Zaten hesabım var" : "Davet kodum var"}
            </button>
          </form>

          <p className="auth-security">
            Parolan bu cihazdan çıkmaz; sunucuya yalnızca ondan türetilmiş bir
            giriş anahtarı ve şifreli veriler gönderilir.
          </p>
        </section>
      </main>
    );
  }

  const serverStatus = isServerReady
    ? "Çevrimiçi"
    : isAuthenticated && me && me.id !== vault.userId
      ? "Sunucu hesabı eşleşmiyor"
      : "Çevrimdışı";

  return (
    <main className="vault-page">
      <aside className="vault-sidebar">
        <div className="auth-brand">
          <BrandIcon />
          <span>Password Manager</span>
        </div>

        <nav className="vault-nav">
          <button
            className={`vault-nav-item${view === "vault" ? " active" : ""}`}
            type="button"
            onClick={() => setView("vault")}
          >
            <NavIcon>
              <circle cx="8" cy="15" r="4" />
              <path d="m10.85 12.15 8.65-8.65" />
              <path d="m16.5 6.5 2.5 2.5" />
              <path d="m14 9 2 2" />
            </NavIcon>
            Tüm kayıtlar
          </button>

          <button className="vault-nav-item" type="button">
            <NavIcon>
              <path d="m12 3.5 2.6 5.3 5.9.85-4.25 4.15 1 5.85L12 16.9l-5.25 2.75 1-5.85L3.5 9.65l5.9-.85Z" />
            </NavIcon>
            Favoriler
          </button>

          {canManageUsers && (
            <button
              className={`vault-nav-item${view === "admin" ? " active" : ""}`}
              type="button"
              onClick={() => setView("admin")}
            >
              <NavIcon>
                <circle cx="9" cy="8" r="3.5" />
                <path d="M2.5 20a6.5 6.5 0 0 1 13 0" />
                <path d="M16 4.6a3.5 3.5 0 0 1 0 6.8" />
                <path d="M18.5 14.2A6.5 6.5 0 0 1 21.5 20" />
              </NavIcon>
              Kullanıcılar
            </button>
          )}

          <button
            className={`vault-nav-item${view === "settings" ? " active" : ""}`}
            type="button"
            onClick={() => setView("settings")}
          >
            <NavIcon>
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
            </NavIcon>
            Ayarlar
          </button>
        </nav>

        <p className="vault-eyebrow" style={{ marginTop: "auto" }}>
          {isServerReady ? me.displayName : vault.email}
          {isServerReady && (
            <>
              <br />
              {ROLE_LABELS[me.role]}
              {me.departmentName ? ` · ${me.departmentName}` : ""}
            </>
          )}
        </p>

        <button
          className="vault-logout"
          type="button"
          onClick={() => void handleLock()}
          disabled={isLockingVault}
        >
          {isLockingVault ? "Kilitleniyor..." : "Kilitle ve çıkış yap"}
        </button>
      </aside>

      <section className="vault-content">
        <header className="vault-header">
          <div>
            <p className="vault-eyebrow">
              {view === "admin" ? "YÖNETİM" : view === "settings" ? "HESAP" : "GÜVENLİ KASA"}
            </p>
            <h1>{view === "admin" ? "Kullanıcılar" : view === "settings" ? "Ayarlar" : "Kasam"}</h1>
          </div>

          <span className={`vault-status${isServerReady ? " online" : ""}`}>
            <span className="vault-status-dot" />
            {serverStatus}
          </span>
        </header>

        <KeySync
          enabled={isServerReady}
          serverPublicKey={me?.publicKey ?? null}
          onError={setKeySyncError}
        />

        {serverError && !isServerReady && (
          <p className="vault-form-error" role="status">
            {serverError}
          </p>
        )}

        {keySyncError && isServerReady && (
          <p className="vault-form-error" role="alert">
            {keySyncError}
          </p>
        )}

        {isAuthenticated && me && me.email === vault.email && me.id !== vault.userId && (
          <p className="vault-form-error" role="alert">
            Bu cihazdaki kasa, sunucudaki hesabından farklı bir kayda bağlı. Geliştirme
            ortamında yerel kasayı sıfırlayıp yeniden giriş yapabilirsin.
          </p>
        )}

        {view === "admin" && isServerReady ? (
          <AdminPanel me={me} />
        ) : view === "settings" ? (
          <div className="vault-settings">
            <PasswordChangeForm
              email={vault.email}
              isOnline={isServerReady}
              onChanged={(newSecret) => {
                authSecretRef.current = newSecret;
              }}
            />
          </div>
        ) : (
          <div className="vault-workspace">
            <PasswordManager key={vault.userId} data={vaultData} isOnline={isServerReady} />

            {formError && (
              <p className="vault-form-error" role="alert">
                {formError}
              </p>
            )}

            <DevVaultResetButton email={vault.email} />
          </div>
        )}

        <footer className="vault-footer">
          Parolalar bu cihazda şifrelenir; sunucu yalnızca şifreli veri görür.
        </footer>
      </section>
    </main>
  );
}

export default App;
