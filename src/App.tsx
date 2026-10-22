import { SignIn, SignUp, useAuth, useClerk, useUser } from "@clerk/react";
import { dark } from "@clerk/ui/themes";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useMutation } from "convex/react";
import { useCallback, useEffect, useState } from "react";
import type React from "react";

import { api } from "../convex/_generated/api";
import PasswordManager from "./PasswordManager";
import { DevVaultResetButton } from "./components/DevVaultResetButton";

type VaultStatus = "uninitialized" | "initialized";

const IDLE_LOCK_MS = 5 * 60 * 1000;
const ACTIVITY_HEARTBEAT_MS = 5 * 1000;

function App() {
  const { isLoaded, isSignedIn, getToken } = useAuth();
  const { isLoaded: isUserLoaded, user } = useUser();
  const { signOut } = useClerk();

  const [isVaultInitialized, setIsVaultInitialized] = useState<boolean | null>(
    null,
  );
  const [isVaultUnlocked, setIsVaultUnlocked] = useState(false);
  const [vaultStatusError, setVaultStatusError] = useState(false);

  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [isCreatingVault, setIsCreatingVault] = useState(false);
  const [isUnlockingVault, setIsUnlockingVault] = useState(false);
  const [isLockingVault, setIsLockingVault] = useState(false);
  const [isSigningOut, setIsSigningOut] = useState(false);

  const getSessionToken = useCallback(async (): Promise<string> => {
    if (!isSignedIn) {
      throw new Error("İşlem için Clerk oturumu açılmalı.");
    }

    const token = await getToken();

    if (!token) {
      throw new Error("Clerk oturum token'ı alınamadı.");
    }

    return token;
  }, [getToken, isSignedIn]);

  const upsertMe = useMutation(api.users.upsertMe);

  // Bu cihazdaki kimlik anahtarının açık kısmını Convex'e yazar; diğer
  // kullanıcılar paylaşım yaparken bu anahtarı kullanır.
  async function registerIdentity() {
    if (!isUserLoaded || !user) {
      throw new Error("Kullanıcı bilgileri henüz yüklenmedi.");
    }

    const email = user.primaryEmailAddress?.emailAddress;

    if (!email) {
      throw new Error("Hesabında bir e-posta adresi bulunamadı.");
    }

    const displayName =
      user.fullName?.trim() || user.username?.trim() || email.split("@")[0];

    const publicKey = await invoke<string>("get_identity_public_key", {
      sessionToken: await getSessionToken(),
    });

    await upsertMe({ email, displayName, publicKey });
  }

  // Local vault status is bound to the currently authenticated Clerk user.
  useEffect(() => {
    if (!isLoaded) {
      return;
    }

    if (!isSignedIn) {
      setIsVaultInitialized(null);
      setIsVaultUnlocked(false);
      setVaultStatusError(false);
      setMasterPassword("");
      setConfirmPassword("");

      void invoke("lock_vault").catch((error) => {
        console.error("Oturum kapandığında kasa kilitlenemedi:", error);
      });

      return;
    }

    let cancelled = false;

    async function loadVaultStatus() {
      try {
        const sessionToken = await getSessionToken();

        const [status, unlocked] = await Promise.all([
          invoke<VaultStatus>("get_vault_status", { sessionToken }),
          invoke<boolean>("is_vault_unlocked", {
            sessionToken,
          }),
        ]);

        if (!cancelled) {
          setIsVaultInitialized(status !== "uninitialized");
          setIsVaultUnlocked(unlocked);
          setVaultStatusError(false);
          setFormError("");
        }
      } catch (error: unknown) {
        if (!cancelled) {
          console.error("Kasa durumu kontrol edilemedi:", error);
          setIsVaultUnlocked(false);
          setVaultStatusError(true);
        }
      }
    }

    void loadVaultStatus();

    return () => {
      cancelled = true;
    };
  }, [getSessionToken, isLoaded, isSignedIn, user?.id]);

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;

    void listen("vault://auto-locked", () => {
      if (cancelled) return;

      setIsVaultUnlocked(false);
      setMasterPassword("");
      setConfirmPassword("");
      setFormError("Hareketsizlik nedeniyle kasa otomatik kilitlendi.");
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
  }, []);

  useEffect(() => {
    if (!isLoaded || !isSignedIn || !isVaultUnlocked) {
      return;
    }

    let cancelled = false;
    let idleTimer: number | undefined;
    let lastHeartbeatAt = 0;
    let lastPointerMoveAt = 0;
    let heartbeatInProgress = false;

    function clearUiSession(message?: string) {
      if (cancelled) return;

      setIsVaultUnlocked(false);
      setMasterPassword("");
      setConfirmPassword("");

      if (message) {
        setFormError(message);
      }
    }

    async function lockForInactivity() {
      try {
        await invoke("lock_vault");
      } catch (error) {
        console.error("Otomatik kilit isteği tamamlanamadı:", error);
      } finally {
        clearUiSession("Hareketsizlik nedeniyle kasa otomatik kilitlendi.");
      }
    }

    async function sendActivityHeartbeat() {
      if (heartbeatInProgress || cancelled) return;

      heartbeatInProgress = true;

      try {
        const sessionToken = await getSessionToken();

        await invoke("touch_vault_activity", {
          sessionToken,
        });
      } catch (error) {
        console.error("Kasa etkinliği doğrulanamadı:", error);

        try {
          await invoke("lock_vault");
        } catch (lockError) {
          console.error("Güvenlik kilidi tamamlanamadı:", lockError);
        } finally {
          clearUiSession(
            "Kasa etkinliği doğrulanamadı; güvenlik için kasa kilitlendi.",
          );
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
  }, [getSessionToken, isLoaded, isSignedIn, isVaultUnlocked, user?.id]);

  const isSignUp = window.location.pathname === "/sign-up";

  const appearance = {
    theme: dark,
    elements: {
      rootBox: {
        width: "100%",
        maxWidth: "100%",
        minWidth: "0",
      },
      cardBox: {
        width: "100%",
        maxWidth: "100%",
        minWidth: "0",
      },
      card: {
        width: "100%",
        maxWidth: "100%",
        minWidth: "0",
        boxShadow: "none",
      },
    },
  };

  async function handleCreateVault(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
    event.preventDefault();
    setFormError("");

    if (masterPassword.trim().length === 0) {
      setFormError("Ana parola boş olamaz.");
      return;
    }

    if (masterPassword !== confirmPassword) {
      setFormError("Girdiğin parolalar eşleşmiyor.");
      return;
    }

    if (masterPassword.length < 8) {
      setFormError("Ana parolan en az 8 karakter olmalı.");
      return;
    }

    if (isCreatingVault) return;

    setIsCreatingVault(true);

    try {
      const sessionToken = await getSessionToken();

      await invoke("create_vault", {
        sessionToken,
        masterPassword,
      });

      setMasterPassword("");
      setConfirmPassword("");
      setIsVaultInitialized(true);
      setIsVaultUnlocked(true);
      setVaultStatusError(false);

      try {
        await registerIdentity();
      } catch (error: unknown) {
        console.error("Kimlik anahtarı sunucuya kaydedilemedi:", error);

        setFormError(
          typeof error === "string"
            ? `Kasa oluşturuldu ancak paylaşım anahtarı sunucuya kaydedilemedi: ${error}`
            : error instanceof Error
              ? `Kasa oluşturuldu ancak paylaşım anahtarı sunucuya kaydedilemedi: ${error.message}`
              : "Kasa oluşturuldu ancak paylaşım anahtarı sunucuya kaydedilemedi. Kasayı kilitleyip yeniden açarak tekrar deneyebilirsin.",
        );
      }
    } catch (error: unknown) {
      console.error("Kasa oluşturulamadı:", error);

      setFormError(
        typeof error === "string"
          ? error
          : "Kasa oluşturulamadı. Lütfen tekrar dene.",
      );
    } finally {
      setMasterPassword("");
      setConfirmPassword("");
      setIsCreatingVault(false);
    }
  }

  async function handleUnlockVault(
    event: Parameters<NonNullable<React.ComponentProps<"form">["onSubmit"]>>[0],
  ) {
    event.preventDefault();

    if (isUnlockingVault) return;

    setFormError("");

    if (!masterPassword) {
      setFormError("Ana parolanı gir.");
      return;
    }

    setIsUnlockingVault(true);

    try {
      const sessionToken = await getSessionToken();

      await invoke("unlock_vault", {
        sessionToken,
        masterPassword,
      });

      setMasterPassword("");
      setIsVaultUnlocked(true);
      setVaultStatusError(false);

      try {
        await registerIdentity();
      } catch (error: unknown) {
        console.error("Kimlik anahtarı sunucuya kaydedilemedi:", error);

        setFormError(
          typeof error === "string"
            ? `Kasa açıldı ancak paylaşım anahtarı sunucuya kaydedilemedi: ${error}`
            : error instanceof Error
              ? `Kasa açıldı ancak paylaşım anahtarı sunucuya kaydedilemedi: ${error.message}`
              : "Kasa açıldı ancak paylaşım anahtarı sunucuya kaydedilemedi.",
        );
      }
    } catch (error: unknown) {
      console.error("Kasa açılamadı:", error);

      setFormError(
        typeof error === "string" && error === "Decryption failed"
          ? "Ana parola yanlış. Lütfen tekrar dene."
          : typeof error === "string"
            ? error
            : "Kasa açılamadı. Lütfen tekrar dene.",
      );
    } finally {
      setMasterPassword("");
      setIsUnlockingVault(false);
    }
  }

  async function handleLockVault() {
    if (isLockingVault || isSigningOut) return;

    setFormError("");
    setIsLockingVault(true);

    try {
      await invoke("lock_vault");

      setIsVaultUnlocked(false);
      setMasterPassword("");
      setConfirmPassword("");
    } catch (error: unknown) {
      console.error("Kasa kilitlenirken hata oluştu:", error);

      const stillUnlocked = await getSessionToken()
        .then((sessionToken) =>
          invoke<boolean>("is_vault_unlocked", { sessionToken }),
        )
        .catch(() => false);

      setIsVaultUnlocked(stillUnlocked);

      if (!stillUnlocked) {
        setMasterPassword("");
        setConfirmPassword("");
        setFormError(
          "Kasa kilitlendi; ancak bellek temizliği sırasında hata oluştu.",
        );
      } else {
        setFormError(
          typeof error === "string"
            ? error
            : "Kasa kilitlenemedi. Lütfen tekrar dene.",
        );
      }
    } finally {
      setIsLockingVault(false);
    }
  }

  async function handleSignOut() {
    if (isSigningOut || isLockingVault) return;

    setFormError("");
    setIsSigningOut(true);

    try {
      try {
        await invoke("lock_vault");
      } catch (lockError) {
        console.error("Kasa kilitleme işlemi hata verdi:", lockError);

        const stillUnlocked = await getSessionToken()
          .then((sessionToken) =>
            invoke<boolean>("is_vault_unlocked", { sessionToken }),
          )
          .catch(() => false);

        if (stillUnlocked) {
          throw lockError;
        }
      }

      setIsVaultUnlocked(false);
      setMasterPassword("");
      setConfirmPassword("");

      await signOut();
    } catch (error: unknown) {
      console.error("Oturum kapatılamadı:", error);

      setFormError(
        "Kasa kilitlenemediği için oturum kapatılmadı. Lütfen tekrar dene.",
      );
      setIsSigningOut(false);
    }
  }

  if (!isLoaded) {
    return (
      <main className="auth-page">
        <section className="auth-panel">
          <p>Oturum kontrol ediliyor...</p>
        </section>
      </main>
    );
  }

  if (isSignedIn) {
    const vaultStatus = vaultStatusError
      ? "Kasa durumu alınamadı"
      : isVaultInitialized === null
        ? "Kasa durumu kontrol ediliyor..."
        : isVaultInitialized
          ? isVaultUnlocked
            ? "Kasa açık"
            : "Kasa kilitli"
          : "Kasa henüz oluşturulmadı";

    return (
      <main className="vault-page">
        <aside className="vault-sidebar">
          <div className="auth-brand">
            <span className="auth-icon">P</span>
            <span>Password Manager</span>
          </div>

          <nav className="vault-nav">
            <button className="vault-nav-item active" type="button">
              <span>▦</span>
              Tüm kayıtlar
            </button>

            <button className="vault-nav-item" type="button">
              <span>☆</span>
              Favoriler
            </button>
          </nav>

          <button
            className="vault-logout"
            type="button"
            onClick={() => void handleSignOut()}
            disabled={isSigningOut || isLockingVault}
          >
            {isSigningOut ? "Oturum kapatılıyor..." : "Oturumu kapat"}
          </button>
        </aside>

        <section className="vault-content">
          <header className="vault-header">
            <div>
              <p className="vault-eyebrow">GÜVENLİ KASA</p>
              <h1>Kasam</h1>
            </div>

            <span className="vault-status">
              <span className="vault-status-dot" />
              {vaultStatus}
            </span>
          </header>

          <div
            className={
              isVaultInitialized && isVaultUnlocked
                ? "vault-workspace"
                : "vault-empty"
            }
          >
            <div className="vault-empty-icon">⌑</div>

            {vaultStatusError ? (
              <>
                <h2>Kasa durumuna ulaşılamadı</h2>
                <p>
                  Uygulama ile güvenli kasa arasındaki bağlantı kontrol
                  edilemedi. Uygulamayı yeniden başlatıp tekrar deneyebilirsin.
                </p>
              </>
            ) : isVaultInitialized === null ? (
              <>
                <h2>Kasa durumu kontrol ediliyor</h2>
                <p>Lütfen bekle.</p>
              </>
            ) : !isVaultInitialized ? (
              <>
                <h2>Kasanı oluşturalım</h2>
                <p>
                  Kasanı korumak için hesabından ayrı, güçlü bir ana parola
                  belirle.
                </p>

                <form className="vault-form" onSubmit={handleCreateVault}>
                  <label htmlFor="master-password">Ana parola</label>
                  <input
                    id="master-password"
                    type="password"
                    autoComplete="new-password"
                    value={masterPassword}
                    onChange={(event) => setMasterPassword(event.target.value)}
                    minLength={8}
                    required
                    disabled={isCreatingVault}
                    placeholder="En az 8 karakter"
                  />

                  <label htmlFor="confirm-password">Ana parola tekrarı</label>
                  <input
                    id="confirm-password"
                    type="password"
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    minLength={8}
                    required
                    disabled={isCreatingVault}
                    placeholder="Ana parolanı tekrar gir"
                  />

                  {formError && (
                    <p className="vault-form-error" role="alert">
                      {formError}
                    </p>
                  )}

                  <button
                    className="vault-primary"
                    type="submit"
                    disabled={isCreatingVault}
                  >
                    {isCreatingVault
                      ? "Kasa oluşturuluyor..."
                      : "Kasayı oluştur"}
                  </button>
                </form>
              </>
            ) : isVaultUnlocked ? (
              <>
                {!isUserLoaded || !user ? (
                  <>
                    <h2>Kullanıcı bilgileri yükleniyor</h2>
                    <p>Lütfen bekle.</p>
                  </>
                ) : (
                  <PasswordManager
                    key={user.id}
                    isUnlocked={isVaultUnlocked}
                    getSessionToken={getSessionToken}
                  />
                )}

                {formError && (
                  <p className="vault-form-error" role="alert">
                    {formError}
                  </p>
                )}

                <DevVaultResetButton />

                <button
                  className="vault-primary"
                  type="button"
                  onClick={() => void handleLockVault()}
                  disabled={isLockingVault || isSigningOut}
                >
                  {isLockingVault ? "Kasa kilitleniyor..." : "Kasayı kilitle"}
                </button>
              </>
            ) : (
              <>
                <h2>Kasam kilitli</h2>
                <p>Kasan oluşturulmuş. Devam etmek için ana parolanı gir.</p>

                <form className="vault-form" onSubmit={handleUnlockVault}>
                  <label htmlFor="unlock-master-password">Ana parola</label>
                  <input
                    id="unlock-master-password"
                    type="password"
                    autoComplete="current-password"
                    value={masterPassword}
                    onChange={(event) => setMasterPassword(event.target.value)}
                    required
                    disabled={isUnlockingVault}
                    placeholder="Ana parolanı gir"
                    autoFocus
                  />

                  {formError && (
                    <p className="vault-form-error" role="alert">
                      {formError}
                    </p>
                  )}

                  <button
                    className="vault-primary"
                    type="submit"
                    disabled={isUnlockingVault}
                  >
                    {isUnlockingVault ? "Kasa açılıyor..." : "Kasa kilidini aç"}
                  </button>
                </form>
              </>
            )}
          </div>

          <footer className="vault-footer">
            Hesap oturumu ile kasa şifrelemesi birbirinden ayrıdır.
          </footer>
        </section>
      </main>
    );
  }

  return (
    <main className="auth-page">
      <section className="auth-panel">
        <div className="auth-brand">
          <span className="auth-icon">P</span>
          <span>Password Manager</span>
        </div>

        <div className="auth-heading">
          <h1>{isSignUp ? "Hesabını oluştur" : "Tekrar hoş geldin"}</h1>
          <p>
            {isSignUp
              ? "Güvenli kasanı oluşturmak için kayıt ol."
              : "Güvenli kasana erişmek için giriş yap."}
          </p>
        </div>

        {isSignUp ? (
          <SignUp routing="hash" signInUrl="/sign-in" appearance={appearance} />
        ) : (
          <SignIn routing="hash" signUpUrl="/sign-up" appearance={appearance} />
        )}

        <p className="auth-security">
          Hesap doğrulaması ile kasa şifrelemesi birbirinden ayrıdır.
        </p>
      </section>
    </main>
  );
}

export default App;
