// SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause - see the LICENSE file in the project root for full license terms.
const I18N_PL = {
  "login.tagline": "Zaloguj się, aby zarządzać swoim DNS",
  "login.username": "Nazwa użytkownika",
  "login.password": "Hasło",
  "login.sign_in": "Zaloguj się",
  "login.totp_code": "Kod uwierzytelniający",
  "login.totp_ph": "6-cyfrowy kod lub kod zapasowy",
  "login.verify": "Zweryfikuj",
  "login.use_passkey": "Użyj klucza dostępu",
  "login.or": "lub",
  "login.view_public": "Zobacz publiczne statystyki bez logowania →",
  "login.signing_in": "Logowanie...",
  "login.invalid_credentials": "Nieprawidłowa nazwa użytkownika lub hasło",
  "login.sign_in_failed": "Logowanie nie powiodło się",
  "login.verifying": "Weryfikacja...",
  "login.incorrect_code": "Nieprawidłowy kod",
  "login.verification_failed": "Weryfikacja nie powiodła się",
  "login.waiting_passkey": "Oczekiwanie na klucz dostępu...",
  "login.passkey_start_failed": "Nie udało się rozpocząć logowania kluczem dostępu",
  "login.passkey_signin_failed": "Logowanie kluczem dostępu nie powiodło się",
  "login.passkey_failed": "Logowanie kluczem dostępu nie powiodło się lub zostało anulowane",
  "login.sign_in_with": "Zaloguj się przez ",
  "login.page_title": "DNS-shield - Logowanie",
  "sso.sso_failed": "Logowanie jednokrotne nie powiodło się - spróbuj ponownie lub użyj nazwy użytkownika i hasła.",
  "sso.sso_expired": "Żądanie logowania wygasło - spróbuj ponownie.",
  "sso.sso_unavailable": "Logowanie jednokrotne jest tymczasowo niedostępne.",
  "sso.sso_no_identity": "Dostawca tożsamości nie zwrócił użytecznej nazwy konta.",
  "sso.sso_no_account": "Nie istnieje jeszcze konto DNS-shield dla tej tożsamości - poproś administratora o jego utworzenie.",
};

function detectBrowserLang() {
  const nav = (navigator.language || navigator.userLanguage || "en").toLowerCase();
  return nav.startsWith("pl") ? "pl" : "en";
}

const currentLang = detectBrowserLang();

function t(key, fallback) {
  if (currentLang === "pl" && Object.prototype.hasOwnProperty.call(I18N_PL, key)) return I18N_PL[key];
  return fallback !== undefined ? fallback : key;
}

function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((elm) => {
    const key = elm.getAttribute("data-i18n");
    if (currentLang === "pl" && Object.prototype.hasOwnProperty.call(I18N_PL, key)) elm.innerHTML = I18N_PL[key];
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((elm) => {
    const key = elm.getAttribute("data-i18n-ph");
    if (currentLang === "pl" && Object.prototype.hasOwnProperty.call(I18N_PL, key)) elm.setAttribute("placeholder", I18N_PL[key]);
  });
  document.documentElement.lang = currentLang;
  document.title = t("login.page_title", document.title);
}
applyI18n();

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBuffer(base64url) {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const buffer = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buffer[i] = raw.charCodeAt(i);
  return buffer.buffer;
}

const form = document.getElementById("login-form");
const totpForm = document.getElementById("totp-form");
const errorBox = document.getElementById("error");
const submitBtn = document.getElementById("submit-btn");
const totpSubmitBtn = document.getElementById("totp-submit-btn");
const totpCodeInput = document.getElementById("totp-code");
const passkeyBtn = document.getElementById("passkey-btn");

const params = new URLSearchParams(location.search);
const nextUrl = params.get("next") || "/";
let pendingTotpToken = null;

const ssoErrors = {
  sso_failed: t("sso.sso_failed", "Single sign-on failed - try again, or use your username and password."),
  sso_expired: t("sso.sso_expired", "The sign-in request expired - try again."),
  sso_unavailable: t("sso.sso_unavailable", "Single sign-on is temporarily unavailable."),
  sso_no_identity: t("sso.sso_no_identity", "The identity provider did not return a usable account name."),
  sso_no_account: t("sso.sso_no_account", "No DNS-shield account exists for that identity yet - ask an administrator to create one."),
};
const ssoError = params.get("error");
if (ssoError && ssoErrors[ssoError]) {
  errorBox.textContent = ssoErrors[ssoError];
  errorBox.style.display = "block";
}

fetch("/api/whoami").then((r) => r.json()).then((body) => {
  if (body.sso_enabled) {
    const btn = document.getElementById("sso-btn");
    btn.textContent = t("login.sign_in_with", "Sign in with ") + (body.sso_button_label || "SSO");
    btn.href = "/api/sso/login?next=" + encodeURIComponent(nextUrl.startsWith("/") ? nextUrl : "/");
    btn.style.display = "block";
    document.getElementById("sso-divider").style.display = "flex";
  }
}).catch(() => {});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorBox.style.display = "none";
  submitBtn.disabled = true;
  submitBtn.textContent = t("login.signing_in", "Signing in...");
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(body.detail || t("login.invalid_credentials", "Invalid username or password"));
    }
    if (body.totp_required) {
      pendingTotpToken = body.totp_token;
      form.style.display = "none";
      totpForm.style.display = "flex";
      document.getElementById("totp-code-field").style.display = body.totp_available ? "" : "none";
      totpCodeInput.required = !!body.totp_available;
      totpSubmitBtn.style.display = body.totp_available ? "" : "none";
      const canUsePasskey = body.passkey_available && window.PublicKeyCredential;
      passkeyBtn.style.display = canUsePasskey ? "" : "none";
      if (body.totp_available) {
        totpCodeInput.focus();
      } else if (canUsePasskey) {
        passkeyBtn.click();
      }
      return;
    }
    location.href = nextUrl.startsWith("/") ? nextUrl : "/";
  } catch (err) {
    errorBox.textContent = err.message || t("login.sign_in_failed", "Sign in failed");
    errorBox.style.display = "block";
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = t("login.sign_in", "Sign in");
  }
});

totpForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorBox.style.display = "none";
  totpSubmitBtn.disabled = true;
  totpSubmitBtn.textContent = t("login.verifying", "Verifying...");
  try {
    const res = await fetch("/api/login/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        totp_token: pendingTotpToken,
        code: totpCodeInput.value,
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || t("login.incorrect_code", "Incorrect code"));
    }
    location.href = nextUrl.startsWith("/") ? nextUrl : "/";
  } catch (err) {
    errorBox.textContent = err.message || t("login.verification_failed", "Verification failed");
    errorBox.style.display = "block";
  } finally {
    totpSubmitBtn.disabled = false;
    totpSubmitBtn.textContent = t("login.verify", "Verify");
  }
});

passkeyBtn.addEventListener("click", async () => {
  errorBox.style.display = "none";
  passkeyBtn.disabled = true;
  passkeyBtn.textContent = t("login.waiting_passkey", "Waiting for your passkey...");
  try {
    const optRes = await fetch("/api/login/passkey/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ totp_token: pendingTotpToken }),
    });
    if (!optRes.ok) {
      const body = await optRes.json().catch(() => ({}));
      throw new Error(body.detail || t("login.passkey_start_failed", "Could not start passkey sign-in"));
    }
    const { options } = await optRes.json();
    const opts = JSON.parse(options);
    opts.challenge = base64urlToBuffer(opts.challenge);
    if (opts.allowCredentials) {
      for (const c of opts.allowCredentials) c.id = base64urlToBuffer(c.id);
    }
    const assertion = await navigator.credentials.get({ publicKey: opts });
    const credentialJson = {
      id: assertion.id,
      rawId: bufferToBase64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        signature: bufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
      },
    };
    const verifyRes = await fetch("/api/login/passkey/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ totp_token: pendingTotpToken, credential: credentialJson }),
    });
    if (!verifyRes.ok) {
      const body = await verifyRes.json().catch(() => ({}));
      throw new Error(body.detail || t("login.passkey_signin_failed", "Passkey sign-in failed"));
    }
    location.href = nextUrl.startsWith("/") ? nextUrl : "/";
  } catch (err) {
    errorBox.textContent = err.message || t("login.passkey_failed", "Passkey sign-in failed or was cancelled");
    errorBox.style.display = "block";
  } finally {
    passkeyBtn.disabled = false;
    passkeyBtn.textContent = t("login.use_passkey", "Use a passkey instead");
  }
});
