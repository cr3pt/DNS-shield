# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Login (password, TOTP, passkeys, SSO), logout and whoami."""

from __future__ import annotations

import base64
import secrets
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response

from app import passkeys as passkeys_lib
from app.sessions import COOKIE_NAME
from app.sso import OIDCError, build_authorization_url, exchange_code, verify_id_token
from app.users import public_user
from app.web.common import STATIC_DIR
from app.web.context import AppContext
from app.web.models import (
    LoginIn,
    PasskeyLoginOptionsIn,
    PasskeyLoginVerifyIn,
    TotpLoginIn,
)


def register(app: FastAPI, ctx: AppContext) -> None:
    NO_CACHE = ctx.NO_CACHE
    _clear_auth_cookies = ctx._clear_auth_cookies
    _client_ip = ctx._client_ip
    _current_user = ctx._current_user
    _enforce_login_throttle = ctx._enforce_login_throttle
    _login_retry_after = ctx._login_retry_after
    _set_auth_cookies = ctx._set_auth_cookies
    _webauthn_origin = ctx._webauthn_origin
    _webauthn_rp_id = ctx._webauthn_rp_id
    audit_log = ctx.audit_log
    config_store = ctx.config_store
    login_throttle = ctx.login_throttle
    pending_challenges = ctx.pending_challenges
    pending_sso = ctx.pending_sso
    pending_totp = ctx.pending_totp
    sessions = ctx.sessions
    users = ctx.users

    @app.get("/login")
    def login_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "login.html", headers=NO_CACHE)

    @app.post("/api/login")
    def login(body: LoginIn, request: Request, response: Response) -> dict[str, Any]:
        client_ip = _client_ip(request)
        _enforce_login_throttle(client_ip)

        user = users.verify_login(body.username.strip(), body.password)
        if user is None:
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if users.has_second_factor(user["username"]):
            totp_token = pending_totp.create(user["username"])
            return {
                "ok": True,
                "totp_required": True,
                "totp_token": totp_token,
                "totp_available": bool(user.get("totp_enabled")),
                "passkey_available": bool(user.get("webauthn_credentials")),
            }

        login_throttle.record_success(client_ip)
        token = sessions.create(user["username"])
        _set_auth_cookies(response, token)
        if audit_log is not None:
            audit_log.record(user["username"], "login", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/login/totp")
    def login_totp(body: TotpLoginIn, request: Request, response: Response) -> dict[str, Any]:
        client_ip = _client_ip(request)
        _enforce_login_throttle(client_ip)

        username = pending_totp.username_for(body.totp_token)
        if username is None:
            raise HTTPException(status_code=401, detail="Login session expired - sign in again")

        if not users.verify_totp_or_backup_code(username, body.code):
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Incorrect authenticator code")

        pending_totp.consume(body.totp_token)
        login_throttle.record_success(client_ip)
        user = users.get(username)
        token = sessions.create(username)
        _set_auth_cookies(response, token)
        if audit_log is not None:
            audit_log.record(username, "login (2FA)", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/login/passkey/options")
    def login_passkey_options(body: PasskeyLoginOptionsIn, request: Request) -> dict[str, Any]:
        username = pending_totp.username_for(body.totp_token)
        if username is None:
            raise HTTPException(status_code=401, detail="Login session expired - sign in again")
        credential_ids = users.passkey_credential_ids(username)
        if not credential_ids:
            raise HTTPException(status_code=400, detail="No passkeys registered for this account")
        options_json, challenge = passkeys_lib.authentication_options_json(_webauthn_rp_id(request), credential_ids)
        pending_challenges.set(body.totp_token, username, challenge)
        return {"options": options_json}

    @app.post("/api/login/passkey/verify")
    def login_passkey_verify(body: PasskeyLoginVerifyIn, request: Request, response: Response) -> dict[str, Any]:
        client_ip = _client_ip(request)
        _enforce_login_throttle(client_ip)

        pending_username = pending_totp.username_for(body.totp_token)
        challenge_entry = pending_challenges.get(body.totp_token)
        if pending_username is None or challenge_entry is None or challenge_entry[0] != pending_username:
            raise HTTPException(status_code=401, detail="Login session expired - sign in again")
        username, challenge = challenge_entry

        credential_id = body.credential.get("id")
        passkey = users.find_passkey_by_credential_id(username, credential_id) if credential_id else None
        if passkey is None:
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Unrecognized passkey")

        try:
            result = passkeys_lib.verify_authentication(
                credential=body.credential,
                expected_challenge=challenge,
                rp_id=_webauthn_rp_id(request),
                origin=_webauthn_origin(request),
                public_key=base64.b64decode(passkey["public_key"]),
                sign_count=passkey.get("sign_count", 0),
            )
        except Exception:
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Passkey verification failed")

        users.record_passkey_use(username, passkey["credential_id"], result.new_sign_count)
        pending_totp.consume(body.totp_token)
        pending_challenges.pop(body.totp_token)
        login_throttle.record_success(client_ip)
        user = users.get(username)
        token = sessions.create(username)
        _set_auth_cookies(response, token)
        if audit_log is not None:
            audit_log.record(username, "login (passkey)", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    def _sso_config() -> dict[str, Any]:
        return config_store.get("sso", default={}) or {}

    def _sso_redirect_uri(request: Request) -> str:
        return f"{request.url.scheme}://{request.url.netloc}/api/sso/callback"

    @app.get("/api/sso/login")
    def sso_login(request: Request, next: str = "/") -> RedirectResponse:
        cfg = _sso_config()
        if not cfg.get("enabled"):
            raise HTTPException(status_code=404, detail="Single sign-on is not enabled")
        nonce = secrets.token_urlsafe(24)
        safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
        state = pending_sso.create(nonce, safe_next)
        try:
            auth_url = build_authorization_url(cfg, _sso_redirect_uri(request), state, nonce)
        except OIDCError:
            return RedirectResponse("/login?error=sso_unavailable")
        return RedirectResponse(auth_url)

    @app.get("/api/sso/callback")
    def sso_callback(
        request: Request,
        response: Response,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ) -> RedirectResponse:
        client_ip = _client_ip(request)
        cfg = _sso_config()
        if not cfg.get("enabled"):
            raise HTTPException(status_code=404, detail="Single sign-on is not enabled")

        if _login_retry_after(client_ip) is not None:
            return RedirectResponse("/login?error=sso_failed")

        entry = pending_sso.consume(state)
        if error or entry is None:
            return RedirectResponse("/login?error=sso_failed")

        if code is None:
            return RedirectResponse("/login?error=sso_failed")

        try:
            token, metadata = exchange_code(cfg, _sso_redirect_uri(request), code)
            id_token = token.get("id_token")
            if not id_token:
                raise OIDCError("Identity provider did not return an ID token")
            claims = verify_id_token(id_token, metadata, cfg, entry["nonce"])
        except OIDCError:
            login_throttle.record_failure(client_ip)
            return RedirectResponse("/login?error=sso_failed")

        username_claim = cfg.get("username_claim") or "preferred_username"
        identity = claims.get(username_claim) or claims.get("email") or claims.get("sub")
        if not identity:
            return RedirectResponse("/login?error=sso_no_identity")
        identity = str(identity).strip()

        existing = users.get(identity)
        if existing is not None and not existing.get("sso"):
            login_throttle.record_failure(client_ip)
            return RedirectResponse("/login?error=sso_account_conflict")
        if existing is None:
            if not cfg.get("auto_provision", True):
                return RedirectResponse("/login?error=sso_no_account")
            user = users.find_or_create_sso(identity, cfg.get("default_role") or "user")
        else:
            user = existing

        login_throttle.record_success(client_ip)
        session_token = sessions.create(user["username"])
        redirect = RedirectResponse(entry.get("next") or "/")
        _set_auth_cookies(redirect, session_token)
        if audit_log is not None:
            audit_log.record(user["username"], "login (SSO)", client_ip=client_ip)
        return redirect

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, Any]:
        user = _current_user(request)
        sessions.destroy(request.cookies.get(COOKIE_NAME))
        _clear_auth_cookies(response)
        if audit_log is not None and user is not None:
            client_ip = _client_ip(request)
            audit_log.record(user["username"], "logout", client_ip=client_ip)
        return {"ok": True}

    @app.get("/api/whoami")
    def whoami(request: Request) -> dict[str, Any]:
        user = _current_user(request)
        enr = config_store.get("enrichment", default={}) or {}
        public_ready = bool(enr.get("public_enabled")) and (
            any(
                enr.get(k)
                for k in (
                    "virustotal_api_key",
                    "abuseipdb_api_key",
                    "otx_api_key",
                    "greynoise_api_key",
                    "shodan_api_key",
                    "urlhaus_api_key",
                )
            )
            or enr.get("rdap_enabled", True)
            or enr.get("crtsh_enabled")
        )
        local_ready = bool(enr.get("local_enabled")) and bool(enr.get("local_url"))
        sso_cfg = config_store.get("sso", default={}) or {}
        return {
            "user": public_user(user) if user is not None else None,
            "enrichment_available": public_ready or local_ready,
            "sso_enabled": bool(sso_cfg.get("enabled")),
            "sso_button_label": sso_cfg.get("button_label") or "Single Sign-On",
        }
