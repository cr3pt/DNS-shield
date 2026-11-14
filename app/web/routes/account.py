# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Users, own account (password, language, 2FA, passkeys, API tokens) and the audit log."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from webauthn.helpers import bytes_to_base64url

from app import passkeys as passkeys_lib
from app.auth import verify_password
from app.two_factor import qr_svg
from app.users import (
    LANGUAGE_NATIVE_NAMES,
    SUPPORTED_LANGUAGES,
    check_new_password,
    public_user,
)
from app.web.common import LOCALES_DIR
from app.web.context import AppContext
from app.web.models import (
    ApiTokenIn,
    ChangePasswordIn,
    LanguageIn,
    PasskeyRegisterVerifyIn,
    TotpConfirmIn,
    TotpDisableIn,
    UserCreateIn,
    UserUpdateIn,
)


def register(app: FastAPI, ctx: AppContext) -> None:
    _set_auth_cookies = ctx._set_auth_cookies
    _webauthn_origin = ctx._webauthn_origin
    _webauthn_rp_id = ctx._webauthn_rp_id
    audit_log = ctx.audit_log
    pending_challenges = ctx.pending_challenges
    require_admin = ctx.require_admin
    require_auth = ctx.require_auth
    sessions = ctx.sessions
    users = ctx.users

    @app.get("/api/users")
    def list_users(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return [public_user(u) for u in users.list()]

    @app.post("/api/users")
    def create_user(body: UserCreateIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        try:
            check_new_password(body.password)
            user = users.create(
                body.username,
                body.password,
                body.role,
                body.permissions.model_dump() if body.permissions else None,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return public_user(user)

    @app.patch("/api/users/{username}")
    def update_user(username: str, body: UserUpdateIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        try:
            if body.password:
                check_new_password(body.password)
            user = users.update(
                username,
                password=body.password or None,
                role=body.role,
                permissions=body.permissions.model_dump() if body.permissions is not None else None,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if body.password:
            sessions.destroy_all_for(username)
        return public_user(user)

    @app.delete("/api/users/{username}")
    def delete_user(username: str, admin: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if username == admin.get("username"):
            raise HTTPException(status_code=400, detail="Can't delete the account you're signed in with")
        try:
            users.delete(username)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        sessions.destroy_all_for(username)
        return {"ok": True}

    @app.post("/api/account/password")
    def change_own_password(
        body: ChangePasswordIn, response: Response, user: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        if not verify_password(body.current_password, user.get("password_hash", "")):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        try:
            check_new_password(body.new_password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if body.new_password == body.current_password:
            raise HTTPException(status_code=400, detail="The new password must differ from the current one")
        users.update(user["username"], password=body.new_password)
        # Log out every other session of this account (e.g. a stolen cookie),
        # and give this browser a fresh session so it stays signed in.
        sessions.destroy_all_for(user["username"])
        _set_auth_cookies(response, sessions.create(user["username"]))
        return {"ok": True}

    @app.get("/api/languages")
    def list_languages() -> list[dict[str, str]]:
        return [{"code": code, "name": LANGUAGE_NATIVE_NAMES.get(code, code)} for code in SUPPORTED_LANGUAGES]

    @app.get("/api/locales/{lang}")
    def get_locale(lang: str) -> Response:
        if lang not in SUPPORTED_LANGUAGES:
            raise HTTPException(status_code=404, detail="Unknown language")
        locale_path = LOCALES_DIR / f"{lang}.json"
        if locale_path.exists():
            return FileResponse(locale_path, media_type="application/json")
        return Response(content="{}", media_type="application/json")

    @app.post("/api/account/language")
    def set_own_language(body: LanguageIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            updated = users.set_language(user["username"], body.language)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return public_user(updated)

    @app.post("/api/account/totp/setup")
    def start_totp_setup(user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        secret, uri = users.begin_totp_setup(user["username"])
        return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}

    @app.post("/api/account/totp/confirm")
    def confirm_totp_setup(body: TotpConfirmIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            backup_codes = users.confirm_totp_setup(user["username"], body.code)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True, "backup_codes": backup_codes}

    @app.post("/api/account/totp/disable")
    def disable_totp(body: TotpDisableIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            users.disable_totp(user["username"], body.password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/api/account/passkeys/register/options")
    def start_passkey_registration(request: Request, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        existing_ids = users.passkey_credential_ids(user["username"])
        options_json, challenge = passkeys_lib.registration_options_json(
            _webauthn_rp_id(request), "DNS-shield", user["username"], existing_ids
        )
        token = pending_challenges.new_token(user["username"], challenge)
        return {"token": token, "options": options_json}

    @app.post("/api/account/passkeys/register/verify")
    def confirm_passkey_registration(
        body: PasskeyRegisterVerifyIn, request: Request, user: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        entry = pending_challenges.pop(body.token)
        if entry is None or entry[0] != user["username"]:
            raise HTTPException(status_code=400, detail="Registration session expired - try again")
        challenge = entry[1]
        try:
            result = passkeys_lib.verify_registration(
                credential=body.credential,
                expected_challenge=challenge,
                rp_id=_webauthn_rp_id(request),
                origin=_webauthn_origin(request),
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not verify passkey: {exc}") from exc
        credential_id = bytes_to_base64url(result.credential_id)
        return users.add_passkey(
            user["username"], body.name, credential_id, result.credential_public_key, result.sign_count
        )

    @app.get("/api/account/passkeys")
    def list_passkeys(user: dict[str, Any] = Depends(require_auth)) -> list[dict[str, Any]]:
        return users.list_passkeys(user["username"])

    @app.delete("/api/account/passkeys/{passkey_id}")
    def delete_passkey(passkey_id: str, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            users.remove_passkey(user["username"], passkey_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"ok": True}

    @app.get("/api/account/tokens")
    def list_api_tokens(user: dict[str, Any] = Depends(require_auth)) -> list[dict[str, Any]]:
        return users.list_tokens(user["username"])

    @app.post("/api/account/tokens")
    def create_api_token(body: ApiTokenIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            token, record = users.create_token(user["username"], body.name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"token": token, **record}

    @app.delete("/api/account/tokens/{token_id}")
    def revoke_api_token(token_id: str, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            users.revoke_token(user["username"], token_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"ok": True}

    @app.get("/api/audit-log")
    def list_audit_log(
        before_id: int | None = None, limit: int = 200, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        if audit_log is None:
            return []
        return audit_log.list(limit=min(limit, 500), before_id=before_id)
