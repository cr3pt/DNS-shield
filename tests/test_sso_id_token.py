# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import base64
import hashlib
import hmac
import json
import time

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, KeySet, OctKey, RSAKey

import app.sso as sso

ISSUER = "https://idp.example.com"
CLIENT_ID = "dns-shield"
NONCE = "expected-nonce"
METADATA = {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"}
CFG = {"client_id": CLIENT_ID}


@pytest.fixture(scope="module")
def rsa_key():
    return RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})


@pytest.fixture(scope="module")
def ec_key():
    return ECKey.generate_key("P-256", parameters={"kid": "ec-1"})


@pytest.fixture
def serve_jwks(monkeypatch):
    def serve(*keys):
        document = KeySet(list(keys)).as_dict(private=False)

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return document

        monkeypatch.setattr(sso.requests, "get", lambda url, timeout: Response())

    return serve


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "nonce": NONCE,
        "iat": now,
        "exp": now + 300,
        "preferred_username": "alice",
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def _b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _sign(key, claims, alg="RS256"):
    return jwt.encode({"alg": alg, "kid": key.kid}, claims, key)


def test_a_correctly_signed_token_is_accepted(rsa_key, serve_jwks):
    serve_jwks(rsa_key)

    claims = sso.verify_id_token(_sign(rsa_key, _claims()), METADATA, CFG, NONCE)

    assert claims["preferred_username"] == "alice"
    assert claims["sub"] == "user-1"


def test_elliptic_curve_signatures_are_accepted(ec_key, serve_jwks):
    serve_jwks(ec_key)

    claims = sso.verify_id_token(_sign(ec_key, _claims(), alg="ES256"), METADATA, CFG, NONCE)

    assert claims["sub"] == "user-1"


def test_the_matching_key_is_picked_out_of_a_larger_key_set(rsa_key, ec_key, serve_jwks):
    serve_jwks(ec_key, rsa_key)

    assert sso.verify_id_token(_sign(rsa_key, _claims()), METADATA, CFG, NONCE)["sub"] == "user-1"


def test_a_list_audience_containing_the_client_id_is_accepted(rsa_key, serve_jwks):
    serve_jwks(rsa_key)
    token = _sign(rsa_key, _claims(aud=["other-client", CLIENT_ID]))

    assert sso.verify_id_token(token, METADATA, CFG, NONCE)["sub"] == "user-1"


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.example.com"},
        {"iss": None},
        {"aud": "someone-else"},
        {"aud": None},
        {"exp": int(time.time()) - 3600},
        {"exp": None},
        {"nbf": int(time.time()) + 3600},
    ],
    ids=["wrong-issuer", "no-issuer", "wrong-audience", "no-audience", "expired", "no-expiry", "not-yet-valid"],
)
def test_tokens_with_bad_claims_are_rejected(rsa_key, serve_jwks, overrides):
    serve_jwks(rsa_key)

    with pytest.raises(sso.OIDCError):
        sso.verify_id_token(_sign(rsa_key, _claims(**overrides)), METADATA, CFG, NONCE)


def test_a_small_clock_skew_is_tolerated(rsa_key, serve_jwks):
    serve_jwks(rsa_key)
    token = _sign(rsa_key, _claims(exp=int(time.time()) - 10))

    assert sso.verify_id_token(token, METADATA, CFG, NONCE)["sub"] == "user-1"


def test_a_nonce_mismatch_is_rejected_as_a_replay(rsa_key, serve_jwks):
    serve_jwks(rsa_key)

    with pytest.raises(sso.OIDCError, match="nonce"):
        sso.verify_id_token(_sign(rsa_key, _claims(nonce="another")), METADATA, CFG, NONCE)


def test_a_token_missing_its_nonce_is_rejected(rsa_key, serve_jwks):
    serve_jwks(rsa_key)

    with pytest.raises(sso.OIDCError, match="nonce"):
        sso.verify_id_token(_sign(rsa_key, _claims(nonce=None)), METADATA, CFG, NONCE)


def test_a_token_signed_by_an_unknown_key_is_rejected(rsa_key, serve_jwks):
    serve_jwks(rsa_key)
    attacker = RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})

    with pytest.raises(sso.OIDCError):
        sso.verify_id_token(_sign(attacker, _claims()), METADATA, CFG, NONCE)


def test_a_tampered_payload_is_rejected(rsa_key, serve_jwks):
    serve_jwks(rsa_key)
    good = _sign(rsa_key, _claims(preferred_username="alice"))
    forged = _sign(rsa_key, _claims(preferred_username="admin"))
    header, _, signature = good.split(".")
    forged_payload = forged.split(".")[1]

    with pytest.raises(sso.OIDCError):
        sso.verify_id_token(f"{header}.{forged_payload}.{signature}", METADATA, CFG, NONCE)


def test_an_unsigned_token_is_rejected(rsa_key, serve_jwks):
    serve_jwks(rsa_key)
    unsigned = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(_claims())}."

    with pytest.raises(sso.OIDCError):
        sso.verify_id_token(unsigned, METADATA, CFG, NONCE)


def test_a_symmetric_algorithm_cannot_be_used_to_forge_a_token(rsa_key, serve_jwks):
    serve_jwks(rsa_key)
    signing_input = f"{_b64({'alg': 'HS256', 'kid': 'rsa-1'})}.{_b64(_claims())}"
    mac = hmac.new(rsa_key.as_pem(private=False), signing_input.encode(), hashlib.sha256).digest()
    forged = f"{signing_input}.{base64.urlsafe_b64encode(mac).rstrip(b'=').decode()}"

    with pytest.raises(sso.OIDCError):
        sso.verify_id_token(forged, METADATA, CFG, NONCE)


def test_garbage_is_reported_as_a_verification_failure(rsa_key, serve_jwks):
    serve_jwks(rsa_key)

    with pytest.raises(sso.OIDCError, match="ID token verification failed"):
        sso.verify_id_token("not-a-jwt", METADATA, CFG, NONCE)


def test_a_discovery_document_without_jwks_uri_is_rejected(rsa_key):
    with pytest.raises(sso.OIDCError, match="jwks_uri"):
        sso.verify_id_token(_sign(rsa_key, _claims()), {"issuer": ISSUER}, CFG, NONCE)
