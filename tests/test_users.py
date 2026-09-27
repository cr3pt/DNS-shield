import pyotp

from app.users import UserStore


def _store(config_store) -> UserStore:
    store = UserStore(config_store)
    store.create("alice", "hunter22", "user")
    return store


def test_create_token_round_trips_through_find_by_token(config_store):
    store = _store(config_store)
    token, _ = store.create_token("alice", "my token")

    found = store.find_by_token(token)

    assert found is not None
    assert found["username"] == "alice"


def test_find_by_token_rejects_wrong_token(config_store):
    store = _store(config_store)
    store.create_token("alice", "my token")

    assert store.find_by_token("not-a-real-token") is None


def test_find_by_token_rejects_empty_token(config_store):
    store = _store(config_store)

    assert store.find_by_token("") is None


def test_revoked_token_no_longer_verifies(config_store):
    store = _store(config_store)
    token, record = store.create_token("alice", "my token")
    store.revoke_token("alice", record["id"])

    assert store.find_by_token(token) is None


def test_verify_totp_or_backup_code_accepts_valid_totp_code(config_store):
    store = _store(config_store)
    secret, _ = store.begin_totp_setup("alice")
    valid_code = pyotp.TOTP(secret).now()
    store.confirm_totp_setup("alice", valid_code)

    assert store.verify_totp_or_backup_code("alice", pyotp.TOTP(secret).now()) is True


def test_verify_totp_or_backup_code_accepts_and_consumes_backup_code(config_store):
    store = _store(config_store)
    secret, _ = store.begin_totp_setup("alice")
    backup_codes = store.confirm_totp_setup("alice", pyotp.TOTP(secret).now())
    code = backup_codes[0]

    assert store.verify_totp_or_backup_code("alice", code) is True
    assert store.verify_totp_or_backup_code("alice", code) is False


def test_verify_totp_or_backup_code_rejects_wrong_code(config_store):
    store = _store(config_store)
    secret, _ = store.begin_totp_setup("alice")
    store.confirm_totp_setup("alice", pyotp.TOTP(secret).now())

    assert store.verify_totp_or_backup_code("alice", "000000") is False


def test_verify_totp_or_backup_code_false_when_totp_not_enabled(config_store):
    store = _store(config_store)

    assert store.verify_totp_or_backup_code("alice", "000000") is False
