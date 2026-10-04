import json
import os
import stat
import pytest
from mobilevault import *

FAST = 2 ** 10
KEY = b"12345678901234567890"


def test_hotp_rfc4226_vectors():
    exp = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [hotp(KEY, i) for i in range(10)] == exp


@pytest.mark.parametrize("t,code", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")])
def test_totp_rfc6238_sha1_vectors(t, code):
    assert totp(KEY, t, digits=8) == code


def test_totp_base32_and_otpauth_parsing():
    import base64
    b32 = base64.b32encode(KEY).decode()
    assert totp(b32, 59, digits=8) == "94287082" and totp(b32.lower(), 59, digits=8) == "94287082"
    p = parse_otpauth(f"otpauth://totp/Acme:bob%40x.com?secret={b32}&issuer=Acme&digits=8&period=30")
    assert p["label"] == "Acme:bob@x.com" and p["digits"] == 8 and p["issuer"] == "Acme"
    with pytest.raises(ValueError):
        parse_otpauth("https://example.com")


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "v.json"), scrypt_n=FAST)
    v.create("correct horse battery")
    return v


def test_roundtrip_and_crud(vault):
    eid = vault.add("GitHub", "nobita", "s3cret-Pass!", "https://github.com", totp_secret="JBSWY3DPEHPK3PXP")
    v2 = Vault(vault.path)
    v2.unlock("correct horse battery")
    assert v2.get(eid)["password"] == "s3cret-Pass!"
    v2.update(eid, username="clea")
    v2.delete(eid)
    with pytest.raises(KeyError):
        v2.get(eid)


def test_file_has_no_plaintext_and_is_0600(vault):
    vault.add("Bank", "me", "ultra-secret-pw-123")
    raw = open(vault.path).read()
    assert "ultra-secret-pw-123" not in raw and "Bank" not in raw
    assert stat.S_IMODE(os.stat(vault.path).st_mode) == 0o600


def test_wrong_password_rejected(vault):
    v = Vault(vault.path)
    with pytest.raises(WrongPassword):
        v.unlock("nope-nope-nope")


def test_every_tamper_is_detected(vault):
    vault.add("a", password="x" * 12)
    blob = json.load(open(vault.path))
    import base64
    for field in ("ct", "nonce"):
        b = bytearray(base64.b64decode(blob[field]))
        b[0] ^= 1
        bad = dict(blob, **{field: base64.b64encode(bytes(b)).decode()})
        json.dump(bad, open(vault.path, "w"))
        with pytest.raises(VaultError):
            Vault(vault.path).unlock("correct horse battery")
    bad = json.loads(json.dumps(blob))
    bad["kdf"]["n"] = 2 ** 9                    # downgrade attack on KDF cost: must fail authentication
    json.dump(bad, open(vault.path, "w"))
    with pytest.raises(VaultError):
        Vault(vault.path).unlock("correct horse battery")


def test_nonce_changes_on_every_save(vault):
    n1 = json.load(open(vault.path))["nonce"]
    vault.add("x")
    n2 = json.load(open(vault.path))["nonce"]
    vault.add("y")
    assert len({n1, n2, json.load(open(vault.path))["nonce"]}) == 3


def test_garbage_file_and_missing_file(tmp_path):
    p = tmp_path / "junk"
    p.write_text("not json")
    with pytest.raises(TamperedVault):
        Vault(str(p)).unlock("whatever123")
    with pytest.raises(TamperedVault):
        Vault(str(tmp_path / "missing")).unlock("whatever123")


def test_auto_lock_and_manual_lock(tmp_path):
    t = [0.0]
    v = Vault(str(tmp_path / "v"), scrypt_n=FAST, auto_lock_seconds=60, clock=lambda: t[0])
    v.create("correct horse battery")
    v.add("a")
    t[0] = 30
    assert not v.locked
    t[0] = 91
    assert v.locked
    with pytest.raises(VaultError):
        v.add("b")
    v.unlock("correct horse battery")
    v.lock()
    with pytest.raises(VaultError):
        v.search("a")


def test_change_master_password(vault):
    eid = vault.add("a", password="pw-123456789")
    vault.change_master_password("a brand new passphrase")
    with pytest.raises(WrongPassword):
        Vault(vault.path).unlock("correct horse battery")
    v = Vault(vault.path)
    v.unlock("a brand new passphrase")
    assert v.get(eid)["password"] == "pw-123456789"


def test_create_refuses_overwrite_and_short_password(tmp_path, vault):
    with pytest.raises(VaultError):
        Vault(vault.path, scrypt_n=FAST).create("another long password")
    with pytest.raises(VaultError):
        Vault(str(tmp_path / "new"), scrypt_n=FAST).create("short")


def test_search_and_audit(vault):
    vault.add("GitHub", "me", "same-password-1", "https://github.com")
    vault.add("GitLab", "me", "same-password-1")
    vault.add("Old", "me", "short")
    assert {r["name"] for r in vault.search("git")} == {"GitHub", "GitLab"}
    a = vault.audit()
    assert a["reused"] == [["GitHub", "GitLab"]] and a["weak"] == ["Old"]


def test_password_generator_properties():
    for _ in range(200):
        pw = generate_password(16)
        assert len(pw) == 16 and any(c.islower() for c in pw) and any(c.isupper() for c in pw) \
            and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)
    assert len({generate_password(20) for _ in range(100)}) == 100
    assert not set(generate_password(200, avoid_ambiguous=True)) & set("Il1O0o")
    assert generate_password(12, symbols=False).isalnum()
    with pytest.raises(ValueError):
        generate_password(4)
    assert len(generate_passphrase(6).split("-")) == 6
    assert entropy_bits("aaaaaaaa") < entropy_bits(generate_password(20))
