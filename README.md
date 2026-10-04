# MobileVault

The cryptographic core of a password manager: an **encrypted credential vault**, **RFC-correct TOTP**, and a password
generator. Library only (Python); it is the secure backend you would put behind a mobile or desktop UI. It is *not* a mobile app.

```python
from mobilevault import Vault, totp_now, generate_password

v = Vault("vault.json", auto_lock_seconds=120)
v.create("correct horse battery")
eid = v.add("GitHub", "nobita", generate_password(24), "https://github.com", totp_secret="JBSWY3DPEHPK3PXP")
print(totp_now(v.get(eid)["totp_secret"]))      # 6-digit 2FA code
```

## Security design

| Concern | Choice |
|---|---|
| Key derivation | **scrypt** (N=2^15, r=8, p=1), random 16-byte salt per vault; ~90-100 ms per unlock on the test machine |
| Encryption | **AES-256-GCM**, fresh 96-bit random nonce on *every* save (tested) |
| Header integrity | KDF parameters are bound in as GCM associated data, so lowering N to weaken the KDF **fails authentication** (tested) |
| Tamper evidence | any flipped bit in ciphertext, nonce or header is rejected; a wrong password and tampering are deliberately indistinguishable |
| Plaintext at rest | none: entry names, usernames, URLs and notes are all inside the ciphertext (tested) |
| Writes | atomic (`mkstemp` + `fsync` + `os.replace`), file mode `0600` |
| Session | `lock()` drops key and entries; optional **auto-lock** after idle time (injected clock, tested) |
| Master password rotation | `change_master_password()` re-salts and re-derives; the old password stops working (tested) |
| Generator | `secrets`-based; guarantees every character class; optional no-ambiguous-characters; passphrase mode |
| Audit | finds reused and short passwords locally; nothing leaves the device |

## TOTP
Implemented from the RFCs with `hmac`/`hashlib` only and verified against the **official test vectors**: RFC 4226 HOTP
(counts 0-9) and RFC 6238 TOTP (SHA-1, 8 digits, times 59 ... 20000000000). Supports Base32 secrets and `otpauth://` URIs.

## Honest limits
- Python cannot reliably wipe secrets from memory; decrypted data lives in ordinary `str`/`dict` objects while unlocked.
- No sync, no biometric unlock, no UI, no clipboard handling, no brute-force lockout (scrypt cost is the only throttle).
- `entropy_bits` is a character-class upper bound, not a guess-resistance estimate for human-chosen passwords.
- Not independently audited. Do not use it to protect real secrets without a review.

## Development
```
pip install -e .[dev] && pytest -q      # 19 tests
```
MIT licensed.
