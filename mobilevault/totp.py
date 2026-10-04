"""RFC 4226 (HOTP) and RFC 6238 (TOTP), standard library only."""
import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlsplit


def _key(secret) -> bytes:
    if isinstance(secret, bytes):
        return secret
    s = secret.replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    mac = hmac.new(_key(secret), struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret, at: float, step: int = 30, digits: int = 6, algo: str = "sha1") -> str:
    return hotp(secret, int(at // step), digits, algo)


def totp_now(secret, **kw) -> str:
    return totp(secret, time.time(), **kw)


def parse_otpauth(uri: str) -> dict:
    u = urlsplit(uri)
    if u.scheme != "otpauth" or u.netloc != "totp":
        raise ValueError("expected an otpauth://totp/ URI")
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    if "secret" not in q:
        raise ValueError("otpauth URI has no secret")
    return {"label": unquote(u.path.lstrip("/")), "secret": q["secret"], "issuer": q.get("issuer", ""),
            "digits": int(q.get("digits", 6)), "step": int(q.get("period", 30)),
            "algo": q.get("algorithm", "SHA1").lower()}
