"""Encrypted credential vault: scrypt KDF + AES-256-GCM, authenticated header, atomic writes, auto-lock."""
from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import uuid
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = "MobileVault/1"


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class TamperedVault(VaultError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _kdf(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode())


class Vault:
    def __init__(self, path: str, scrypt_n: int = 2 ** 15, auto_lock_seconds: Optional[float] = None,
                 clock=time.monotonic):
        self.path, self.n, self.r, self.p = path, scrypt_n, 8, 1
        self.auto_lock, self.clock = auto_lock_seconds, clock
        self._entries: Optional[Dict[str, dict]] = None
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._last = 0.0

    # -- lifecycle -----------------------------------------------------------
    def create(self, password: str):
        if os.path.exists(self.path):
            raise VaultError("vault already exists")
        if len(password) < 8:
            raise VaultError("master password must be at least 8 characters")
        self._salt = os.urandom(16)
        self._key = _kdf(password, self._salt, self.n, self.r, self.p)
        self._entries = {}
        self._touch()
        self._save()

    def unlock(self, password: str):
        try:
            blob = json.load(open(self.path))
            if blob.get("magic") != MAGIC:
                raise ValueError
            hdr = blob["kdf"]
            salt = base64.b64decode(hdr["salt"])
            self.n, self.r, self.p = hdr["n"], hdr["r"], hdr["p"]
            nonce, ct = base64.b64decode(blob["nonce"]), base64.b64decode(blob["ct"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            raise TamperedVault("vault file is missing, unreadable or not a MobileVault file")
        key = _kdf(password, salt, self.n, self.r, self.p)
        try:
            plain = AESGCM(key).decrypt(nonce, ct, self._aad(blob["kdf"]))
        except InvalidTag:
            # cannot distinguish a wrong password from tampering: both fail authentication
            raise WrongPassword("wrong master password, or the vault was modified")
        self._entries, self._key, self._salt = json.loads(plain)["entries"], key, salt
        self._touch()

    def lock(self):
        self._entries, self._key = None, None

    @property
    def locked(self) -> bool:
        if self._entries is not None and self.auto_lock and self.clock() - self._last > self.auto_lock:
            self.lock()
        return self._entries is None

    def _touch(self):
        self._last = self.clock()

    def _need(self):
        if self.locked:
            raise VaultError("vault is locked")
        self._touch()

    # -- persistence ---------------------------------------------------------
    @staticmethod
    def _aad(kdf: dict) -> bytes:
        return MAGIC.encode() + json.dumps(kdf, sort_keys=True).encode()   # KDF params are authenticated too

    def _save(self):
        kdf = {"alg": "scrypt", "salt": _b64(self._salt), "n": self.n, "r": self.r, "p": self.p}
        nonce = os.urandom(12)                                             # fresh nonce on every save
        ct = AESGCM(self._key).encrypt(nonce, json.dumps({"entries": self._entries}).encode(), self._aad(kdf))
        blob = {"magic": MAGIC, "kdf": kdf, "nonce": _b64(nonce), "ct": _b64(ct)}
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d)
        with os.fdopen(fd, "w") as fh:
            json.dump(blob, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)                                         # atomic: no half-written vault

    # -- entries -------------------------------------------------------------
    def add(self, name: str, username: str = "", password: str = "", url: str = "", notes: str = "",
            totp_secret: str = "") -> str:
        self._need()
        eid = uuid.uuid4().hex[:8]
        self._entries[eid] = {"name": name, "username": username, "password": password, "url": url,
                              "notes": notes, "totp_secret": totp_secret, "updated": int(time.time())}
        self._save()
        return eid

    def get(self, eid: str) -> dict:
        self._need()
        if eid not in self._entries:
            raise KeyError(eid)
        return dict(self._entries[eid])

    def update(self, eid: str, **fields):
        self._need()
        if eid not in self._entries:
            raise KeyError(eid)
        self._entries[eid].update(fields, updated=int(time.time()))
        self._save()

    def delete(self, eid: str):
        self._need()
        del self._entries[eid]
        self._save()

    def search(self, text: str) -> List[dict]:
        self._need()
        t = text.lower()
        return [{"id": k, **{f: v[f] for f in ("name", "username", "url")}} for k, v in self._entries.items()
                if t in v["name"].lower() or t in v["url"].lower() or t in v["username"].lower()]

    def audit(self) -> dict:
        """Reused and short passwords (nothing leaves the device)."""
        self._need()
        seen: Dict[str, List[str]] = {}
        for k, v in self._entries.items():
            if v["password"]:
                seen.setdefault(v["password"], []).append(v["name"])
        return {"reused": [names for names in seen.values() if len(names) > 1],
                "weak": [v["name"] for v in self._entries.values() if v["password"] and len(v["password"]) < 10]}

    def change_master_password(self, new_password: str):
        self._need()
        if len(new_password) < 8:
            raise VaultError("master password must be at least 8 characters")
        self._salt = os.urandom(16)
        self._key = _kdf(new_password, self._salt, self.n, self.r, self.p)
        self._save()
