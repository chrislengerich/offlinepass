"""Proton Pass item model, GPG-encrypted storage, git sync, password/TOTP generation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import struct
import subprocess
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class ProtonItem:
    name: str = ""
    username: str = ""
    email: str = ""
    password: str = ""
    urls: list[str] = field(default_factory=list)
    note: str = ""
    totp_uri: str = ""
    item_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    item_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def display_name(self) -> str:
        """Best available display label: name, URL domain, or identity."""
        if self.name:
            return self.name
        if self.urls:
            parsed = urllib.parse.urlparse(self.urls[0])
            host = parsed.hostname or parsed.path.lstrip("/")
            if host:
                return host
        return self.username or self.email or "(unnamed)"

    def to_proton_json(self) -> dict[str, Any]:
        return {
            "itemId": self.item_id,
            "shareId": "local",
            "data": {
                "type": "login",
                "metadata": {
                    "name": self.name,
                    "note": self.note,
                    "itemUuid": self.item_uuid,
                },
                "content": {
                    "itemEmail": self.email,
                    "itemUsername": self.username,
                    "password": self.password,
                    "urls": self.urls,
                    "autofillUrls": [{"url": u, "mode": 0} for u in self.urls],
                    "totpUri": self.totp_uri,
                    "passkeys": [],
                },
                "extraFields": [],
                "platformSpecific": {},
            },
            "state": 1,
            "aliasEmail": None,
            "contentFormatVersion": 1,
            "createTime": 0,
            "modifyTime": 0,
            "pinned": False,
            "shareCount": 0,
            "files": [],
        }

    @classmethod
    def from_proton_json(cls, obj: dict[str, Any]) -> "ProtonItem":
        data = obj.get("data", obj)
        metadata = data.get("metadata", {})
        content = data.get("content", {})
        return cls(
            name=metadata.get("name", ""),
            username=content.get("itemUsername", ""),
            email=content.get("itemEmail", ""),
            password=content.get("password", ""),
            urls=content.get("urls", []),
            note=metadata.get("note", ""),
            totp_uri=content.get("totpUri", ""),
            item_uuid=metadata.get("itemUuid", str(uuid.uuid4())),
            item_id=obj.get("itemId", str(uuid.uuid4())),
        )

    @property
    def identity(self) -> str:
        return self.username or self.email

    def matches(self, query: str) -> bool:
        q = query.lower()
        haystack = " ".join([
            self.name, self.username, self.email,
            " ".join(self.urls), self.note,
        ]).lower()
        return all(word in haystack for word in q.split())


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


def generate_password(length: int = 24) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def generate_alias() -> str:
    """Generate a SimpleLogin-style alias (stub)."""
    adjectives = ["quick", "lazy", "happy", "silent", "bright", "calm", "eager"]
    nouns = ["fox", "river", "stone", "leaf", "wind", "star", "wave"]
    num = secrets.randbelow(1000)
    return f"{secrets.choice(adjectives)}.{secrets.choice(nouns)}{num}@aleeas.com"


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------

def _base32_decode(secret: str) -> bytes:
    """Decode a base32 string, stripping spaces and fixing padding."""
    clean = secret.replace(" ", "").replace("-", "").upper()
    padding = (8 - len(clean) % 8) % 8
    return base64.b32decode(clean + "=" * padding)


def parse_totp_uri(uri: str) -> tuple[str, str, int, int]:
    """Parse an otpauth:// URI. Returns (secret, issuer, digits, period)."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError(f"Not an otpauth URI: {uri}")
    params = urllib.parse.parse_qs(parsed.query)
    secret = params.get("secret", [""])[0]
    if not secret:
        raise ValueError("No secret in TOTP URI")
    issuer = params.get("issuer", [""])[0]
    digits = int(params.get("digits", ["6"])[0])
    period = int(params.get("period", ["30"])[0])
    return secret, issuer, digits, period


def totp_secret_from_input(user_input: str) -> str:
    """Accept either a raw base32 secret or an otpauth:// URI.
    Returns a normalized otpauth:// URI."""
    user_input = user_input.strip()
    if user_input.startswith("otpauth://"):
        return user_input
    # Raw secret — wrap in a minimal otpauth URI
    secret = user_input.replace(" ", "").replace("-", "").upper()
    return f"otpauth://totp/linuxpass?secret={secret}&issuer=linuxpass"


def generate_totp(uri: str, at_time: int | None = None) -> tuple[str, int]:
    """Generate a TOTP code from an otpauth:// URI.
    Returns (code, seconds_remaining_in_period)."""
    secret_b32, _issuer, digits, period = parse_totp_uri(uri)
    key = _base32_decode(secret_b32)
    now = at_time if at_time is not None else int(time.time())
    counter = now // period
    remaining = period - (now % period)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    code = str(code_int)[-digits:].zfill(digits)
    return code, remaining


# ---------------------------------------------------------------------------
# Storage — GPG-encrypted JSON file with git sync
# ---------------------------------------------------------------------------

class PasswordStore:
    def __init__(
        self,
        path: str,
        gpg_recipients: list[str] | None = None,
        use_gpg: bool = True,
        git_dir: str | None = None,
    ):
        self.path = path
        # One or more recipients; the vault is encrypted to all of them so
        # both the desktop and the phone can open it.
        self.gpg_recipients = gpg_recipients
        self.use_gpg = use_gpg
        self.git_dir = git_dir or os.path.dirname(os.path.abspath(path))
        # Envelope bookkeeping shared with the phone client: rev bumps per
        # save, tombstones survive merges, unknown top-level fields pass
        # through untouched.
        self._envelope: dict | None = None
        self._deleted: set[str] = set()
        self._device_id = self._load_device_id()

    def _load_device_id(self) -> str:
        # Stable per clone; untracked marker next to the vault repo.
        marker = os.path.join(self.git_dir, ".linuxpass-device")
        try:
            if os.path.exists(marker):
                with open(marker) as f:
                    did = f.read().strip()
                if did:
                    return did
            did = str(uuid.uuid4())
            with open(marker, "w") as f:
                f.write(did)
            return did
        except OSError:
            return str(uuid.uuid4())

    def load(self) -> list[ProtonItem]:
        if not os.path.exists(self.path):
            return []
        raw = self._read_file()
        self._envelope = json.loads(raw) if raw.lstrip().startswith("{") else None
        if isinstance(self._envelope, dict):
            self._deleted = set(self._envelope.get("deletedItemUuids", []))
        return self._parse_items(raw)

    def save(self, items: list[ProtonItem]) -> None:
        envelope = self._build_envelope(items)
        text = json.dumps(envelope, separators=(",", ":"))
        self._write_file(text)
        # Keep the written envelope so consecutive saves keep bumping rev
        # (a reload would also see it, but saves may come back-to-back).
        self._envelope = envelope
        self._git_commit()
        self.git_push(timeout=45)

    def _read_file(self) -> str:
        if self.use_gpg:
            result = subprocess.run(
                ["gpg", "--decrypt", "--quiet", "--batch", self.path],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"GPG decrypt failed: {result.stderr.strip()}")
            return result.stdout
        with open(self.path, "r") as f:
            return f.read()

    def _write_file(self, text: str) -> None:
        if self.use_gpg and self.gpg_recipients:
            cmd = ["gpg", "--encrypt", "--batch", "--yes", "--output", self.path]
            for recipient in self.gpg_recipients:
                cmd += ["--recipient", recipient]
            result = subprocess.run(cmd, input=text, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"GPG encrypt failed: {result.stderr.strip()}")
        else:
            with open(self.path, "w") as f:
                f.write(text)

    def _parse_items(self, raw: str) -> list[ProtonItem]:
        data = json.loads(raw)
        items: list[ProtonItem] = []
        if isinstance(data, list):
            for obj in data:
                items.append(ProtonItem.from_proton_json(obj))
        elif isinstance(data, dict) and "vaults" in data:
            for vault in data["vaults"].values():
                for obj in vault.get("items", []):
                    items.append(ProtonItem.from_proton_json(obj))
        elif isinstance(data, dict) and "data" in data:
            items.append(ProtonItem.from_proton_json(data))
        items.sort(key=lambda i: i.display_name.lower())
        return items

    def _build_envelope(self, items: list[ProtonItem]) -> dict[str, Any]:
        # Preserve everything the envelope already carried (rev, deviceId,
        # tombstones, unknown fields); only the items array and rev are ours.
        env = dict(self._envelope) if isinstance(self._envelope, dict) else {}
        env.setdefault("userId", "local")
        env.setdefault("version", "1.0")
        vaults = env.get("vaults")
        if not isinstance(vaults, dict) or "local" not in vaults:
            vaults = {"local": {"name": "Personal", "description": "",
                                "display": {"color": 0, "icon": 0}}}
            env["vaults"] = vaults
        vaults["local"]["items"] = [item.to_proton_json() for item in items]
        env["rev"] = int(env.get("rev", 0)) + 1
        env["deviceId"] = self._device_id
        env["deletedItemUuids"] = sorted(self._deleted)
        return env

    def _git_commit(self) -> None:
        if not os.path.isdir(os.path.join(self.git_dir, ".git")):
            return
        filename = os.path.basename(self.path)
        subprocess.run(["git", "-C", self.git_dir, "add", filename],
                       capture_output=True)
        subprocess.run(
            ["git", "-C", self.git_dir, "commit", "-m", f"Update {filename}"],
            capture_output=True,
        )

    def git_pull(self) -> bool:
        if not os.path.isdir(os.path.join(self.git_dir, ".git")):
            return False
        result = subprocess.run(
            ["git", "-C", self.git_dir, "pull", "--ff-only"],
            capture_output=True, text=True,
        )
        return result.returncode == 0 and "Already up to date" not in result.stdout

    def git_push(self, timeout: int = 45) -> bool:
        """Best-effort push of the current branch. Non-fatal: a failed push
        (offline, pending key touch, no upstream) leaves the local commit
        in place for the next attempt."""
        if not os.path.isdir(os.path.join(self.git_dir, ".git")):
            return False
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        try:
            result = subprocess.run(
                ["git", "-C", self.git_dir, "push", "origin", "HEAD"],
                capture_output=True, text=True, timeout=timeout, env=env,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"git push skipped: {e}")
            return False
