"""Proton Pass item model, GPG-encrypted storage, git sync, password generation."""

from __future__ import annotations

import json
import os
import secrets
import string
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class ProtonItem:
    name: str
    username: str = ""
    email: str = ""
    password: str = ""
    urls: list[str] = field(default_factory=list)
    note: str = ""
    totp_uri: str = ""
    item_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    item_id: str = field(default_factory=lambda: str(uuid.uuid4()))

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
# Storage — GPG-encrypted JSON file with git sync
# ---------------------------------------------------------------------------

class PasswordStore:
    def __init__(
        self,
        path: str,
        gpg_recipient: str | None = None,
        use_gpg: bool = True,
        git_dir: str | None = None,
    ):
        self.path = path
        self.gpg_recipient = gpg_recipient
        self.use_gpg = use_gpg
        self.git_dir = git_dir or os.path.dirname(os.path.abspath(path))

    def load(self) -> list[ProtonItem]:
        if not os.path.exists(self.path):
            return []
        raw = self._read_file()
        return self._parse_items(raw)

    def save(self, items: list[ProtonItem]) -> None:
        envelope = self._build_envelope(items)
        text = json.dumps(envelope, separators=(",", ":"))
        self._write_file(text)
        self._git_commit()

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
        if self.use_gpg and self.gpg_recipient:
            result = subprocess.run(
                ["gpg", "--encrypt", "--recipient", self.gpg_recipient,
                 "--output", self.path, "--batch", "--yes"],
                input=text, capture_output=True, text=True,
            )
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
        items.sort(key=lambda i: i.name.lower())
        return items

    def _build_envelope(self, items: list[ProtonItem]) -> dict[str, Any]:
        return {
            "userId": "local",
            "version": "1.0",
            "vaults": {
                "local": {
                    "name": "Personal",
                    "description": "",
                    "display": {"color": 0, "icon": 0},
                    "items": [item.to_proton_json() for item in items],
                }
            },
        }

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
