#!/usr/bin/env python3
"""Verifies the screenlock commit signature embedded in a vault commit.

Screenlock-enrolled commits carry an ECDSA signature over the exact commit
payload in a custom armor block (git's verify-commit can't parse non-PGP
blocks). This script reconstructs the signed payload the same way git
does for GPG signatures (strip the gpgsig block + one trailing newline)
and verifies the embedded signature against the published public key
(keys/keystore-signer.pub).

Usage:
  python3 scripts/verify-commit-sig.py <repo-dir> [<ref>]   # ref default HEAD
"""
import base64
import re
import subprocess
import sys

ARMOR_BEGIN = b"-----BEGIN OFFLINEPASS SIGNATURE-----"
ARMOR_END = b"-----END OFFLINEPASS SIGNATURE-----"


def commit_object(repo: str, ref: str) -> bytes:
    return subprocess.check_output(["git", "-C", repo, "cat-file", "commit", ref])


def signed_payload(commit: bytes) -> bytes:
    """The exact bytes that were signed: the commit object with the gpgsig
    header block removed and one trailing newline dropped."""
    lines = commit.split(b"\n")
    out, skipping = [], False
    for line in lines:
        if line.startswith(b"gpgsig "):
            skipping = True
            continue
        if skipping and line.startswith(b" "):
            continue
        skipping = False
        out.append(line)
    payload = b"\n".join(out)
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    return payload


def extract_signature(commit: bytes) -> bytes:
    i = commit.find(ARMOR_BEGIN)
    j = commit.find(ARMOR_END, i)
    if i < 0 or j < 0:
        raise SystemExit("no OFFLINEPASS signature block in this commit")
    block = commit[i:j]
    b64 = b"".join(
        line for line in block.split(b"\n")
        if line and not line.startswith(b"-----")
    )
    return base64.b64decode(b64)


def main() -> None:
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    ref = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
    commit = commit_object(repo, ref)
    payload = signed_payload(commit)
    signature = extract_signature(commit)

    pem = open(f"{repo}/keys/keystore-signer.pub", "rb").read()
    open("/tmp/verify-pub.pem", "wb").write(pem)
    open("/tmp/verify-sig.der", "wb").write(signature)
    open("/tmp/verify-payload.bin", "wb").write(payload)
    ok = subprocess.call(
        ["openssl", "dgst", "-sha256", "-verify", "/tmp/verify-pub.pem",
         "-signature", "/tmp/verify-sig.der", "/tmp/verify-payload.bin"],
        stdout=subprocess.DEVNULL) == 0
    print("screenlock commit signature: " + ("VALID" if ok else "INVALID"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
