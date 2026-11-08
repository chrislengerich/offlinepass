#!/usr/bin/env python3
"""Generates fixed test vectors for the linuxpass device-wrap protocol
(Plan 2 rev 2, docs/extension-protocol.md) so the Android (JCE) and
extension (WebCrypto) implementations can be cross-checked against each
other.

Rev 2 wire format — wrap-once, target-many:
  payload : AES-256-GCM(cek, iv_p, aad="offlinepass-paste-wrap-v1", protonJson)
  per target: AES-256-GCM(HKDF(ECDH(eph, target.pub)), iv_t, aad_t, cek)
  keyId   = hex(SHA-256(rawCredentialId)[0..8])   (stable identity, R1)

Run:  python3 scripts/gen_device_wrap_vectors.py
"""
import hashlib
import hmac
import json
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat)

# --- fixed inputs ----------------------------------------------------------
PRF_OUT = bytes(range(32))                                  # fake PRF output
CRED_ID = bytes(range(32, 64))                              # fake credentialId #1
CRED_ID2 = bytes(range(64, 96))                             # fake credentialId #2
SEED_IV = bytes.fromhex("000102030405060708090a0b")         # seed-wrap iv
PAYLOAD_IV = bytes.fromhex("0102030405060708090a0b0c")      # CEK payload iv
T1_IV = bytes.fromhex("000102030405060708090a0b")           # target-1 wrap iv
T2_IV = bytes.fromhex("101112131415161718191a1b")           # target-2 wrap iv
SEED_SCALAR = int.from_bytes(hashlib.sha256(b"device-seed").digest(), "big") % ec.SECP256R1().group_order
SEED2_SCALAR = int.from_bytes(hashlib.sha256(b"device-seed-2").digest(), "big") % ec.SECP256R1().group_order
EPH1_SCALAR = int.from_bytes(hashlib.sha256(b"ephemeral").digest(), "big") % ec.SECP256R1().group_order
EPH2_SCALAR = int.from_bytes(hashlib.sha256(b"ephemeral-2").digest(), "big") % ec.SECP256R1().group_order
CEK = bytes(range(96, 128))                                 # the random paste CEK
PAYLOAD = json.dumps({
    "itemId": "vec-item-0000", "shareId": "local",
    "data": {"type": "login",
             "metadata": {"name": "Vector Test", "itemUuid": "vec-item-0000"},
             "content": {"itemEmail": "", "itemUsername": "vector",
                         "password": "s3cret-vector", "urls": ["https://example.test"],
                         "totpUri": "", "passkeys": []}},
    "state": 1}, separators=(",", ":"))

# --- HKDF (RFC 5869) on stdlib primitives — vector generation only ---------
def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:length]

def b64(b): return base64.b64encode(b).decode()

PASTE_INFO = b"offlinepass-paste-wrap-v1"

def make_target(cred_id, seed_scalar, eph_scalar, iv):
    """Build one target's wrapped-CEK blob."""
    seed_priv = ec.derive_private_key(seed_scalar, ec.SECP256R1())
    seed_pub_raw = seed_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    key_id = hashlib.sha256(cred_id).digest()[:8].hex()
    eph_priv = ec.derive_private_key(eph_scalar, ec.SECP256R1())
    eph_pub_raw = eph_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    shared_x = eph_priv.exchange(ec.ECDH(), seed_priv.public_key())
    kek = hkdf(shared_x, bytes.fromhex(key_id), PASTE_INFO)
    aad = f"offlinepass-paste-wrap-v1:{key_id}:{b64(eph_pub_raw)}".encode()
    ct = AESGCM(kek).encrypt(iv, CEK, aad)
    salt_raw = hashlib.sha256(b"offlinepass-device-v1" + cred_id).digest()
    return {
        "keyId": key_id, "seedPubRaw": seed_pub_raw, "seedScalar": seed_scalar,
        "ephScalar": eph_scalar,
        "ephPubRaw": eph_pub_raw, "sharedX": shared_x, "kek": kek,
        "iv": iv, "ct": ct, "aad": aad.decode(), "saltRaw": salt_raw,
        "record": {"id": key_id, "name": f"vector-key-{key_id[:4]}",
                   "credId": b64(cred_id), "pub": b64(seed_pub_raw),
                   "keyId": key_id, "added": 1762500000,
                   "salt": b64(salt_raw),
                   "wrapped": {"iv": b64(SEED_IV), "ct": None}},  # filled by caller
    }

def make_seed_blob(seed_scalar, iv):
    priv = ec.derive_private_key(seed_scalar, ec.SECP256R1())
    pkcs8 = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    salt = None  # per-credential; filled by caller
    return pkcs8

t1 = make_target(CRED_ID, SEED_SCALAR, EPH1_SCALAR, T1_IV)
t2 = make_target(CRED_ID2, SEED2_SCALAR, EPH2_SCALAR, T2_IV)

# Seed-wrap blobs (enrollment side): KEK from PRF, pkcs8 AES-GCM'd.
t1_kek_seed = hkdf(PRF_OUT, t1["saltRaw"], b"offlinepass-seed-kek-v1")
seed_pkcs8 = ec.derive_private_key(SEED_SCALAR, ec.SECP256R1()).private_bytes(
    Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
seed_ct = AESGCM(t1_kek_seed).encrypt(SEED_IV, seed_pkcs8, b"offlinepass-seed-wrap-v1")
t1["record"]["wrapped"]["ct"] = b64(seed_ct)

# Payload layer.
payload_ct = AESGCM(CEK).encrypt(PAYLOAD_IV, PAYLOAD.encode(), PASTE_INFO)

# Full wrapped paste, two targets.
wrapped = {
    "v": 1, "type": "offlinepass-wrap",
    "payload": {"iv": b64(PAYLOAD_IV), "ct": b64(payload_ct)},
    "targets": [
        {"keyId": t["keyId"], "epk": b64(t["ephPubRaw"]),
         "iv": b64(t["iv"]), "ct": b64(t["ct"])} for t in (t1, t2)],
}
wrapped_json = json.dumps(wrapped, separators=(",", ":"))
record_json = json.dumps({"type": "offlinepass-device", "device": t1["record"]}, separators=(",", ":"))

def block(title, obj):
    print(f"--- {title} ---")
    print(json.dumps(obj, indent=2) if not isinstance(obj, str) else obj)
    print()

print("# Auto-generated by scripts/gen_device_wrap_vectors.py — do not edit by hand.")
for name, t in (("target-1", t1), ("target-2", t2)):
    block(f"{name} inputs", {
        "credId": t["record"]["credId"], "keyId": t["keyId"],
        "seedPubRaw": t["seedPubRaw"].hex(), "seedPrivScalar": hex(t["seedScalar"]),
        "ephScalar": hex(t["ephScalar"]), "ephPubRaw": t["ephPubRaw"].hex(),
        "sharedX": t["sharedX"].hex(), "kek": t["kek"].hex(),
        "wrapIv": t["iv"].hex(), "aad": t["aad"],
        "salt": t["record"]["salt"], "kekSeed": t1_kek_seed.hex() if name == "target-1" else "(n/a)",
    })
block("seed wrap (enrollment, target-1)", {
    "prfOut": PRF_OUT.hex(), "kek": t1_kek_seed.hex(), "iv": SEED_IV.hex(),
    "aad": "offlinepass-seed-wrap-v1",
    "seedPkcs8Sha256": hashlib.sha256(seed_pkcs8).hexdigest(), "ct": b64(seed_ct)})
block("payload layer", {"cek": CEK.hex(), "iv": PAYLOAD_IV.hex(),
                        "aad": PASTE_INFO.decode(), "ct": b64(payload_ct)})
block("device record (QRFT payload the pair page emits)", record_json)
block("wrapped paste, 2 targets (QRFT payload the export flow emits)", wrapped_json)
print("--- expected decrypt (Android + extension must both produce) ---")
print(PAYLOAD)
