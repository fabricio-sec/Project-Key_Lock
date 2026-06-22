import os
import base64
import json
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

ARGON2_TIME_COST    = 4
ARGON2_MEMORY_COST  = 262144
ARGON2_PARALLELISM  = 4
ARGON2_HASH_LEN     = 32
ARGON2_SALT_LEN     = 16
AES_NONCE_LEN       = 12
HKDF_SALT_LEN       = 16

HKDF_INFO_RECOVERY  = b"key_lock recovery key v2 x25519"

_RECOVERY_BLOB_AAD = b"key_lock:master_key_blob:v2"

def secure_zero(buf) -> None:
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0

def derive_key_from_passphrase(
    passphrase: "str | bytes",
    salt: "bytes | None" = None,
) -> "tuple[bytearray, bytes]":
    if salt is None:
        salt = os.urandom(ARGON2_SALT_LEN)

    secret = passphrase.encode("utf-8") if isinstance(passphrase, str) else bytes(passphrase)

    raw_key = hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )

    return bytearray(raw_key), salt

def encrypt_vault(data: dict, key: "bytes | bytearray", aad: "bytes | None" = None) -> bytes:
    nonce = os.urandom(AES_NONCE_LEN)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext

def decrypt_vault(blob: bytes, key: "bytes | bytearray", aad: "bytes | None" = None) -> dict:
    nonce = blob[:AES_NONCE_LEN]
    ciphertext = blob[AES_NONCE_LEN:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return json.loads(plaintext.decode("utf-8"))

def generate_recovery_keypair() -> "tuple[bytes, bytes]":
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes

def encrypt_master_key_with_recovery(
    master_key: "bytes | bytearray",
    recovery_public_raw: bytes,
) -> bytes:

    eph_private = X25519PrivateKey.generate()
    eph_public_bytes = eph_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    static_pub = X25519PublicKey.from_public_bytes(recovery_public_raw)
    shared_secret = bytearray(eph_private.exchange(static_pub))

    hkdf_salt = os.urandom(HKDF_SALT_LEN)
    aes_key = _hkdf_derive(shared_secret, hkdf_salt)
    secure_zero(shared_secret)

    nonce = os.urandom(AES_NONCE_LEN)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, master_key, _RECOVERY_BLOB_AAD)

    return eph_public_bytes + hkdf_salt + nonce + ciphertext

def decrypt_master_key_with_recovery(
    blob: bytes,
    recovery_private_raw: bytes,
    use_aad: bool = True,
) -> bytearray:
    EPH_PUB_LEN = 32
    eph_public_bytes = blob[:EPH_PUB_LEN]
    hkdf_salt        = blob[EPH_PUB_LEN : EPH_PUB_LEN + HKDF_SALT_LEN]
    nonce            = blob[EPH_PUB_LEN + HKDF_SALT_LEN :
                            EPH_PUB_LEN + HKDF_SALT_LEN + AES_NONCE_LEN]
    ciphertext       = blob[EPH_PUB_LEN + HKDF_SALT_LEN + AES_NONCE_LEN:]

    static_priv = X25519PrivateKey.from_private_bytes(recovery_private_raw)
    eph_pub = X25519PublicKey.from_public_bytes(eph_public_bytes)
    shared_secret = bytearray(static_priv.exchange(eph_pub))

    aes_key = _hkdf_derive(shared_secret, hkdf_salt)
    secure_zero(shared_secret)

    aesgcm = AESGCM(aes_key)
    aad = _RECOVERY_BLOB_AAD if use_aad else None
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return bytearray(plaintext)

def _hkdf_derive(ikm: "bytes | bytearray", salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO_RECOVERY,
    )
    return hkdf.derive(ikm)

from core.passphrase import estimate_passphrase_entropy, generate_password

def bytes_to_b64(data: "bytes | bytearray") -> str:
    return base64.urlsafe_b64encode(bytes(data)).decode("utf-8")

def b64_to_bytes(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))
