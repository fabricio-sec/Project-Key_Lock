import json
import os
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULTKEY_ARGON2_TIME   = 4
VAULTKEY_ARGON2_MEM    = 262144
VAULTKEY_ARGON2_PAR    = 4
VAULTKEY_ARGON2_LEN    = 32
VAULTKEY_SALT_LEN      = 16
AES_NONCE_LEN          = 12
VAULTKEY_VERSION       = 3

MIN_PIN_LENGTH = 8

_VAULTKEY_AAD = b"key_lock:vaultkey_blob:v2"

def _derive_pin_key(pin: str, salt: bytes) -> bytearray:
    raw = hash_secret_raw(
        secret=pin.encode("utf-8"),
        salt=salt,
        time_cost=VAULTKEY_ARGON2_TIME,
        memory_cost=VAULTKEY_ARGON2_MEM,
        parallelism=VAULTKEY_ARGON2_PAR,
        hash_len=VAULTKEY_ARGON2_LEN,
        type=Type.ID,
    )
    return bytearray(raw)

def build_vaultkey_file(mnemonic_phrase: str, vault_salt: bytes, pin: str) -> str:
    vaultkey_salt = os.urandom(VAULTKEY_SALT_LEN)
    pin_key = _derive_pin_key(pin, vaultkey_salt)
    try:
        nonce = os.urandom(AES_NONCE_LEN)
        aesgcm = AESGCM(pin_key)
        ciphertext = aesgcm.encrypt(nonce, mnemonic_phrase.encode("utf-8"), _VAULTKEY_AAD)
        encrypted_mnemonic = nonce + ciphertext
    finally:
        for i in range(len(pin_key)):
            pin_key[i] = 0

    payload = {
        "version": VAULTKEY_VERSION,
        "vaultkey_salt": base64.urlsafe_b64encode(vaultkey_salt).decode(),
        "encrypted_mnemonic": base64.urlsafe_b64encode(encrypted_mnemonic).decode(),
        "vault_salt": base64.urlsafe_b64encode(vault_salt).decode(),
    }

    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")

def parse_vaultkey_file(file_content: str, pin: str) -> tuple[str, bytes]:
    try:
        raw = base64.urlsafe_b64decode(file_content.strip().encode("utf-8"))
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ValueError("Arquivo .vaultkey inválido ou corrompido.")

    version = payload.get("version", 1)
    if version == 1:
        raise ValueError(
            "Arquivo .vaultkey em formato legado (versão 1) não é suportado.\n"
            "Este arquivo foi criado por uma versão muito antiga do key_lock.\n"
            "Use o mnemônico de 24 palavras para recuperar o acesso e gere um novo .vaultkey."
        )
    if version not in (2, VAULTKEY_VERSION):

        raise ValueError("Versão do arquivo .vaultkey não é suportada por esta versão do key_lock.")

    try:
        vaultkey_salt = base64.urlsafe_b64decode(payload["vaultkey_salt"])
        encrypted_mnemonic = base64.urlsafe_b64decode(payload["encrypted_mnemonic"])
        vault_salt = base64.urlsafe_b64decode(payload["vault_salt"])
    except Exception:
        raise ValueError("Estrutura do arquivo .vaultkey inválida.")

    pin_key = _derive_pin_key(pin, vaultkey_salt)
    aad = _VAULTKEY_AAD if version == VAULTKEY_VERSION else None

    try:
        nonce = encrypted_mnemonic[:AES_NONCE_LEN]
        ciphertext = encrypted_mnemonic[AES_NONCE_LEN:]
        aesgcm = AESGCM(pin_key)
        mnemonic_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
        mnemonic_phrase = mnemonic_bytes.decode("utf-8")
    except Exception:
        raise ValueError("PIN incorreto ou arquivo .vaultkey corrompido.")
    finally:
        for i in range(len(pin_key)):
            pin_key[i] = 0

    return mnemonic_phrase, vault_salt

def is_secure_vaultkey(file_content: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(file_content.strip().encode("utf-8"))
        payload = json.loads(raw.decode("utf-8"))
        return payload.get("version") == VAULTKEY_VERSION
    except Exception:
        return False

def write_vaultkey_file(path: str, content: str) -> None:
    """Grava um arquivo .vaultkey (ou qualquer segredo equivalente) com
    permissão restrita ao dono (0600) desde a criação do arquivo.

    [N-03] Usar open(path, "w") comum cria o arquivo com a permissão padrão
    do umask do sistema (tipicamente 0644 em Linux/macOS — legível por
    outros usuários locais). Como o .vaultkey é o único artefato que,
    combinado com o PIN, recupera integralmente o cofre, ele deve ter a
    mesma proteção de permissão que o .vault e o machine_secret.key já têm.
    Esta função centraliza o padrão correto (os.open com O_CREAT|O_TRUNC e
    modo 0600) para ser reaproveitada por todo o código (CLI e GUI), em vez
    de duplicar a lógica em cada ponto de escrita.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        try:
            os.unlink(path)
        except Exception:
            pass
        raise
