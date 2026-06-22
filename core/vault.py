from __future__ import annotations

import json
import os
from pathlib import Path

from core.crypto import (
    derive_key_from_passphrase,
    encrypt_vault,
    decrypt_vault,
    generate_recovery_keypair,
    encrypt_master_key_with_recovery,
    decrypt_master_key_with_recovery,
    secure_zero,
    bytes_to_b64,
    b64_to_bytes,
)
from core.mnemonic import private_key_to_mnemonic, mnemonic_to_private_key
from core.vault_format import build_vaultkey_file, parse_vaultkey_file
from core.filelock import VaultLock, VaultLockError
from core.meta import write_meta, check_and_update_meta, load_fail_count, write_fail_count, clear_fail_count
from core.machine_bind import (
    get_machine_secret,
    compute_bind_tag,
    verify_bind_tag,
    secret_file_path,
    MachineMismatchError,
)

VAULT_VERSION = 4

_VAULT_AAD = b"key_lock:vault_blob:v2"

REKEY_CUSTODY_WARNING = (
    "\n⚠️  RECOMENDAÇÃO DE SEGURANÇA — CUSTÓDIA ALTERADA\n"
    "   Execute 'python cli.py rekey <arquivo.vault>' para rotacionar\n"
    "   as credenciais. Isso invalida criptograficamente todas as cópias\n"
    "   antigas do cofre em poder de ex-responsáveis.\n"
)

import time as _time

def create_vault(passphrase: str, vault_path: str, vaultkey_pin: str) -> tuple[str, str]:
    kdf_key, salt = derive_key_from_passphrase(passphrase)
    try:
        recovery_private, recovery_public = generate_recovery_keypair()

        kdf_key_blob = encrypt_master_key_with_recovery(kdf_key, recovery_public)

        now = int(_time.time())
        empty_vault = {"version": VAULT_VERSION, "last_saved": now, "entries": []}
        vault_blob = encrypt_vault(empty_vault, kdf_key, aad=_VAULT_AAD)

        vault_data = {
            "version":         VAULT_VERSION,
            "salt":            bytes_to_b64(salt),
            "master_key_blob": bytes_to_b64(kdf_key_blob),
            "vault_blob":      bytes_to_b64(vault_blob),
        }

        try:
            machine_secret = get_machine_secret()
            vault_data["machine_tag"] = compute_bind_tag(machine_secret, salt)
        except Exception:
            pass

        _atomic_write(vault_path, json.dumps(vault_data, indent=2))
        write_meta(vault_path, now)

        mnemonic_phrase = private_key_to_mnemonic(recovery_private)
        vaultkey_content = build_vaultkey_file(mnemonic_phrase, salt, vaultkey_pin)
        return mnemonic_phrase, vaultkey_content
    finally:
        secure_zero(kdf_key)

def open_vault_with_passphrase(
    passphrase: str, vault_path: str, *, force_accept_meta: bool = False
) -> tuple[dict, bytearray]:

    fails, last_fail_ts = load_fail_count(vault_path)
    if fails >= 3:
        wait = min(2 ** (fails - 2), 60)
        _time.sleep(wait)

    vault_data = _load_vault_file(vault_path)
    salt = b64_to_bytes(vault_data["salt"])

    stored_tag = vault_data.get("machine_tag")
    if stored_tag:
        try:
            machine_secret = get_machine_secret()
            if not verify_bind_tag(machine_secret, salt, stored_tag):
                raise MachineMismatchError(str(secret_file_path()))
        except MachineMismatchError:
            raise
        except Exception:
            pass

    kdf_key, _ = derive_key_from_passphrase(passphrase, salt)

    outer_version = vault_data.get("version", 2)
    aad = _VAULT_AAD if outer_version >= 3 else None

    try:
        contents = decrypt_vault(b64_to_bytes(vault_data["vault_blob"]), kdf_key, aad=aad)

        clear_fail_count(vault_path)
    except Exception:

        write_fail_count(vault_path, fails + 1)
        secure_zero(kdf_key)
        raise ValueError("Passphrase incorreta ou cofre corrompido.")

    try:
        check_and_update_meta(vault_path, contents, force_accept=force_accept_meta)
    except ValueError:
        secure_zero(kdf_key)
        raise
    return contents, kdf_key

def open_vault_with_recovery_file(
    vaultkey_path: str, vault_path: str, pin: str, *, force_accept_meta: bool = False
) -> tuple[dict, bytearray]:

    MAX_VAULTKEY_SIZE = 4096
    path = Path(vaultkey_path)
    if path.stat().st_size > MAX_VAULTKEY_SIZE:
        raise ValueError(
            f"Arquivo .vaultkey excede o tamanho máximo esperado ({MAX_VAULTKEY_SIZE} bytes). "
            "Arquivo possivelmente corrompido ou malicioso."
        )
    file_content = path.read_text().strip()
    mnemonic_phrase, _ = parse_vaultkey_file(file_content, pin)
    return _open_with_mnemonic(mnemonic_phrase, vault_path, force_accept_meta=force_accept_meta)

def open_vault_with_mnemonic(
    mnemonic_phrase: str, vault_path: str, *, force_accept_meta: bool = False
) -> tuple[dict, bytearray]:
    return _open_with_mnemonic(mnemonic_phrase.strip(), vault_path, force_accept_meta=force_accept_meta)

def _open_with_mnemonic(
    mnemonic_phrase: str, vault_path: str, *, force_accept_meta: bool = False
) -> tuple[dict, bytearray]:
    recovery_private = mnemonic_to_private_key(mnemonic_phrase)
    vault_data = _load_vault_file(vault_path)
    master_key_blob = b64_to_bytes(vault_data["master_key_blob"])
    outer_version = vault_data.get("version", 2)
    aad = _VAULT_AAD if outer_version >= 3 else None

    recovery_use_aad = (outer_version >= 4)

    kdf_key = None
    try:
        kdf_key = decrypt_master_key_with_recovery(
            master_key_blob, recovery_private, use_aad=recovery_use_aad
        )
        contents = decrypt_vault(b64_to_bytes(vault_data["vault_blob"]), kdf_key, aad=aad)
    except Exception:
        if kdf_key is not None:
            secure_zero(kdf_key)
        raise ValueError("Chave de recuperação inválida ou cofre corrompido.")
    try:
        check_and_update_meta(vault_path, contents, force_accept=force_accept_meta)
    except ValueError:
        secure_zero(kdf_key)
        raise
    return contents, kdf_key

def save_vault(
    vault_contents: dict,
    passphrase: str,
    vault_path: str,
    warn_rekey: bool = False,
) -> None:
    with VaultLock(vault_path):
        vault_data = _load_vault_file(vault_path)
        salt = b64_to_bytes(vault_data["salt"])
        kdf_key, _ = derive_key_from_passphrase(passphrase, salt)
        try:
            now = int(_time.time())
            vault_contents["last_saved"] = now
            vault_blob = encrypt_vault(vault_contents, kdf_key, aad=_VAULT_AAD)
            vault_data["vault_blob"] = bytes_to_b64(vault_blob)
            vault_data["version"] = VAULT_VERSION
            _atomic_write(vault_path, json.dumps(vault_data, indent=2))
            write_meta(vault_path, now)
        finally:
            secure_zero(kdf_key)

    if warn_rekey:
        print(REKEY_CUSTODY_WARNING)

def save_vault_with_key(
    vault_contents: dict,
    kdf_key: bytearray,
    vault_path: str,
    warn_rekey: bool = False,
) -> None:
    with VaultLock(vault_path):
        vault_data = _load_vault_file(vault_path)
        try:
            now = int(_time.time())
            vault_contents["last_saved"] = now
            vault_blob = encrypt_vault(vault_contents, kdf_key, aad=_VAULT_AAD)
            vault_data["vault_blob"] = bytes_to_b64(vault_blob)
            vault_data["version"] = VAULT_VERSION
            _atomic_write(vault_path, json.dumps(vault_data, indent=2))
            write_meta(vault_path, now)
        except Exception:
            raise

    if warn_rekey:
        print(REKEY_CUSTODY_WARNING)

def rotate_master_key(
    old_passphrase: str | None,
    new_passphrase: str,
    vault_path: str,
    vaultkey_pin: str,
    contents: dict | None = None,
) -> tuple[str, str]:
    with VaultLock(vault_path):
        vault_data = _load_vault_file(vault_path)

        if contents is None:
            old_salt = b64_to_bytes(vault_data["salt"])
            old_version = vault_data.get("version", 2)
            old_aad = _VAULT_AAD if old_version >= 3 else None
            old_kdf_key, _ = derive_key_from_passphrase(old_passphrase, old_salt)
            try:
                contents = decrypt_vault(b64_to_bytes(vault_data["vault_blob"]), old_kdf_key, aad=old_aad)
            except Exception:
                raise ValueError("Passphrase antiga incorreta ou cofre corrompido.")
            finally:
                secure_zero(old_kdf_key)

        new_kdf_key, new_salt = derive_key_from_passphrase(new_passphrase)
        new_recovery_private, new_recovery_public = generate_recovery_keypair()
        try:

            new_kdf_key_blob = encrypt_master_key_with_recovery(
                new_kdf_key, new_recovery_public
            )
            now = int(_time.time())
            contents["last_saved"] = now
            new_vault_blob = encrypt_vault(contents, new_kdf_key, aad=_VAULT_AAD)

            new_vault_data = {
                "version":         VAULT_VERSION,
                "salt":            bytes_to_b64(new_salt),
                "master_key_blob": bytes_to_b64(new_kdf_key_blob),
                "vault_blob":      bytes_to_b64(new_vault_blob),
            }

            try:
                machine_secret = get_machine_secret()
                new_vault_data["machine_tag"] = compute_bind_tag(machine_secret, new_salt)
            except Exception:
                pass

            _atomic_write(vault_path, json.dumps(new_vault_data, indent=2))
            write_meta(vault_path, now)

            new_mnemonic = private_key_to_mnemonic(new_recovery_private)
            new_vaultkey_content = build_vaultkey_file(new_mnemonic, new_salt, vaultkey_pin)
            return new_mnemonic, new_vaultkey_content
        finally:
            secure_zero(new_kdf_key)

def rebind_vault(passphrase: str, vault_path: str) -> None:
    vault_data = _load_vault_file(vault_path)
    salt = b64_to_bytes(vault_data["salt"])

    kdf_key, _ = derive_key_from_passphrase(passphrase, salt)
    outer_version = vault_data.get("version", 2)
    aad = _VAULT_AAD if outer_version >= 3 else None
    try:
        decrypt_vault(b64_to_bytes(vault_data["vault_blob"]), kdf_key, aad=aad)
    except Exception:
        raise ValueError("Passphrase incorreta ou cofre corrompido.")
    finally:
        secure_zero(kdf_key)

    machine_secret = get_machine_secret()
    vault_data["machine_tag"] = compute_bind_tag(machine_secret, salt)
    _atomic_write(vault_path, json.dumps(vault_data, indent=2))

def add_entry(vault_contents: dict, name: str, username: str,
              password: str, url: str = "") -> dict:
    if not name.strip():
        raise ValueError("O nome da entrada não pode ser vazio.")

    if not password:
        raise ValueError("A senha da entrada não pode ser vazia.")
    if len(name) > 200 or len(username) > 200 or len(url) > 2048:
        raise ValueError("Campo excede o comprimento máximo permitido.")
    if url and not (url.startswith("https://") or url.startswith("http://")):
        url = ""
    entry = {
        "id":       _generate_id(),
        "name":     name.strip(),
        "username": username,
        "password": password,
        "url":      url,
    }
    vault_contents["entries"].append(entry)
    return vault_contents

def delete_entry(vault_contents: dict, entry_id: str) -> dict:
    vault_contents["entries"] = [
        e for e in vault_contents["entries"] if e["id"] != entry_id
    ]
    return vault_contents

def _atomic_write(path: str, content: str) -> None:
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise

def _meta_path(vault_path: str) -> Path:
    from core.meta import _meta_path as _mp
    return _mp(vault_path)

def _write_meta(vault_path: str, timestamp: int) -> None:
    write_meta(vault_path, timestamp)

def _load_vault_file(vault_path: str) -> dict:

    MAX_VAULT_SIZE = 50 * 1024 * 1024
    path = Path(vault_path)
    if not path.exists():
        raise FileNotFoundError(f"Cofre não encontrado: {vault_path}")
    if path.stat().st_size > MAX_VAULT_SIZE:
        raise ValueError(
            "Arquivo .vault excede o tamanho máximo (50 MB). "
            "Arquivo possivelmente corrompido ou malicioso."
        )
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Arquivo .vault corrompido ou em formato inválido: {e}"
        ) from e

def _generate_id() -> str:
    import uuid
    return str(uuid.uuid4())
