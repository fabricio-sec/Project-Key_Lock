import hashlib
import hmac as _hmac
import json
import os
import time
import warnings
from pathlib import Path

from core.machine_bind import get_machine_secret as _get_machine_secret

_META_DIR      = Path.home() / ".key_lock_meta"
_META_VERSION  = 2

_LEGACY_MACHINE_SECRET_FILE = _META_DIR / ".machine_secret"

def _get_or_create_machine_secret() -> bytes:
    return _get_machine_secret()

def _compute_hmac(payload: dict, secret: bytes) -> str:
    data_to_sign = {k: v for k, v in payload.items() if k != "hmac"}
    canonical = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":"))
    mac = _hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()

def _verify_hmac(payload: dict, secret: bytes) -> bool:
    expected_hmac = payload.get("hmac")
    if not expected_hmac:
        return False
    computed = _compute_hmac(payload, secret)
    return _hmac.compare_digest(computed, expected_hmac)

def _meta_path(vault_path: str) -> Path:

    resolved = str(Path(vault_path).resolve())
    digest   = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]
    stem     = Path(vault_path).stem
    return _META_DIR / f"{stem}_{digest}.json"

def write_meta(vault_path: str, timestamp: int) -> None:
    _META_DIR.mkdir(parents=True, exist_ok=True)
    secret = _get_or_create_machine_secret()

    payload = {
        "version":       _META_VERSION,
        "min_timestamp": timestamp,
        "vault":         str(Path(vault_path).resolve()),
        "updated_at":    int(time.time()),
    }
    payload["hmac"] = _compute_hmac(payload, secret)

    mp  = _meta_path(vault_path)
    tmp = str(mp) + ".tmp"
    try:
        content = json.dumps(payload, indent=2)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, str(mp))
    except Exception as e:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        warnings.warn(f"key_lock: não foi possível escrever metadata anti-rollback: {e}", stacklevel=2)

def check_and_update_meta(vault_path: str, contents: dict, *, force_accept: bool = False) -> None:
    vault_ts = contents.get("last_saved", 0)
    mp = _meta_path(vault_path)

    if not mp.exists():
        write_meta(vault_path, vault_ts)
        return

    secret = _get_or_create_machine_secret()
    try:
        stored = json.loads(mp.read_text())
        hmac_ok = _verify_hmac(stored, secret)
    except Exception:
        stored, hmac_ok = None, False

    if not hmac_ok:
        if not force_accept:
            raise ValueError(
                f"⚠️  AVISO DE SEGURANÇA: O metadata anti-rollback está corrompido ou "
                f"adulterado e não pôde ser verificado.\n"
                f"   Arquivo: {mp}\n"
                f"   Isso pode indicar adulteração ou tentativa de ataque de rollback.\n"
                f"   Não é seguro continuar automaticamente. Se você tem certeza de que "
                f"este cofre é legítimo (ex.: corrupção por crash de disco), use a opção "
                f"explícita de aceitar metadata não verificado para este cofre."
            )
        _warn_tampered(mp)
        write_meta(vault_path, vault_ts)
        return

    min_ts = stored.get("min_timestamp", 0)

    if vault_ts < min_ts:
        raise ValueError(
            f"⚠️  AVISO DE SEGURANÇA: O arquivo de cofre parece ser uma versão antiga.\n"
            f"   Timestamp no vault:    {vault_ts}  ({_fmt_ts(vault_ts)})\n"
            f"   Timestamp esperado: ≥ {min_ts}  ({_fmt_ts(min_ts)})\n"
            f"   Isso pode indicar substituição por backup antigo (ataque de rollback).\n"
            f"   Verifique a integridade do arquivo antes de continuar.\n"
            f"   Para aceitar este vault, delete: {mp}"
        )

    if vault_ts > min_ts:
        write_meta(vault_path, vault_ts)

def reset_meta(vault_path: str) -> None:
    mp = _meta_path(vault_path)
    try:
        mp.unlink(missing_ok=True)
    except Exception:
        pass

def get_meta_status(vault_path: str) -> dict:
    mp = _meta_path(vault_path)
    if not mp.exists():
        return {"status": "missing", "path": str(mp)}

    try:
        stored = json.loads(mp.read_text())
        secret = _get_or_create_machine_secret()
        hmac_valid = _verify_hmac(stored, secret)
        return {
            "status":        "valid" if hmac_valid else "tampered",
            "path":          str(mp),
            "min_timestamp": stored.get("min_timestamp", 0),
            "updated_at":    stored.get("updated_at", 0),
            "hmac_valid":    hmac_valid,
        }
    except Exception as e:
        return {"status": "error", "path": str(mp), "error": str(e)}

def _fail_count_path(vault_path: str) -> Path:
    import hashlib as _hl
    resolved = str(Path(vault_path).resolve())
    digest = _hl.sha256(resolved.encode("utf-8")).hexdigest()[:16]
    stem = Path(vault_path).stem
    return _META_DIR / f"{stem}_{digest}_fail.json"

def load_fail_count(vault_path: str) -> tuple[int, float]:
    fp = _fail_count_path(vault_path)
    try:
        data = json.loads(fp.read_text())
        return int(data.get("count", 0)), float(data.get("last_fail", 0.0))
    except Exception:
        return 0, 0.0

def write_fail_count(vault_path: str, count: int) -> None:
    _META_DIR.mkdir(parents=True, exist_ok=True)
    fp = _fail_count_path(vault_path)
    data = {"count": count, "last_fail": time.time()}
    tmp = str(fp) + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data))
        os.replace(tmp, str(fp))
    except Exception as e:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        warnings.warn(f"key_lock: não foi possível persistir fail_count: {e}", stacklevel=2)

def clear_fail_count(vault_path: str) -> None:
    fp = _fail_count_path(vault_path)
    try:
        fp.unlink(missing_ok=True)
    except Exception:
        pass

def _fmt_ts(ts: int) -> str:
    import datetime
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def _warn_tampered(meta_path: Path) -> None:
    warnings.warn(
        f"key_lock: AVISO — arquivo de metadata anti-rollback pode ter sido adulterado: {meta_path}\n"
        f"  O metadata foi recriado com o timestamp atual. Verifique a integridade do cofre.",
        stacklevel=3,
    )
