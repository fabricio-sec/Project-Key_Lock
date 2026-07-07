import hashlib
import hmac
import os
import platform
import secrets
from pathlib import Path

_SECRET_SIZE = 32

def _secret_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "key_lock"

def secret_file_path() -> Path:
    return _secret_dir() / "machine_secret.key"

def get_machine_secret() -> bytes:
    path = secret_file_path()

    try:
        data = path.read_bytes()
        if len(data) == _SECRET_SIZE:
            return data
    except FileNotFoundError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(_SECRET_SIZE)

    # [N-07] Usa O_CREAT|O_EXCL (em vez de O_TRUNC) para a criação do segredo
    # na primeira execução. Duas chamadas concorrentes (ex: GUI e CLI abertas
    # ao mesmo tempo) poderiam antes gerar segredos DIFERENTES e cada uma
    # retornar o seu, mesmo que só um deles tivesse sido persistido em disco —
    # causando um machine_tag mismatch espúrio no processo "perdedor". Com
    # O_EXCL, se outro processo já venceu a corrida, relemos o que ele
    # efetivamente persistiu, em vez de confiar no valor gerado localmente.
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, secret)
        finally:
            os.close(fd)
        return secret
    except FileExistsError:
        return path.read_bytes()

def compute_bind_tag(machine_secret: bytes, vault_salt: bytes) -> str:
    tag = hmac.new(machine_secret, vault_salt, hashlib.sha256).digest()
    return tag.hex()

def verify_bind_tag(machine_secret: bytes, vault_salt: bytes, stored_tag: str) -> bool:
    try:
        expected = compute_bind_tag(machine_secret, vault_salt).encode()
        stored   = stored_tag.encode()
        return hmac.compare_digest(expected, stored)
    except Exception:
        return False

class MachineMismatchError(ValueError):
    def __init__(self, secret_path: str):
        self.secret_path = secret_path
        super().__init__(
            f"Este cofre está vinculado a outra máquina.\n"
            f"Copie o arquivo de segredo da máquina original para:\n"
            f"  {secret_path}\n"
            f"Ou use a chave mnemônica para desvincular e re-vincular."
        )
