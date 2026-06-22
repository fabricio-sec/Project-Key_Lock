import json
import os
import platform
import secrets as _secrets
import socket
import threading as _threading
import time
from pathlib import Path

LOCK_STALE_SECONDS = 300

_THREAD_LOCKS: dict = {}
_THREAD_LOCKS_META = _threading.Lock()

def _get_thread_lock(vault_path: str) -> _threading.Lock:
    with _THREAD_LOCKS_META:
        if vault_path not in _THREAD_LOCKS:
            _THREAD_LOCKS[vault_path] = _threading.Lock()
        return _THREAD_LOCKS[vault_path]

class VaultLockError(Exception):
    pass

class VaultLock:

    def __init__(self, vault_path: str):
        self.vault_path = str(Path(vault_path).resolve())
        self.lock_path  = self.vault_path + ".lock"
        self._held  = False
        self._tlock: "_threading.Lock | None" = None
        self._token: "str | None" = None

    def acquire(self) -> None:

        tlock = _get_thread_lock(self.vault_path)
        if not tlock.acquire(blocking=False):
            raise VaultLockError(
                f"O cofre '{Path(self.vault_path).name}' já está em uso por outra "
                f"thread neste processo."
            )
        self._tlock = tlock

        try:
            existing = self._read_lock()
            if existing is not None and not self._is_stale(existing):
                owner_pid  = existing.get("pid", "?")
                owner_host = existing.get("hostname", "?")
                owner_time = existing.get("acquired_at", 0)
                age_s = int(time.time() - owner_time)
                raise VaultLockError(
                    f"O cofre '{Path(self.vault_path).name}' já está aberto por outra instância.\n"
                    f"  PID: {owner_pid}  |  Host: {owner_host}  |  Há: {age_s}s\n"
                    f"  Se o outro processo travar, aguarde {LOCK_STALE_SECONDS}s para liberação automática.\n"
                    f"  Para forçar (RISCO DE PERDA DE DADOS): delete '{self.lock_path}'"
                )
            elif existing is not None:
                self._force_remove_lock()

            try:
                self._write_lock_exclusive()
            except VaultLockError:
                existing = self._read_lock()
                if existing is not None and not self._is_stale(existing):
                    owner_pid  = existing.get("pid", "?")
                    owner_host = existing.get("hostname", "?")
                    owner_time = existing.get("acquired_at", 0)
                    age_s = int(time.time() - owner_time)
                    raise VaultLockError(
                        f"O cofre '{Path(self.vault_path).name}' já está aberto por outra instância "
                        f"(corrida detectada na aquisição do lock).\n"
                        f"  PID: {owner_pid}  |  Host: {owner_host}  |  Há: {age_s}s\n"
                        f"  Se o outro processo travar, aguarde {LOCK_STALE_SECONDS}s para liberação automática.\n"
                        f"  Para forçar (RISCO DE PERDA DE DADOS): delete '{self.lock_path}'"
                    )
                raise
            self._held = True

        except Exception:
            tlock.release()
            self._tlock = None
            raise

    def release(self) -> None:
        if self._held:
            self._remove_lock()
            self._held = False
        if self._tlock is not None:
            self._tlock.release()
            self._tlock = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False

    def _write_lock_exclusive(self) -> None:

        self._token = _secrets.token_hex(16)
        data = {
            "pid":         os.getpid(),
            "hostname":    socket.gethostname(),
            "platform":    platform.system(),
            "acquired_at": time.time(),
            "vault":       self.vault_path,
            "token":       self._token,
        }
        content = json.dumps(data, indent=2)
        try:
            fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, content.encode("utf-8"))
            finally:
                os.close(fd)
        except FileExistsError as e:
            raise VaultLockError(
                "Lock já existe — outra instância venceu a corrida pela aquisição."
            ) from e
        except Exception as e:
            raise VaultLockError(f"Não foi possível criar o lock file: {e}") from e

    def _read_lock(self) -> "dict | None":
        try:
            return json.loads(Path(self.lock_path).read_text())
        except FileNotFoundError:
            return None
        except Exception:
            return {"pid": -1, "acquired_at": 0}

    def _force_remove_lock(self) -> None:
        try:
            os.unlink(self.lock_path)
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _remove_lock(self) -> None:

        existing = self._read_lock()
        if existing and existing.get("token") and existing.get("token") != self._token:
            return
        try:
            os.unlink(self.lock_path)
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _is_stale(self, lock_data: dict) -> bool:
        acquired_at = lock_data.get("acquired_at", 0)
        pid         = lock_data.get("pid", -1)
        hostname    = lock_data.get("hostname", "")

        if time.time() - acquired_at > LOCK_STALE_SECONDS:
            return True

        if hostname != socket.gethostname():
            return False

        return not _pid_is_alive(pid)

def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except AttributeError:
        return _pid_is_alive_windows(pid)

def _pid_is_alive_windows(pid: int) -> bool:
    try:
        import ctypes
        PROCESS_QUERY_INFORMATION = 0x0400
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if handle == 0:
            return False
        exit_code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return exit_code.value == 259
    except Exception:
        return True

def get_lock_info(vault_path: str) -> "dict | None":
    lock_path = str(Path(vault_path).resolve()) + ".lock"
    try:
        return json.loads(Path(lock_path).read_text())
    except Exception:
        return None
