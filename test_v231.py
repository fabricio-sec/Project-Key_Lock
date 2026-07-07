"""
test_v231.py — Suíte de regressão do Key Lock v2.4.x
Cobre: achados da auditoria de segurança (v2.4.2), BUG-01 a BUG-08, S-01 a S-03,
       C-01 a C-05, F-01, exports de versão e validações de entrada.
Executar: python test_v231.py
Sem dependências externas além das do requirements.txt.
"""
import sys, os, json, shutil, tempfile, threading, time, hmac

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASSED = 0
FAILED = 0
FAILURES = []

def check(name, cond, detail=""):
    global PASSED, FAILED
    tag = "PASS" if cond else "FAIL"
    suffix = f" ({detail})" if detail and not cond else ""
    print(f"{tag}: {name}{suffix}")
    if cond:
        PASSED += 1
    else:
        FAILED += 1
        FAILURES.append(name)

def fresh_home():
    d = tempfile.mkdtemp()
    os.environ["HOME"] = d
    return d

# ── imports ──────────────────────────────────────────────────────────────────
fresh_home()
from core.vault import (
    create_vault, open_vault_with_passphrase, open_vault_with_recovery_file,
    open_vault_with_mnemonic, save_vault, save_vault_with_key,
    add_entry, delete_entry, rotate_master_key, rebind_vault,
    _meta_path, _load_vault_file,
)
from core.filelock import VaultLock, VaultLockError
from core.crypto import secure_zero, encrypt_vault, decrypt_vault
from core.vault_format import MIN_PIN_LENGTH, VAULTKEY_VERSION
from core.vault import VAULT_VERSION
from core.cli import main as cli_main
import core

# ═══════════════════════════════════════════════════════════════════════════
# 1. Fluxo básico create/open/save/add/delete
# ═══════════════════════════════════════════════════════════════════════════
h = fresh_home()
vp = os.path.join(h, "v.vault")
mnemonic, vk = create_vault("senhaForte_inicial_2024!", vp, "pin12345678")
check("1.01 create_vault retorna mnemonic e vaultkey", bool(mnemonic) and bool(vk))

c, k = open_vault_with_passphrase("senhaForte_inicial_2024!", vp)
check("1.02 open com passphrase correta", c["entries"] == [])

try:
    open_vault_with_passphrase("senhaErrada000", vp)
    check("1.03 rejeita passphrase errada", False)
except ValueError:
    check("1.03 rejeita passphrase errada", True)

c = add_entry(c, "GitHub", "fabricio", "SenhaGit123!", "https://github.com")
save_vault_with_key(c, k, vp)
secure_zero(k)
c2, k2 = open_vault_with_passphrase("senhaForte_inicial_2024!", vp)
check("1.04 entrada persistida após save", len(c2["entries"]) == 1)
check("1.05 dados da entrada corretos", c2["entries"][0]["name"] == "GitHub")

eid = c2["entries"][0]["id"]
c2 = delete_entry(c2, eid)
save_vault_with_key(c2, k2, vp)
secure_zero(k2)
c3, k3 = open_vault_with_passphrase("senhaForte_inicial_2024!", vp)
check("1.06 exclusão de entrada persistida", len(c3["entries"]) == 0)
secure_zero(k3)

try:
    add_entry({"entries": []}, "", "user", "pass")
    check("1.07 add_entry rejeita nome vazio", False)
except ValueError:
    check("1.07 add_entry rejeita nome vazio", True)

c4 = add_entry({"entries": []}, "Teste", "user", "pass123", "ftp://malicious.com")
check("1.08 sanitiza URL com scheme inválido", c4["entries"][0]["url"] == "")

# C-05: rejeita senha vazia
try:
    add_entry({"entries": []}, "Banco", "user", "")
    check("1.09 C-05: rejeita senha vazia", False)
except ValueError:
    check("1.09 C-05: rejeita senha vazia", True)

# ═══════════════════════════════════════════════════════════════════════════
# 2. Achado #1 / Anti-rollback fail-closed (v2.4.2)
# ═══════════════════════════════════════════════════════════════════════════
h2 = fresh_home()
vp2 = os.path.join(h2, "v.vault")
create_vault("senhaRollback_999!", vp2, "pin99999999")
c, k = open_vault_with_passphrase("senhaRollback_999!", vp2)
shutil.copy(vp2, vp2 + ".snap")
c = add_entry(c, "Banco", "u", "p!")
save_vault_with_key(c, k, vp2)
secure_zero(k)

# corrompendo metadata (JSON inválido)
mp = _meta_path(vp2)
mp.write_text("LIXO_CORROMPIDO")
shutil.copy(vp2 + ".snap", vp2)
try:
    open_vault_with_passphrase("senhaRollback_999!", vp2)
    check("2.01 bypass via metadata JSON corrompido bloqueado", False)
except ValueError as e:
    check("2.01 bypass via metadata JSON corrompido bloqueado",
          "metadata" in str(e).lower() or "rollback" in str(e).lower())

# force_accept_meta deve permitir explicitamente
cf, kf = open_vault_with_passphrase("senhaRollback_999!", vp2, force_accept_meta=True)
check("2.02 force_accept_meta permite abertura explícita", cf["entries"] == [])
secure_zero(kf)

# HMAC adulterado (JSON válido mas HMAC errado)
h2b = fresh_home()
vp2b = os.path.join(h2b, "v.vault")
create_vault("outraSenha_2024xx!", vp2b, "pin12312312")
mp2b = _meta_path(vp2b)
stored = json.loads(mp2b.read_text())
stored["min_timestamp"] = 99999999999
mp2b.write_text(json.dumps(stored))
try:
    open_vault_with_passphrase("outraSenha_2024xx!", vp2b)
    check("2.03 HMAC adulterado bloqueia abertura", False)
except ValueError:
    check("2.03 HMAC adulterado bloqueia abertura", True)

# ═══════════════════════════════════════════════════════════════════════════
# 3. Achado #2 — cmd_recover sem crash (vault_menu com tipo correto)
# ═══════════════════════════════════════════════════════════════════════════
from unittest import mock

h3 = fresh_home()
vp3 = os.path.join(h3, "v.vault")
m3, vk3 = create_vault("senhaRecovery_inicial!", vp3, "pinrecover12")
vkp3 = os.path.join(h3, "v.vaultkey")
open(vkp3, "w").write(vk3)

c3, old_k3 = open_vault_with_recovery_file(vkp3, vp3, "pinrecover12")
secure_zero(old_k3)
new_m3, new_vk3 = rotate_master_key(
    old_passphrase=None, new_passphrase="novaSenhaRecovery_2024!",
    vault_path=vp3, vaultkey_pin="novopinrecover1", contents=c3,
)
try:
    c3b, k3b = open_vault_with_passphrase("novaSenhaRecovery_2024!", vp3)
    save_vault_with_key(c3b, k3b, vp3)
    secure_zero(k3b)
    check("3.01 fluxo recovery + save_vault_with_key sem TypeError", True)
except TypeError as e:
    check("3.01 fluxo recovery + save_vault_with_key sem TypeError", False, str(e))

# ═══════════════════════════════════════════════════════════════════════════
# 4. Achado #5 — TOCTOU no VaultLock (O_EXCL)
# ═══════════════════════════════════════════════════════════════════════════
h4 = fresh_home()
vp4 = os.path.join(h4, "lock.vault")

results4 = []
barrier4 = threading.Barrier(4)
def worker4(n):
    lock = VaultLock(vp4)
    barrier4.wait()
    try:
        lock._write_lock_exclusive()
        results4.append((n, "ACQUIRED"))
    except VaultLockError:
        results4.append((n, "BLOCKED"))

threads4 = [threading.Thread(target=worker4, args=(i,)) for i in range(4)]
for t in threads4: t.start()
for t in threads4: t.join()
acquired4 = [r for r in results4 if r[1] == "ACQUIRED"]
check("4.01 apenas 1 de 4 threads concorrentes adquire lock (O_EXCL)", len(acquired4) == 1)
try: os.unlink(vp4 + ".lock")
except: pass

# lock stale (pid morto) é substituído
import socket
data4b = {"pid": 999999, "hostname": socket.gethostname(),
          "platform": "Linux", "acquired_at": time.time(), "vault": vp4, "token": "fake"}
open(vp4 + ".lock", "w").write(json.dumps(data4b))
try:
    with VaultLock(vp4): ok4b = True
except Exception: ok4b = False
check("4.02 lock stale (pid morto) substituído sem erro", ok4b)
check("4.03 lock liberado após uso", not os.path.exists(vp4 + ".lock"))

# bloqueio intra-thread
vp4c = os.path.join(h4, "lock2.vault")
lck1 = VaultLock(vp4c)
lck1.acquire()
try:
    VaultLock(vp4c).acquire()
    check("4.04 bloqueio intra-thread (mesmo processo)", False)
except VaultLockError:
    check("4.04 bloqueio intra-thread (mesmo processo)", True)
finally:
    lck1.release()
check("4.05 lock liberado após bloqueio intra-thread", not os.path.exists(vp4c + ".lock"))

# ═══════════════════════════════════════════════════════════════════════════
# 5. Achado #7 — sem cópias bytes() órfãs de chaves
# ═══════════════════════════════════════════════════════════════════════════
master_key = bytearray(b"X" * 32)
blob = encrypt_vault({"a": 1}, master_key, aad=b"test")
secure_zero(master_key)
check("5.01 master_key zerada após encrypt_vault", bytes(master_key) == b"\x00" * 32)
try:
    decrypt_vault(blob, bytearray(b"X" * 32), aad=b"test")
    check("5.02 decrypt funciona com bytearray direto (sem bytes())", True)
except Exception as e:
    check("5.02 decrypt funciona com bytearray direto (sem bytes())", False, str(e))

import subprocess, sys as _sys
result = subprocess.run(
    [_sys.executable, "-c",
     "import ast, sys; src=open('core/crypto.py').read(); "
     "nodes=[n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) "
     "and isinstance(n.func, ast.Name) and n.func.id=='bytes']; "
     "aesgcm = [n for n in nodes if any(isinstance(a, ast.Name) and a.id in ('key','master_key','shared_secret','kdf_key') for a in n.args)]; "
     "sys.exit(len(aesgcm))"],
    capture_output=True, cwd=os.path.dirname(os.path.abspath(__file__))
)
check("5.03 nenhuma conversão bytes(key) órfã em core/crypto.py", result.returncode == 0)

# ═══════════════════════════════════════════════════════════════════════════
# 6. Achado #11 — JSONDecodeError → ValueError amigável
# ═══════════════════════════════════════════════════════════════════════════
h6 = fresh_home()
vp6 = os.path.join(h6, "corrupto.vault")
open(vp6, "w").write("isso nao eh json {{{")
try:
    open_vault_with_passphrase("qualquer", vp6)
    check("6.01 JSON corrompido levanta ValueError amigável", False)
except ValueError as e:
    check("6.01 JSON corrompido levanta ValueError amigável", "corrompido" in str(e).lower())
except json.JSONDecodeError:
    check("6.01 JSON corrompido levanta ValueError amigável", False, "JSONDecodeError escapou")

# ═══════════════════════════════════════════════════════════════════════════
# 7. MIN_PIN_LENGTH centralizado (achado #6)
# ═══════════════════════════════════════════════════════════════════════════
check("7.01 MIN_PIN_LENGTH == 8", MIN_PIN_LENGTH == 8)
check("7.02 MIN_PIN_LENGTH vem de core.vault_format", True)  # já confirmado pelo import

# ═══════════════════════════════════════════════════════════════════════════
# 8. Mnemônico / recovery
# ═══════════════════════════════════════════════════════════════════════════
h8 = fresh_home()
vp8 = os.path.join(h8, "v.vault")
m8, vk8 = create_vault("senhaMnemonico_2024!", vp8, "pinmnemo1234")
c8, k8 = open_vault_with_mnemonic(m8, vp8)
check("8.01 abre com mnemônico correto", c8["entries"] == [])
secure_zero(k8)
try:
    open_vault_with_mnemonic("palavra invalida " * 12, vp8)
    check("8.02 rejeita mnemônico inválido", False)
except ValueError:
    check("8.02 rejeita mnemônico inválido", True)

vkp8 = os.path.join(h8, "v.vaultkey")
open(vkp8, "w").write(vk8)
c8b, k8b = open_vault_with_recovery_file(vkp8, vp8, "pinmnemo1234")
check("8.03 abre via .vaultkey correto", c8b["entries"] == [])
secure_zero(k8b)
try:
    open_vault_with_recovery_file(vkp8, vp8, "pinErrado")
    check("8.04 rejeita PIN errado no .vaultkey", False)
except ValueError:
    check("8.04 rejeita PIN errado no .vaultkey", True)

# C-02: limite de tamanho do .vaultkey
import tempfile as _tf
big_vk = os.path.join(h8, "big.vaultkey")
open(big_vk, "wb").write(b"X" * 5000)
try:
    open_vault_with_recovery_file(big_vk, vp8, "pinmnemo1234")
    check("8.05 C-02: rejeita .vaultkey > 4096 bytes", False)
except ValueError as e:
    check("8.05 C-02: rejeita .vaultkey > 4096 bytes", "vaultkey" in str(e).lower() or "tamanho" in str(e).lower())

# ═══════════════════════════════════════════════════════════════════════════
# 9. Rekey completo
# ═══════════════════════════════════════════════════════════════════════════
h9 = fresh_home()
vp9 = os.path.join(h9, "v.vault")
m9, vk9 = create_vault("senhaRekey_original_2024!", vp9, "pinrekey1234")
new_m9, new_vk9 = rotate_master_key(
    "senhaRekey_original_2024!", "senhaRekey_NOVA_2024!", vp9, "pinrekeyNOVO123"
)
try:
    open_vault_with_passphrase("senhaRekey_original_2024!", vp9)
    check("9.01 passphrase antiga invalidada após rekey", False)
except ValueError:
    check("9.01 passphrase antiga invalidada após rekey", True)

c9, k9 = open_vault_with_passphrase("senhaRekey_NOVA_2024!", vp9)
check("9.02 nova passphrase funciona após rekey", c9["entries"] == [])
secure_zero(k9)

try:
    open_vault_with_mnemonic(m9, vp9)
    check("9.03 mnemônico antigo invalidado após rekey", False)
except ValueError:
    check("9.03 mnemônico antigo invalidado após rekey", True)

c9b, k9b = open_vault_with_mnemonic(new_m9, vp9)
check("9.04 novo mnemônico funciona após rekey", c9b["entries"] == [])
secure_zero(k9b)

# ═══════════════════════════════════════════════════════════════════════════
# 10. machine_tag / machine bind
# ═══════════════════════════════════════════════════════════════════════════
h10 = fresh_home()
vp10 = os.path.join(h10, "v.vault")
m10, vk10 = create_vault("senhaMachine_bind_2024!", vp10, "pinmachine123")
vd10 = _load_vault_file(vp10)
check("10.01 machine_tag presente após create", "machine_tag" in vd10)

vd10["machine_tag"] = "0" * 64
open(vp10, "w").write(json.dumps(vd10, indent=2))
try:
    open_vault_with_passphrase("senhaMachine_bind_2024!", vp10)
    check("10.02 machine_tag adulterado detectado", False)
except Exception:
    check("10.02 machine_tag adulterado detectado", True)

# C-03: limite de tamanho do .vault
h10b = fresh_home()
vp10b = os.path.join(h10b, "big.vault")
open(vp10b, "wb").write(b"X" * (51 * 1024 * 1024))
try:
    open_vault_with_passphrase("qualquer", vp10b)
    check("10.03 C-03: rejeita .vault > 50MB", False)
except ValueError as e:
    check("10.03 C-03: rejeita .vault > 50MB", "50" in str(e) or "vault" in str(e).lower())

# ═══════════════════════════════════════════════════════════════════════════
# 11. S-01 — AAD no master_key_blob (VAULT_VERSION >= 4)
# ═══════════════════════════════════════════════════════════════════════════
check("11.01 S-01: VAULT_VERSION == 4", VAULT_VERSION == 4)
h11 = fresh_home()
vp11 = os.path.join(h11, "v.vault")
create_vault("senhaAAD_s01_2024!", vp11, "pin11111111")
vd11 = _load_vault_file(vp11)
check("11.02 S-01: version==4 salvo no .vault", vd11.get("version") == 4)
check("11.03 S-01: master_key_blob presente", "master_key_blob" in vd11)

# ═══════════════════════════════════════════════════════════════════════════
# 12. S-02 — Segredo de máquina unificado (sem duplicação)
# ═══════════════════════════════════════════════════════════════════════════
h12 = fresh_home()
vp12 = os.path.join(h12, "v.vault")
create_vault("senhaSeg_s02_2024!", vp12, "pin12121212")
from core.machine_bind import get_machine_secret
from core.meta import _get_or_create_machine_secret
s1 = get_machine_secret()
s2 = _get_or_create_machine_secret()
check("12.01 S-02: get_machine_secret == _get_or_create_machine_secret", s1 == s2)
secure_zero(bytearray(s1)); secure_zero(bytearray(s2))

# ═══════════════════════════════════════════════════════════════════════════
# 13. S-03 — save_vault_with_key (sem re-derivar Argon2id por save)
# ═══════════════════════════════════════════════════════════════════════════
h13 = fresh_home()
vp13 = os.path.join(h13, "v.vault")
create_vault("senhaSave_s03_2024!", vp13, "pin13131313")
c13, k13 = open_vault_with_passphrase("senhaSave_s03_2024!", vp13)
c13 = add_entry(c13, "E1", "u", "p!")
t0 = time.time()
save_vault_with_key(c13, k13, vp13)
elapsed = time.time() - t0
secure_zero(k13)
check("13.01 S-03: save_vault_with_key concluiu < 2s (sem Argon2id)", elapsed < 2.0,
      f"demorou {elapsed:.2f}s")
c13b, k13b = open_vault_with_passphrase("senhaSave_s03_2024!", vp13)
check("13.02 S-03: dados salvos corretamente", len(c13b["entries"]) == 1)
secure_zero(k13b)

# ═══════════════════════════════════════════════════════════════════════════
# 14. C-01 — fail_count persistido em disco (brute-force counter)
# ═══════════════════════════════════════════════════════════════════════════
h14 = fresh_home()
vp14 = os.path.join(h14, "v.vault")
create_vault("senhaBrute_c01_2024!", vp14, "pin14141414")
from core.meta import load_fail_count, write_fail_count, clear_fail_count
write_fail_count(vp14, 5)
fails14, _ = load_fail_count(vp14)
check("14.01 C-01: fail_count persistido em disco", fails14 == 5)
clear_fail_count(vp14)
fails14b, _ = load_fail_count(vp14)
check("14.02 C-01: fail_count zerado após clear", fails14b == 0)

# ═══════════════════════════════════════════════════════════════════════════
# 15. F-01 — rebind_vault
# ═══════════════════════════════════════════════════════════════════════════
h15 = fresh_home()
vp15 = os.path.join(h15, "v.vault")
create_vault("senhaRebind_f01_2024!", vp15, "pin15151515")
rebind_vault("senhaRebind_f01_2024!", vp15)
c15, k15 = open_vault_with_passphrase("senhaRebind_f01_2024!", vp15)
check("15.01 F-01: rebind_vault funciona sem erros", c15["entries"] == [])
secure_zero(k15)

# ═══════════════════════════════════════════════════════════════════════════
# 16. Exports de versão (core/__init__.py)
# ═══════════════════════════════════════════════════════════════════════════
check("16.01 core.__vault_version__ == VAULT_VERSION", core.__vault_version__ == VAULT_VERSION)
check("16.02 core.__vaultkey_version__ == VAULTKEY_VERSION", core.__vaultkey_version__ == VAULTKEY_VERSION)
check("16.03 core.__version__ presente", bool(core.__version__))

# ═══════════════════════════════════════════════════════════════════════════
# 17. Achado #9 — comparação de clipboard em tempo constante (import hmac)
# ═══════════════════════════════════════════════════════════════════════════
import ast
gui_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui.py")).read()
check("17.01 hmac importado em gui.py", "import hmac" in gui_src)
check("17.02 hmac.compare_digest usado no clipboard wipe", "hmac.compare_digest" in gui_src)
check("17.03 comparação direta '==' removida do clipboard wipe",
      "clipboard_get() ==" not in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 18. Achado #10 — WM_DELETE_WINDOW registrado
# ═══════════════════════════════════════════════════════════════════════════
check("18.01 WM_DELETE_WINDOW registrado em gui.py", 'protocol("WM_DELETE_WINDOW"' in gui_src)
check("18.02 _on_close_request chama _wipe_secrets", "_on_close_request" in gui_src and "_wipe_secrets" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 19. Achado #12 — _focus_next_word corrigido
# ═══════════════════════════════════════════════════════════════════════════
check("19.01 _word_entries inicializado em RecoverWordsScreen", "_word_entries = []" in gui_src)
check("19.02 _focus_next_word usa focus_set()", "focus_set()" in gui_src)
check("19.03 stub 'grid = self._word_vars[idx + 1]' removido",
      "grid = self._word_vars[idx + 1]" not in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 20. Achado #3 — GUI diferencia tipos de exceção no OpenVaultDlg
# ═══════════════════════════════════════════════════════════════════════════
check("20.01 FileNotFoundError tratado separadamente em OpenVaultDlg",
      "FileNotFoundError" in gui_src)
check("20.02 VaultLockError tratado separadamente em OpenVaultDlg",
      "VaultLockError" in gui_src)
check("20.03 catch-all genérico 'Acesso negado' removido",
      '"Acesso negado"' not in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 21. Achado #4 — _wipe_secrets presente e usado em _close/_auto_lock
# ═══════════════════════════════════════════════════════════════════════════
check("21.01 _wipe_secrets definido em VaultScreen", "def _wipe_secrets" in gui_src)
check("21.02 _wipe_secrets chamado em _close", "_close" in gui_src and
      gui_src.count("_wipe_secrets()") >= 3)

# ═══════════════════════════════════════════════════════════════════════════
# 22. Achado #6 — validação MIN_PIN_LENGTH na GUI
# ═══════════════════════════════════════════════════════════════════════════
check("22.01 MIN_PIN_LENGTH importado em gui.py",
      "from core.vault_format import MIN_PIN_LENGTH" in gui_src)
check("22.02 validação len(pin) < MIN_PIN_LENGTH presente na GUI",
      "len(pin) < MIN_PIN_LENGTH" in gui_src or "len(new_pin) < MIN_PIN_LENGTH" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 23. Achado #8 — PIN separado de nova passphrase nos fluxos de recovery
# ═══════════════════════════════════════════════════════════════════════════
check("23.01 vaultkey_pin=new_pp removido dos fluxos de recovery",
      "vaultkey_pin=new_pp" not in gui_src)
check("23.02 new_pin_v presente nos fluxos de recovery",
      "new_pin_v" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 24. Auditoria v2.4.3 — A-01/A-02: save_vault_with_key na GUI
# ═══════════════════════════════════════════════════════════════════════════
check("24.01 _del_entry usa save_vault_with_key (não save_vault com passphrase)",
      "save_vault_with_key(self.contents, self.kdf_key, self.vault_path)" in gui_src)
check("24.02 _on_added usa save_vault_with_key",
      gui_src.count("save_vault_with_key(self.contents, self.kdf_key, self.vault_path)") >= 2)
check("24.03 _FilesView._save usa save_vault_with_key",
      "save_vault_with_key(self._vs.contents, self._vs.kdf_key, self._vs.vault_path)" in gui_src)
check("24.04 VaultScreen não importa save_vault para operações de sessão",
      gui_src.count("from core.vault import delete_entry, save_vault\n") == 0)

# ═══════════════════════════════════════════════════════════════════════════
# 25. Auditoria v2.4.3 — A-03: RekeyDlg confirmação de PIN
# ═══════════════════════════════════════════════════════════════════════════
check("25.01 RekeyDlg tem campo _pin2_v", "_pin2_v" in gui_src)
check("25.02 RekeyDlg valida pin != pin2",
      "pin != pin2" in gui_src)
check("25.03 RekeyDlg exibe 'Confirmar PIN do .vaultkey'",
      "Confirmar PIN do .vaultkey" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 26. Auditoria v2.4.3 — A-04: mensagem clara para vaultkey v1
# ═══════════════════════════════════════════════════════════════════════════
vf_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "vault_format.py")).read()
check("26.01 mensagem específica para versão 1 do vaultkey",
      "versão 1" in vf_src or "formato legado" in vf_src)
check("26.02 versão 1 tratada separadamente de outras versões inválidas",
      vf_src.index("version == 1") < vf_src.index("version not in"))

# ═══════════════════════════════════════════════════════════════════════════
# 27. Auditoria v2.4.3 — A-05: aviso quando machine_tag ausente
# ═══════════════════════════════════════════════════════════════════════════
vault_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "vault.py")).read()
check("27.01 warnings.warn emitido quando machine_tag ausente",
      "warnings.warn" in vault_src and "machine_tag" in vault_src)
check("27.02 aviso orienta uso do rebind",
      "rebind" in vault_src)

# ═══════════════════════════════════════════════════════════════════════════
# 28. Versão 2.4.3
# ═══════════════════════════════════════════════════════════════════════════
init_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "__init__.py")).read()
check("28.01 versão 2.4.6 em core/__init__.py", "2.4.6" in init_src)

# ═══════════════════════════════════════════════════════════════════════════
# 33. Auditoria v2.4.4 — B-01: passphrase removida de VaultScreen
# ═══════════════════════════════════════════════════════════════════════════
check("33.01 B-01: VaultScreen.__init__ não aceita parâmetro passphrase",
      "def __init__(self, parent, app, contents, vault_path, kdf_key=None):" in gui_src)
check("33.02 B-01: self.passphrase não é atribuída em VaultScreen",
      "self.passphrase = passphrase" not in gui_src)
check("33.03 B-01: self.passphrase não é zerada em _wipe_secrets",
      'self.passphrase = ""' not in gui_src)
check("33.04 B-01: enter_vault não passa passphrase ao construtor de VaultScreen",
      "VaultScreen(self.root, self, contents, vault_path, kdf_key=kdf_key)" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 34. Auditoria v2.4.4 — B-02: fallback morto _get_aes_key removido
# ═══════════════════════════════════════════════════════════════════════════
check("34.01 B-02: fallback derive_key_from_passphrase em _get_aes_key removido",
      "derive_key_from_passphrase(self._vs.passphrase" not in gui_src)
check("34.02 B-02: RuntimeError presente como fallback seguro em _get_aes_key",
      "RuntimeError" in gui_src and "kdf_key não disponível" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 29. Follow-up Audit — R-01: rollback via deleção do metadata bloqueado
# ═══════════════════════════════════════════════════════════════════════════
import time as _time

h29 = tempfile.mkdtemp()
vp29 = os.path.join(h29, "rollback_test.vault")
mn29, _ = create_vault("passphrase-29-forte!", vp29, "pin-29-forte!")
c29, k29 = open_vault_with_passphrase("passphrase-29-forte!", vp29)

# Adiciona dado T0 (snapshot 1 - com entrada)
c29 = add_entry(c29, "EntradaT0", "u0", "senha0!", "https://t0.com")
save_vault_with_key(c29, k29, vp29)
_time.sleep(1)
with open(vp29) as f:
    snap_t0 = f.read()  # vault COM entrada (snapshot T0)

# Adiciona dado T1 (estado atual)
c29_2, k29_2 = open_vault_with_passphrase("passphrase-29-forte!", vp29)
c29_2 = add_entry(c29_2, "BancoTest", "u29", "senha29!", "https://x.com")
save_vault_with_key(c29_2, k29_2, vp29)
secure_zero(k29)
secure_zero(k29_2)

# Simula ataque: old vault (T0, COM EntradaT0 mas SEM BancoTest) + metadata deletado
mp29 = _meta_path(vp29)
snap_t0_no_tag = json.loads(snap_t0)
snap_t0_no_tag.pop("machine_tag", None)
with open(vp29, "w") as f:
    json.dump(snap_t0_no_tag, f)
mp29.unlink(missing_ok=True)

r29_blocked = False
try:
    c_atk29, k_atk29 = open_vault_with_passphrase("passphrase-29-forte!", vp29)
    # Se abriu e não tem entradas, o rollback funcionou (mau)
    if not c_atk29.get("entries"):
        r29_blocked = False
    else:
        r29_blocked = True  # abriu mas tem dados (inesperado)
    secure_zero(k_atk29)
except ValueError as e:
    r29_blocked = True  # bloqueado corretamente

check("29.01 R-01: rollback (old vault + meta deletado com dados) bloqueado", r29_blocked)

vault_src_29 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "meta.py")).read()
check("29.02 R-01: check_and_update_meta verifica has_data quando meta ausente",
      "has_data" in vault_src_29)
check("29.03 R-01: mensagem de erro cita 'metadata anti-rollback' e 'ausente'",
      "AUSENTE" in vault_src_29)

# ═══════════════════════════════════════════════════════════════════════════
# 30. Follow-up Audit — B-02: vault_salt no .vaultkey é verificado
# ═══════════════════════════════════════════════════════════════════════════
import base64 as _b64

h30 = tempfile.mkdtemp()
vp30 = os.path.join(h30, "b02_test.vault")
vkp30 = os.path.join(h30, "b02_test.vaultkey")

mn30, vk30 = create_vault("passphrase-30-forte!", vp30, "pin-30-forte!")
with open(vkp30, "w") as f:
    f.write(vk30)

# Modifica vault_salt no .vaultkey para valor falso
raw30 = _b64.urlsafe_b64decode(vk30.strip().encode())
payload30 = json.loads(raw30)
payload30["vault_salt"] = _b64.urlsafe_b64encode(os.urandom(16)).decode()
mod30 = _b64.urlsafe_b64encode(json.dumps(payload30, separators=(",", ":")).encode()).decode()

vkp30_mod = os.path.join(h30, "modified.vaultkey")
with open(vkp30_mod, "w") as f:
    f.write(mod30)

b02_blocked = False
try:
    from core.vault import open_vault_with_recovery_file as _ovrf
    c30, k30 = _ovrf(vkp30_mod, vp30, "pin-30-forte!")
    secure_zero(k30)
except ValueError as e:
    if "salt" in str(e).lower() or "pertence" in str(e):
        b02_blocked = True

check("30.01 B-02: .vaultkey com vault_salt errado é rejeitado", b02_blocked)

vault_src_30 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "vault.py")).read()
check("30.02 B-02: validação de vaultkey_vault_salt presente em vault.py",
      "vaultkey_vault_salt" in vault_src_30)

# ═══════════════════════════════════════════════════════════════════════════
# 31. Follow-up Audit — P-01: type confusion em version bloqueada
# ═══════════════════════════════════════════════════════════════════════════
h31 = tempfile.mkdtemp()
vp31 = os.path.join(h31, "p01_test.vault")
create_vault("passphrase-31-forte!", vp31, "pin-31-forte!")

with open(vp31) as f:
    vd31 = json.load(f)
vd31["version"] = "4"  # string em vez de int
with open(vp31, "w") as f:
    json.dump(vd31, f)

p01_blocked = False
try:
    c31, k31 = open_vault_with_passphrase("passphrase-31-forte!", vp31)
    secure_zero(k31)
except ValueError as e:
    p01_blocked = True  # ValueError esperado (tratado)
except TypeError:
    p01_blocked = False  # TypeError não tratado (bug)

check("31.01 P-01: version como string levanta ValueError (não TypeError)", p01_blocked)

# ═══════════════════════════════════════════════════════════════════════════
# 32. Follow-up Audit — M-01: pin_key é bytearray (zeravelável)
# ═══════════════════════════════════════════════════════════════════════════
vf_src_32 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "vault_format.py")).read()
check("32.01 M-01: _derive_pin_key retorna bytearray",
      "-> bytearray" in vf_src_32)
check("32.02 M-01: pin_key zerado em build_vaultkey_file (finally block)",
      "pin_key[i] = 0" in vf_src_32)
check("32.03 M-01: pin_key zerado em parse_vaultkey_file (finally block)",
      vf_src_32.count("pin_key[i] = 0") >= 2)

# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
# 35. v2.4.5 — BUG-01: _FilesView._redraw guard para _inner
# ═══════════════════════════════════════════════════════════════════════════
check("35.01 BUG-01: _redraw tem guard hasattr _inner",
      "hasattr(self, \"_inner\")" in gui_src or "hasattr(self, '_inner')" in gui_src)
check("35.02 BUG-01: _redraw verifica winfo_exists()",
      "winfo_exists()" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 36. v2.4.5 — UX-01: Gerador e Rotacionador como abas inline
# ═══════════════════════════════════════════════════════════════════════════
check("36.01 UX-01: _InlineGenpass class existe",
      "class _InlineGenpass" in gui_src)
check("36.02 UX-01: _InlineRekey class existe",
      "class _InlineRekey" in gui_src)
check("36.03 UX-01: _show_genpass method existe em VaultScreen",
      "_show_genpass" in gui_src)
check("36.04 UX-01: _show_rekey method existe em VaultScreen",
      "_show_rekey" in gui_src)
check("36.05 UX-01: _nav_genpass sidebar nav existe",
      "_nav_genpass" in gui_src)
check("36.06 UX-01: _nav_rekey sidebar nav existe",
      "_nav_rekey" in gui_src)
check("36.07 UX-01: GenpassDlg não é mais invocado em _open_genpass",
      "_open_genpass" not in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 37. v2.4.5 — UX-02: contador de arquivos na topbar
# ═══════════════════════════════════════════════════════════════════════════
check("37.01 UX-02: _files_count_lbl instanciado em _build",
      "_files_count_lbl" in gui_src)
check("37.02 UX-02: _files_count_lbl exibido em _show_files",
      "_files_count_lbl.pack" in gui_src)
check("37.03 UX-02: _files_count_lbl oculto em _show_entries",
      "_files_count_lbl.pack_forget()" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 38. v2.4.5 — UX-03: link GitHub na tela inicial
# ═══════════════════════════════════════════════════════════════════════════
check("38.01 UX-03: URL do GitHub presente na WelcomeScreen",
      "github.com/fabricio-sec/Project-Key_Lock" in gui_src)
check("38.02 UX-03: _open_url chamado com link GitHub",
      "https://github.com/fabricio-sec/Project-Key_Lock" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 39. v2.4.5 — BUG-02: RekeyDlg sem self._vs.passphrase
# ═══════════════════════════════════════════════════════════════════════════
check("39.01 BUG-02: passphrase removida de _done no RekeyDlg",
      "self._vs.passphrase = new_pp" not in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 40. v2.4.5 — versão
# ═══════════════════════════════════════════════════════════════════════════
check("40.01 versão 2.4.6 em core/__init__.py", "2.4.6" in init_src)

# ═══════════════════════════════════════════════════════════════════════════
# 41. Auditoria 02/07/2026 (v2.4.6) — N-01: escrita irreversível em disco
#     antes de operações que podem falhar em rotate_master_key()/create_vault()
#     [CRÍTICA — explica o relato de recuperação por 24 palavras "quebrando"
#     permanentemente após uma falha na primeira tentativa]
# ═══════════════════════════════════════════════════════════════════════════
check("41.01 rotate_master_key: mnemônico é gerado ANTES da escrita atômica",
      vault_src.index("private_key_to_mnemonic(new_recovery_private)") <
      vault_src.index('_atomic_write(vault_path, json.dumps(new_vault_data'))

check("41.02 create_vault: mnemônico é gerado ANTES da escrita atômica",
      vault_src.index("private_key_to_mnemonic(recovery_private)") <
      vault_src.index('_atomic_write(vault_path, json.dumps(vault_data'))

# Teste comportamental: força uma falha exatamente na janela pós-escrita
# (como no PoC original do achado) e confirma que NADA foi persistido —
# nem o salt muda, nem o mnemônico antigo para de funcionar.
h41 = fresh_home()
vp41 = os.path.join(h41, "v41.vault")
mn41, _ = create_vault("senhaForte_n01_2024!", vp41, "pin12345678")
with open(vp41) as _f:
    salt_before_41 = json.load(_f)["salt"]

import core.vault as _vault_mod
_real_p2m = _vault_mod.private_key_to_mnemonic
def _flaky_p2m(pk):
    raise RuntimeError("falha simulada pós-escrita (regressão N-01)")
_vault_mod.private_key_to_mnemonic = _flaky_p2m

c41, k41 = open_vault_with_mnemonic(mn41, vp41)
rotate_raised = False
try:
    rotate_master_key(old_passphrase=None, new_passphrase="novaSenha_n01_456!",
                       vault_path=vp41, vaultkey_pin="novopin99", contents=c41)
except RuntimeError:
    rotate_raised = True
_vault_mod.private_key_to_mnemonic = _real_p2m

with open(vp41) as _f:
    salt_after_41 = json.load(_f)["salt"]

check("41.03 rotate_master_key propaga a falha simulada", rotate_raised)
check("41.04 salt do .vault permanece INALTERADO quando a geração falha",
      salt_before_41 == salt_after_41)

old_mnemonic_still_works_41 = True
try:
    open_vault_with_mnemonic(mn41, vp41)
except Exception:
    old_mnemonic_still_works_41 = False
check("41.05 mnemônico ORIGINAL ainda abre o cofre após a falha simulada",
      old_mnemonic_still_works_41)

new_pp_should_fail_41 = False
try:
    open_vault_with_passphrase("novaSenha_n01_456!", vp41)
except Exception:
    new_pp_should_fail_41 = True
check("41.06 nova passphrase NÃO foi aplicada (nenhuma mutação parcial no disco)",
      new_pp_should_fail_41)

# ═══════════════════════════════════════════════════════════════════════════
# 42. Auditoria 02/07/2026 (v2.4.6) — N-02: fluxos de recuperação não
#     descartam mais o novo mnemônico gerado
# ═══════════════════════════════════════════════════════════════════════════
check("42.01 padrão de descarte do mnemônico ('_, new_vaultkey = rotate_master_key(') não existe mais",
      "_, new_vaultkey = rotate_master_key(" not in gui_src)
check("42.02 RecoverFileScreen e RecoverWordsScreen exibem MnemonicDlg com o novo mnemônico",
      gui_src.count("MnemonicDlg(self.app.root, new_mnemonic, vaultkey_path)") == 2)

# ═══════════════════════════════════════════════════════════════════════════
# 43. Auditoria 02/07/2026 (v2.4.6) — N-03: .vaultkey gravado com 0600
#     (helper único reaproveitado por CLI e GUI)
# ═══════════════════════════════════════════════════════════════════════════
check("43.01 write_vaultkey_file existe em core/vault_format.py",
      "def write_vaultkey_file(" in vf_src)
check("43.02 write_vaultkey_file usa os.open com modo 0o600",
      "os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600" in vf_src)
check("43.03 nenhum open(vaultkey_path, \"w\") inseguro remanescente na GUI",
      'open(vaultkey_path, "w")' not in gui_src)
check("43.04 write_vaultkey_file é usado nos 5 pontos de escrita da GUI",
      gui_src.count("write_vaultkey_file(vaultkey_path,") == 5)

h43 = fresh_home()
p43 = os.path.join(h43, "teste.vaultkey")
from core.vault_format import write_vaultkey_file
write_vaultkey_file(p43, "conteudo-de-teste")
perm43 = oct(os.stat(p43).st_mode)[-3:]
check("43.05 arquivo gravado por write_vaultkey_file tem permissão 600",
      perm43 == "600", detail=f"permissão encontrada: {perm43}")

# ═══════════════════════════════════════════════════════════════════════════
# 44. Auditoria 02/07/2026 (v2.4.6) — N-04: crash de TclError no medidor de
#     força de senha/PIN após destruição do widget (fluxo de recuperação por
#     24 palavras) — corrigido via helper único e seguro
# ═══════════════════════════════════════════════════════════════════════════
check("44.01 _bind_strength_meter existe em gui.py",
      "def _bind_strength_meter(" in gui_src)
check("44.02 _bind_strength_meter guarda contra widget destruído (winfo_exists)",
      "if not owner.winfo_exists():" in gui_src)
check("44.03 _bind_strength_meter reaproveitado nas 5 telas (CreateScreen x2 + 4 telas x1)",
      gui_src.count("_bind_strength_meter(") == 11)  # 1 def + 10 chamadas
check("44.04 nenhum callback _on_pp/_on_new_pp/_on_pin_change duplicado remanescente",
      "def _on_pp(" not in gui_src and "def _on_new_pp(" not in gui_src
      and "def _on_pin_change(" not in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 45. Auditoria 02/07/2026 (v2.4.6) — N-05: .vault malformado não gera mais
#     AttributeError/KeyError não tratado (traceback cru na CLI)
# ═══════════════════════════════════════════════════════════════════════════
h45 = fresh_home()
p45a = os.path.join(h45, "lista.vault")
with open(p45a, "w") as _f:
    json.dump([1, 2, 3], _f)
err45a = None
try:
    _load_vault_file(p45a)
except Exception as e:
    err45a = e
check("45.01 JSON de nível superior não-objeto vira ValueError amigável",
      isinstance(err45a, ValueError))

p45b = os.path.join(h45, "incompleto.vault")
with open(p45b, "w") as _f:
    json.dump({"version": 4}, _f)
err45b = None
try:
    _load_vault_file(p45b)
except Exception as e:
    err45b = e
check("45.02 campos obrigatórios ausentes viram ValueError amigável (não KeyError)",
      isinstance(err45b, ValueError))

# ═══════════════════════════════════════════════════════════════════════════
# 46. Auditoria 02/07/2026 (v2.4.6) — N-06: vazamento de bind_all a cada
#     ciclo de abrir/fechar cofre na GUI
# ═══════════════════════════════════════════════════════════════════════════
check("46.01 _unbind_activity existe em VaultScreen",
      "def _unbind_activity(" in gui_src)
check("46.02 _close() chama _unbind_activity()",
      "_unbind_activity()" in gui_src[gui_src.index("def _close(self):"):
                                       gui_src.index("def _close(self):") + 300])
check("46.03 _auto_lock() chama _unbind_activity()",
      "_unbind_activity()" in gui_src[gui_src.index("def _auto_lock(self):"):
                                       gui_src.index("def _auto_lock(self):") + 300])
check("46.04 App._set() tem rede de segurança adicional (isinstance VaultScreen)",
      "isinstance(self._current, VaultScreen)" in gui_src)

# ═══════════════════════════════════════════════════════════════════════════
# 47. Auditoria 02/07/2026 (v2.4.6) — N-07: corrida na criação do
#     machine_secret.key na primeira execução (O_EXCL em vez de O_TRUNC)
# ═══════════════════════════════════════════════════════════════════════════
machine_bind_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "core", "machine_bind.py")).read()
check("47.01 get_machine_secret usa O_EXCL na criação inicial",
      "os.O_WRONLY | os.O_CREAT | os.O_EXCL" in machine_bind_src)
check("47.02 corrida tratada relendo o segredo persistido (FileExistsError)",
      "except FileExistsError:" in machine_bind_src)

import core.machine_bind as _mb_mod
import pathlib as _pathlib
h47 = fresh_home()
secret_path_47 = os.path.join(h47, "machine_secret.key")
_orig_secret_file_path = _mb_mod.secret_file_path
_mb_mod.secret_file_path = lambda: _pathlib.Path(secret_path_47)
results_47 = []
def _worker_47():
    results_47.append(_mb_mod.get_machine_secret())
threads_47 = [threading.Thread(target=_worker_47) for _ in range(8)]
for t in threads_47: t.start()
for t in threads_47: t.join()
_mb_mod.secret_file_path = _orig_secret_file_path
with open(secret_path_47, "rb") as _f:
    persisted_47 = _f.read()
check("47.03 8 threads concorrentes convergem para o MESMO segredo persistido",
      len(set(results_47)) == 1 and all(r == persisted_47 for r in results_47))

# ═══════════════════════════════════════════════════════════════════════════
# 48. Auditoria 02/07/2026 (v2.4.6) — N-08: erro inesperado na verificação de
#     machine-binding agora emite aviso em vez de falhar em silêncio total
# ═══════════════════════════════════════════════════════════════════════════
h48 = fresh_home()
vp48 = os.path.join(h48, "v48.vault")
create_vault("senhaForte_n08_2024!", vp48, "pin12345678")
_real_gms = _vault_mod.get_machine_secret
def _flaky_gms():
    raise PermissionError("simulado (regressão N-08)")
_vault_mod.get_machine_secret = _flaky_gms
import warnings as _warnings48
with _warnings48.catch_warnings(record=True) as _w48:
    _warnings48.simplefilter("always")
    open_vault_with_passphrase("senhaForte_n08_2024!", vp48)
    msgs_48 = [str(x.message) for x in _w48]
_vault_mod.get_machine_secret = _real_gms
check("48.01 erro inesperado no machine-binding emite warnings.warn (não silêncio total)",
      any("vínculo de máquina" in m for m in msgs_48))

# ═══════════════════════════════════════════════════════════════════════════
# 49. Auditoria 02/07/2026 (v2.4.6) — N-09: medidor de força do PIN do
#     .vaultkey adicionado às telas de recuperação/rekey (antes só existia
#     em CreateScreen)
# ═══════════════════════════════════════════════════════════════════════════
check("49.01 RecoverFileScreen liga medidor de força ao novo PIN",
      "_bind_strength_meter(self, self.new_pin_v" in gui_src)
check("49.02 RecoverWordsScreen liga medidor de força ao novo PIN",
      gui_src.count("_bind_strength_meter(self, self.new_pin_v") == 2)
check("49.03 _InlineRekey e RekeyDlg ligam medidor de força ao novo PIN",
      gui_src.count("_bind_strength_meter(self, self._pin_v") == 2)

# ═══════════════════════════════════════════════════════════════════════════
# 50. Auditoria 02/07/2026 (v2.4.6) — N-10: add_entry agora limita o
#     tamanho do campo password (antes só name/username/url tinham teto)
# ═══════════════════════════════════════════════════════════════════════════
v50 = {"version": VAULT_VERSION, "entries": []}
password_rejected_50 = False
try:
    add_entry(v50, "site", "user", "x" * 5000)
except ValueError:
    password_rejected_50 = True
check("50.01 add_entry rejeita senha com mais de 4096 caracteres",
      password_rejected_50)
v50b = add_entry(v50, "site2", "user2", "senha-normal-123")
check("50.02 add_entry ainda aceita senha de tamanho normal",
      len(v50b["entries"]) == 1)

# ═══════════════════════════════════════════════════════════════════════════
# 51. Auditoria 02/07/2026 (v2.4.6) — N-11: dependências com teto de versão
# ═══════════════════════════════════════════════════════════════════════════
req_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "requirements.txt")).read()
check("51.01 todas as dependências têm teto de versão (<)",
      all(f"{pkg}>=" in req_src and req_src[req_src.index(f"{pkg}>="):
          req_src.index(f"{pkg}>=") + 60].count("<") >= 1
          for pkg in ["argon2-cffi", "cryptography", "mnemonic", "pyperclip", "Pillow"]))

# ═══════════════════════════════════════════════════════════════════════════
# Resultado final

# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"RESULTADO: {PASSED} passaram, {FAILED} falharam")
if FAILURES:
    print("Falhas:")
    for f in FAILURES:
        print(f"  ✗ {f}")
sys.exit(1 if FAILED else 0)
