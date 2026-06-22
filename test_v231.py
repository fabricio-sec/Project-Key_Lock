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
# Resultado final
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"RESULTADO: {PASSED} passaram, {FAILED} falharam")
if FAILURES:
    print("Falhas:")
    for f in FAILURES:
        print(f"  ✗ {f}")
sys.exit(1 if FAILED else 0)
