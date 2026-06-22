import sys
import os
import getpass
import hmac
import threading
import time

from core.vault import (
    create_vault,
    open_vault_with_passphrase,
    open_vault_with_recovery_file,
    open_vault_with_mnemonic,
    save_vault,
    save_vault_with_key,
    rotate_master_key,
    rebind_vault,
    add_entry,
    delete_entry,
    VaultLockError,
    REKEY_CUSTODY_WARNING,
)
from core.crypto import (
    estimate_passphrase_entropy,
    generate_password,
    secure_zero,
)
from core.mnemonic import format_mnemonic_display
from core.vault_format import MIN_PIN_LENGTH

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"{GREEN}✔ {msg}{RESET}")
def err(msg):   print(f"{RED}✘ {msg}{RESET}")
def info(msg):  print(f"{CYAN}→ {msg}{RESET}")
def title(msg): print(f"\n{BOLD}{msg}{RESET}\n")
def warn(msg, **kwargs):
    print(f"{YELLOW}⚠ {msg}{RESET}", **kwargs)

_CLIPBOARD_WIPE_SECONDS = 30

def copy_to_clipboard(text: str, wipe_after: int = _CLIPBOARD_WIPE_SECONDS) -> bool:
    try:
        import pyperclip
        pyperclip.copy(text)

        def _wipe():
            time.sleep(wipe_after)
            try:

                if hmac.compare_digest(pyperclip.paste(), text):
                    pyperclip.copy("")
            except Exception:
                pass

        t = threading.Thread(target=_wipe, daemon=True)
        t.start()
        return True
    except ImportError:
        warn("pyperclip não instalado — instale com: pip install pyperclip")
        return False
    except Exception as e:
        warn(f"Erro ao acessar clipboard: {e}")
        return False

def ask_passphrase(confirm: bool = False, label: str = "Passphrase", min_length: int = 0) -> str:
    while True:
        passphrase = getpass.getpass(f"{CYAN}🔑 {label}: {RESET}")

        if not passphrase.strip():
            err("Passphrase não pode ser vazia.")
            continue

        if min_length and len(passphrase) < min_length:
            err(f"Muito curto. Use pelo menos {min_length} caracteres.")
            continue

        analysis = estimate_passphrase_entropy(passphrase)
        print(f"   Entropia: {BOLD}{analysis['bits']} bits{RESET} — {analysis['strength']}")
        for w in analysis["warnings"]:
            warn(f"   {w}")

        if confirm:
            if analysis["bits"] < 40:
                warn("Passphrase fraca. Deseja continuar mesmo assim? [s/N]: ", end="")
                if input().strip().lower() != "s":
                    continue

            passphrase2 = getpass.getpass(f"{CYAN}🔑 Confirme {label}: {RESET}")

            if not hmac.compare_digest(passphrase, passphrase2):
                err("Passphrases não coincidem. Tente novamente.")
                continue

        return passphrase

def cmd_create(vault_path: str):
    title("🆕  Criar novo cofre")

    vaultkey_path = vault_path.replace(".vault", ".vaultkey")
    if not vault_path.endswith(".vault"):
        vaultkey_path = vault_path + ".vaultkey"
        vault_path = vault_path + ".vault"

    if os.path.exists(vault_path):
        err(f"Arquivo já existe: {vault_path}")
        return

    print("A passphrase é sua senha principal. Use uma frase com 4+ palavras.")
    print("Exemplo: minha_vó!café_1987_lua\n")

    passphrase = ask_passphrase(confirm=True)

    print("\nDefina um PIN para proteger o arquivo de recuperação (.vaultkey).")
    print(f"(mínimo {MIN_PIN_LENGTH} caracteres, pode ser diferente da passphrase principal)\n")
    vaultkey_pin = ask_passphrase(confirm=True, label="PIN do .vaultkey", min_length=MIN_PIN_LENGTH)

    info("Derivando chave com Argon2id (pode demorar alguns segundos)...")
    mnemonic_phrase, vaultkey_content = create_vault(passphrase, vault_path, vaultkey_pin)

    fd = os.open(vaultkey_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(vaultkey_content)

    ok(f"Cofre criado: {vault_path}")
    ok(f"Chave de recuperação salva: {vaultkey_path}")

    _display_mnemonic_with_clear(mnemonic_phrase)

def cmd_open(vault_path: str):
    title("🔓  Abrir cofre")
    passphrase = getpass.getpass(f"{CYAN}🔑 Passphrase: {RESET}")
    try:
        info("Derivando chave...")
        contents, kdf_key = open_vault_with_passphrase(passphrase, vault_path)

    except VaultLockError as e:
        err(str(e))
        return
    except ValueError as e:
        err(str(e))
        return
    except FileNotFoundError as e:
        err(str(e))
        return
    ok("Cofre aberto!\n")

    _print_custody_reminder()

    try:
        vault_menu(contents, kdf_key, vault_path)
    finally:

        secure_zero(kdf_key)

def cmd_recover(vault_path: str, vaultkey_path: str):
    title("🔄  Recuperar cofre")
    print("Digite o PIN de proteção do arquivo .vaultkey:")
    vaultkey_pin = getpass.getpass(f"{CYAN}🔑 PIN do .vaultkey: {RESET}")
    try:
        contents, kdf_key = open_vault_with_recovery_file(vaultkey_path, vault_path, vaultkey_pin)
        secure_zero(kdf_key)
    except FileNotFoundError as e:
        err(f"Arquivo não encontrado: {e}")
        return
    except PermissionError as e:
        err(f"Sem permissão para ler o arquivo: {e}")
        return
    except ValueError as e:
        err(f"PIN incorreto ou arquivo corrompido: {e}")
        return
    except OSError as e:
        err(f"Erro de disco ou sistema de arquivos: {e}")
        return
    except Exception as e:
        err(f"Falha inesperada na recuperação: {e}")
        return
    ok("Cofre recuperado!\n")

    print(f"\n{BOLD}{'─'*60}{RESET}")
    warn("REKEY OBRIGATÓRIO: defina nova passphrase e um novo PIN.")
    warn("Isso invalida o mnemônico atual e gera credenciais novas.")
    print(f"{BOLD}{'─'*60}{RESET}\n")

    print("Nova passphrase para o cofre:")
    new_passphrase = ask_passphrase(confirm=True)
    print(f"\nNovo PIN para o novo arquivo .vaultkey (mínimo {MIN_PIN_LENGTH} caracteres):")
    new_pin = ask_passphrase(confirm=True, label="Novo PIN do .vaultkey", min_length=MIN_PIN_LENGTH)

    vaultkey_path_new = vault_path.replace(".vault", ".vaultkey")

    info("Rotacionando credenciais (Argon2id — pode demorar alguns segundos)...")
    try:

        new_mnemonic, new_vaultkey_content = rotate_master_key(
            old_passphrase=None,
            new_passphrase=new_passphrase,
            vault_path=vault_path,
            vaultkey_pin=new_pin,
            contents=contents,
        )
    except VaultLockError as e:
        err(str(e))
        return
    except ValueError as e:
        err(str(e))
        return

    fd = os.open(vaultkey_path_new, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(new_vaultkey_content)

    ok("Credenciais rotacionadas com sucesso!")
    ok(f"Novo .vaultkey salvo em: {vaultkey_path_new}")

    _display_mnemonic_with_clear(new_mnemonic, label="NOVAS 24 PALAVRAS — AS ANTERIORES SÃO INVÁLIDAS")

    contents2, kdf_key2 = open_vault_with_passphrase(new_passphrase, vault_path)
    try:
        vault_menu(contents2, kdf_key2, vault_path)
    finally:
        secure_zero(kdf_key2)

def cmd_rekey(vault_path: str):
    title("🔁  Rotação completa de credenciais")
    warn("Este comando gera uma NOVA chave mestra e um NOVO mnemônico de 24 palavras.")
    warn("O arquivo .vaultkey antigo se tornará inválido.\n")

    old_passphrase = getpass.getpass(f"{CYAN}🔑 Passphrase atual: {RESET}")
    print("\nNova passphrase:")
    new_passphrase = ask_passphrase(confirm=True)
    print("\nNovo PIN para o novo .vaultkey:")
    new_pin = ask_passphrase(confirm=True, label="Novo PIN do .vaultkey", min_length=MIN_PIN_LENGTH)

    vaultkey_path = vault_path.replace(".vault", ".vaultkey")

    info("Rotacionando chave mestra com Argon2id (pode demorar alguns segundos)...")
    try:
        new_mnemonic, new_vaultkey_content = rotate_master_key(
            old_passphrase, new_passphrase, vault_path, new_pin
        )
    except VaultLockError as e:
        err(str(e))
        return
    except ValueError as e:
        err(str(e))
        return

    fd = os.open(vaultkey_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(new_vaultkey_content)

    ok("Chave mestra rotacionada com sucesso!")
    ok(f"Novo .vaultkey salvo em: {vaultkey_path}")

    _display_mnemonic_with_clear(new_mnemonic, label="NOVAS 24 PALAVRAS — AS ANTERIORES SÃO INVÁLIDAS")

def _display_mnemonic_with_clear(mnemonic_phrase: str, label: str = "GUARDE ESTAS 24 PALAVRAS") -> None:

    print(f"\n{BOLD}{'─'*60}")
    print(f"  🔐 {label}")
    print("  (papel físico, cofre, nunca em foto ou nuvem)")
    print(f"{'─'*60}{RESET}\n")
    print(format_mnemonic_display(mnemonic_phrase))
    print(f"\n{BOLD}{'─'*60}{RESET}")
    input("\nPressione Enter para APAGAR as palavras da tela...")

    word_lines = (len(mnemonic_phrase.split()) // 4) + 8
    print(f"\033[{word_lines}A\033[J", end="")
    ok("Mnemônico apagado da tela. Guarde-o em local seguro.")

def cmd_genpass():
    title("🎲  Gerador de Senhas")
    try:
        length = int(input("Tamanho da senha [20]: ").strip() or "20")
    except ValueError:
        length = 20
    use_upper   = input("Incluir maiúsculas? [S/n]: ").strip().lower() != "n"
    use_digits  = input("Incluir números? [S/n]: ").strip().lower() != "n"
    use_symbols = input("Incluir símbolos? [S/n]: ").strip().lower() != "n"

    pwd = generate_password(length, use_upper, use_digits, use_symbols)
    analysis = estimate_passphrase_entropy(pwd)

    print(f"\n{BOLD}Senha gerada:{RESET}")
    print(f"  {GREEN}{pwd}{RESET}")
    print(f"  Entropia: {analysis['bits']} bits — {analysis['strength']}")

    if copy_to_clipboard(pwd):
        ok(f"Copiado para o clipboard! (será apagado em {_CLIPBOARD_WIPE_SECONDS}s)")

def cmd_rebind(vault_path: str):
    title("🔗  Vincular cofre a esta máquina")
    warn("Isso sobrescreve o vínculo anterior. Use ao transferir o cofre para uma nova máquina.")
    passphrase = getpass.getpass(f"{CYAN}🔑 Passphrase: {RESET}")
    try:
        rebind_vault(passphrase, vault_path)
        ok("Cofre vinculado a esta máquina com sucesso.")
    except ValueError as e:
        err(str(e))
    except FileNotFoundError as e:
        err(str(e))

def _print_custody_reminder():
    print(f"\n{YELLOW}{'─'*60}")
    print("  💼 LEMBRETE DE CUSTÓDIA")
    print("  Se um responsável pelo cofre saiu da equipe ou houve")
    print("  qualquer troca de custódia, execute:")
    print(f"  {BOLD}python cli.py rekey <arquivo.vault>{RESET}{YELLOW}")
    print("  Isso invalida criptograficamente cópias em mãos antigas.")
    print(f"{'─'*60}{RESET}\n")

def vault_menu(contents: dict, kdf_key: bytearray, vault_path: str):
    while True:
        entries = contents.get("entries", [])
        n = len(entries)

        print(f"\n{BOLD}📦 Cofre — {n} entrada(s){RESET}")
        print("  [1] Listar entradas")
        print("  [2] Ver senha de uma entrada")
        print("  [3] Adicionar entrada")
        print("  [4] Deletar entrada")
        print("  [5] Gerar senha segura")
        print("  [0] Sair (salva automaticamente)")

        choice = input(f"\n{CYAN}Escolha: {RESET}").strip()

        if choice == "1":
            list_entries(entries)
        elif choice == "2":
            show_entry(entries)
        elif choice == "3":
            contents = menu_add_entry(contents)
            try:

                save_vault_with_key(contents, kdf_key, vault_path)
                ok("Entrada adicionada e cofre salvo.")
            except VaultLockError as e:
                err(f"Não foi possível salvar: {e}")
        elif choice == "4":
            contents = menu_delete_entry(contents)
            try:
                save_vault_with_key(contents, kdf_key, vault_path)
                ok("Entrada deletada e cofre salvo.")
            except VaultLockError as e:
                err(f"Não foi possível salvar: {e}")
        elif choice == "5":
            cmd_genpass()
        elif choice == "0":
            try:
                save_vault_with_key(contents, kdf_key, vault_path)
                ok("Cofre salvo. Até logo! 👋")
            except VaultLockError as e:
                err(f"Não foi possível salvar: {e}")
            break
        else:
            warn("Opção inválida.")

def list_entries(entries: list):
    if not entries:
        warn("Nenhuma entrada no cofre.")
        return
    print(f"\n{'#':<4} {'Nome':<20} {'Usuário':<25} {'URL'}")
    print("─" * 70)
    for i, e in enumerate(entries, 1):
        print(f"{i:<4} {e['name']:<20} {e['username']:<25} {e.get('url', '')}")

def show_entry(entries: list):
    if not entries:
        warn("Nenhuma entrada no cofre.")
        return
    list_entries(entries)
    try:
        idx = int(input(f"\n{CYAN}Número da entrada: {RESET}").strip()) - 1
        entry = entries[idx]
    except (ValueError, IndexError):
        err("Entrada inválida.")
        return
    print(f"\n  Nome:    {entry['name']}")
    print(f"  Usuário: {entry['username']}")
    print(f"  URL:     {entry.get('url', '—')}")

    if copy_to_clipboard(entry['password']):
        ok(f"Senha copiada para o clipboard! (será apagada em {_CLIPBOARD_WIPE_SECONDS}s)")
    else:
        reveal = input("  Revelar senha? [s/N]: ").strip().lower()
        if reveal == "s":
            print(f"  Senha:   {BOLD}{entry['password']}{RESET}")
        else:
            print(f"  Senha:   {'*' * len(entry['password'])}")

def menu_add_entry(contents: dict) -> dict:
    print(f"\n{BOLD}➕ Nova entrada{RESET}")
    name     = input("  Nome (ex: GitHub): ").strip()
    username = input("  Usuário/Email: ").strip()
    url      = input("  URL (opcional): ").strip()
    print("  Senha: [1] Digitar  [2] Gerar automaticamente")
    choice = input("  Escolha [2]: ").strip() or "2"
    if choice == "2":
        password = generate_password()
        print(f"  Senha gerada: {GREEN}{password}{RESET}")
        if copy_to_clipboard(password):
            ok(f"  Copiado para clipboard! (será apagado em {_CLIPBOARD_WIPE_SECONDS}s)")
    else:
        password = getpass.getpass("  Senha: ")
    return add_entry(contents, name, username, password, url)

def menu_delete_entry(contents: dict) -> dict:
    entries = contents.get("entries", [])
    if not entries:
        warn("Nenhuma entrada para deletar.")
        return contents
    list_entries(entries)
    try:
        idx = int(input(f"\n{CYAN}Número da entrada para deletar: {RESET}").strip()) - 1
        entry = entries[idx]
    except (ValueError, IndexError):
        err("Entrada inválida.")
        return contents
    confirm = input(f"  Deletar '{entry['name']}'? [s/N]: ").strip().lower()
    if confirm == "s":
        return delete_entry(contents, entry["id"])
    else:
        info("Cancelado.")
        return contents

def usage():
    print(f"""
{BOLD}key_lock — Cofre de Senhas v2.4{RESET}

Uso:
  python cli.py create  <arquivo.vault>
  python cli.py open    <arquivo.vault>
  python cli.py recover <arquivo.vault> <arquivo.vaultkey>
  python cli.py rekey   <arquivo.vault>        (rotação completa de credenciais)
  python cli.py rebind  <arquivo.vault>        (vincular cofre a esta máquina)
  python cli.py genpass
""")

def main():
    args = sys.argv[1:]
    if not args:
        usage()
        sys.exit(0)
    cmd = args[0].lower()
    try:
        if cmd == "create" and len(args) == 2:
            cmd_create(args[1])
        elif cmd == "open" and len(args) == 2:
            cmd_open(args[1])
        elif cmd == "recover" and len(args) == 3:
            cmd_recover(args[1], args[2])
        elif cmd == "rekey" and len(args) == 2:
            cmd_rekey(args[1])
        elif cmd == "rebind" and len(args) == 2:
            cmd_rebind(args[1])
        elif cmd == "genpass":
            cmd_genpass()
        else:
            usage()
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrompido pelo usuário.{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
