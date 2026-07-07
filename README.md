# key_lock 🔐

**Cofre de senhas local com criptografia forte — Argon2id + AES-256-GCM + X25519**

Versão: `2.4.6` | Python ≥ 3.10 | Linux / macOS

---

## O que é

key_lock é um gerenciador de senhas que roda inteiramente no seu computador. Nenhum dado sai da máquina — não há servidor, nuvem ou conta obrigatória. Todos os segredos ficam num único arquivo `.vault` cifrado em disco.

---

## Funcionalidades

- **AES-256-GCM** com autenticação: qualquer adulteração do arquivo é detectada
- **Argon2id** (256 MB, 4 iterações) para derivação de chave — resistente a ataques de GPU e ASIC
- **Chave de recuperação X25519** codificada em 24 palavras BIP-39 — escrevível em papel
- **Arquivo `.vaultkey`** cifrado com PIN (mínimo 8 caracteres), protegendo o mnemônico em disco
- **Vinculação de máquina** via `machine_secret` — um cofre roubado não abre em outra máquina sem o segredo ou o mnemônico
- **Anti-rollback fail-closed** — metadata corrompido ou adulterado bloqueia abertura; substituição por backup antigo é detectada
- **Locking exclusivo** com `O_EXCL` e detecção de locks stale — previne corrupção por acesso simultâneo
- **Escritas atômicas** (`tmp` + `os.replace()`) — sem corrupção por crash ou queda de energia
- **Auto-wipe de clipboard** — senhas copiadas são apagadas automaticamente após 30 segundos
- **Gerador de senhas criptograficamente seguro** (`secrets` module)
- **Estimador de entropia** com penalidades reais para padrões humanos (l33t, anos, sufixos comuns)
- Interface **GUI** (Tkinter) e **CLI** disponíveis

---

## Requisitos

```
Python >= 3.10
argon2-cffi >= 21.3.0
cryptography >= 44.0.0
mnemonic >= 0.21
pyperclip >= 1.8.0   (opcional — clipboard auto-wipe)
Pillow >= 10.0.0     (opcional — preview de imagens na GUI)
```

```bash
pip install -r requirements.txt
```

---

## Início rápido — CLI

### Criar um cofre

```bash
python cli.py create meu_cofre.vault
```

1. Pedir uma passphrase (com medidor de entropia)
2. Pedir um PIN para proteger o arquivo `.vaultkey` (mínimo 8 caracteres)
3. Exibir as 24 palavras de recuperação — **anote-as em papel e guarde em local seguro**
4. Criar `meu_cofre.vault` e `meu_cofre.vaultkey`

### Abrir o cofre

```bash
python cli.py open meu_cofre.vault
```

### Recuperar acesso (sem a passphrase)

Via arquivo `.vaultkey` + PIN:

```bash
python cli.py recover meu_cofre.vault meu_cofre.vaultkey
```

Via as 24 palavras: o próprio `recover` oferece a opção interativamente.

### Rotacionar credenciais

Recomendado quando alguém que conhecia a passphrase sai da equipe:

```bash
python cli.py rekey meu_cofre.vault
```

Gera nova passphrase, novo salt Argon2id, nova chave X25519 e novo mnemônico. Todas as cópias antigas do cofre se tornam criptograficamente inválidas.

### Re-vincular a esta máquina

Quando o cofre foi transferido para uma nova máquina:

```bash
python cli.py rebind meu_cofre.vault
```

### Gerar uma senha aleatória

```bash
python cli.py genpass
```

---

## Início rápido — GUI

```bash
python gui.py
```

A interface gráfica oferece as mesmas operações da CLI com formulários visuais, gerenciador de entradas e timeout de inatividade (10 minutos). Ao fechar a janela, os segredos em memória são zerados automaticamente.

---

## Estrutura do projeto

```
key_lock/
├── cli.py                  # Ponto de entrada CLI (wrapper)
├── gui.py                  # Interface gráfica (Tkinter)
├── requirements.txt
├── test_v231.py            # Suíte de regressão (141 testes)
├── CHANGELOG.md
├── SECURITY.md
├── THREAT_MODEL.md
└── core/
    ├── __init__.py         # Versão do pacote (2.4.6)
    ├── crypto.py           # Primitivas: Argon2id, AES-GCM, X25519, HKDF
    ├── vault.py            # Lógica principal do cofre
    ├── vault_format.py     # Formato do arquivo .vaultkey
    ├── filelock.py         # Locking exclusivo de arquivo (O_EXCL)
    ├── meta.py             # Metadata anti-rollback com HMAC (fail-closed)
    ├── machine_bind.py     # Vinculação de cofre à máquina
    ├── mnemonic.py         # Conversão X25519 ↔ BIP-39
    ├── passphrase.py       # Gerador e estimador de entropia
    └── cli.py              # Implementação dos comandos CLI
```

---

## Formato do arquivo `.vault`

JSON cifrado com permissões `0o600`:

```json
{
  "version": 4,
  "salt": "<base64url — salt Argon2id>",
  "master_key_blob": "<base64url — X25519 ECDH + HKDF + AES-GCM>",
  "vault_blob": "<base64url — AES-256-GCM(entries, AAD)>",
  "machine_tag": "<hex — HMAC-SHA256(machine_secret, salt)>"
}
```

Retrocompatibilidade: versões 2, 3 e 4 são lidas. Migração para v4 ocorre automaticamente na primeira gravação.

---

## Formato do arquivo `.vaultkey`

String base64url opaca (JSON interno cifrado com PIN via Argon2id + AES-GCM). Contém o mnemônico de 24 palavras cifrado — sem o PIN, o arquivo é ilegível. Versão atual: `3`.

---

## Esquema criptográfico

```
Passphrase  ──Argon2id(256MB, t=4, p=4)──►  kdf_key (bytearray, 256 bits)
                                                  │
                                          AES-256-GCM + AAD
                                                  │
                                            vault_blob  ──► .vault

X25519 Keypair (recovery):
  eph_priv ──ECDH──► shared_secret ──HKDF-SHA256──► aes_key
  aes_key + AES-GCM + AAD ──► master_key_blob  ──► .vault

  Recovery: X25519(static_priv, eph_pub) ──HKDF──► aes_key ──AES-GCM──► kdf_key
```

Separação de domínio por AAD em todos os blobs:
- `key_lock:vault_blob:v2` — vault principal
- `key_lock:master_key_blob:v2` — blob da chave de recovery
- `key_lock:vaultkey_blob:v2` — arquivo .vaultkey

---

## Testes

```bash
python test_v231.py
```

141 testes cobrindo: todos os 12 achados da auditoria de segurança (v2.4.2), regressões de bugs (BUG-01 a BUG-08), controles criptográficos (S-01 a S-03), controles de operação (C-01 a C-05), achados das auditorias v2.4.3 (A-01 a A-06), v2.4.4 (B-01 a B-06) e v2.4.6 (N-01 a N-11).

---

## Aviso de segurança

- **Anote as 24 palavras de recuperação** na criação do cofre. Sem elas e sem a passphrase, o acesso é irrecuperável.
- **Use um PIN forte** (mínimo 8 caracteres) para o `.vaultkey` — é a única proteção do arquivo caso ele seja roubado.
- **Guarde o `machine_secret.key`** se for transferir o cofre para outra máquina (`~/.config/key_lock/machine_secret.key`).
- Use uma passphrase com pelo menos **60 bits de entropia** (o estimador interno avisa se for fraca).
- Execute `rekey` sempre que alguém que conhecia a passphrase deixar de ter acesso autorizado.

---

## Autor

Fabrício Almeida — [linkedin.com/in/fabrici04](https://www.linkedin.com/in/fabrici04/)

GitHub: [github.com/fabricio-sec](https://github.com/fabricio-sec)

Licença: ver arquivo `LICENSE` (se presente) ou contatar o autor.
