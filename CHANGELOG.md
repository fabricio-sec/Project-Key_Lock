# Changelog — key_lock

Todas as mudanças notáveis neste projeto são documentadas aqui.

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).
Versionamento seguindo [SemVer](https://semver.org/lang/pt-BR/).

---

## [2.4.2] — junho 2026

Versão de segurança — corrige todos os 12 achados da auditoria externa de junho/2026.

### Segurança (crítico)

- **[Achado #1] Anti-rollback fail-closed** (`core/meta.py`, `core/vault.py`): `check_and_update_meta` agora bloqueia a abertura do cofre por padrão quando o arquivo de metadata está ausente, corrompido ou com HMAC inválido. Antes, corromper o arquivo (ex.: truncar) era suficiente para bypass silencioso do anti-rollback sem precisar do `machine_secret.key`. Novo parâmetro `force_accept_meta=True` disponível nas funções `open_vault_with_passphrase`, `open_vault_with_recovery_file` e `open_vault_with_mnemonic` para aceitar metadata não verificado de forma explícita (com aviso emitido).

- **[Achado #2] `cmd_recover` crashava com TypeError** (`core/cli.py`): `vault_menu` era chamada com `(contents, new_passphrase, vault_path)` após o rekey, mas a assinatura esperava `(contents, kdf_key, vault_path)`. O cofre era salvo mas o menu pós-recovery crashava garantidamente em 100% dos casos. Corrigido para reabrir o cofre com a nova passphrase e obter o `kdf_key` correto.

- **[Achado #5] TOCTOU na aquisição do `VaultLock`** (`core/filelock.py`): substituído `_write_lock()` (que usava `O_TRUNC`, permitindo corrida entre read-then-write) por `_write_lock_exclusive()` com `O_CREAT|O_EXCL` — operação atômica no kernel que garante que apenas um processo adquire o lock. Adicionado `_force_remove_lock()` para remoção de locks stale de outros donos (sem verificação de token, que só faz sentido na liberação do próprio lock).

### Segurança (médio)

- **[Achado #3] GUI mascarava erros de integridade** (`gui.py`): `OpenVaultDlg._open` capturava `Exception` genérica e exibia sempre "Passphrase incorreta", escondendo erros de integridade (`ValueError` com mensagem de rollback), arquivo não encontrado (`FileNotFoundError`) e cofre em uso (`VaultLockError`). Agora cada tipo de exceção exibe mensagem específica.

- **[Achado #6] PIN sem validação de comprimento mínimo na GUI** (`gui.py`, `core/vault_format.py`): `CreateScreen`, `RekeyDlg` e os dois fluxos de recovery agora validam `len(pin) >= MIN_PIN_LENGTH` (8 caracteres) antes de prosseguir. `MIN_PIN_LENGTH` centralizado em `core/vault_format.py` e importado em todos os pontos de uso (GUI e CLI).

- **[Achado #8] PIN reutilizado como novo PIN do `.vaultkey` nos fluxos de recovery** (`gui.py`): `RecoverFileScreen` reutilizava o PIN *antigo* do `.vaultkey` como PIN do novo arquivo. `RecoverWordsScreen` usava a nova passphrase como PIN. Ambos os fluxos agora têm campos dedicados de novo PIN (com confirmação) e o arquivo `.vaultkey` é salvo em disco após rotação.

- **[Achado #11] `JSONDecodeError` escapava como exceção técnica** (`core/vault.py`): `_load_vault_file` agora captura `json.JSONDecodeError` e levanta `ValueError` com mensagem legível ("Arquivo .vault corrompido ou em formato inválido").

### Segurança (baixo)

- **[Achado #4] `VaultScreen._close()` não zerava segredos** (`gui.py`): fechamento manual do cofre (botão "Fechar") não chamava `secure_zero(kdf_key)`. Refatorado para método centralizado `_wipe_secrets()` usado em `_close()`, `_auto_lock()` e `_on_close_request()`.

- **[Achado #7] Cópias `bytes()` órfãs da master key** (`core/crypto.py`, `core/vault.py`, `gui.py`): todas as conversões `bytes(key)` desnecessárias removidas — `AESGCM`, `HKDF.derive` e `X25519` aceitam `bytearray` diretamente. As cópias imutáveis criadas por `bytes()` não podiam ser zeradas e ficavam na heap.

- **[Achado #9] Comparação de clipboard sem tempo constante** (`gui.py`): `widget.clipboard_get() == text` substituído por `hmac.compare_digest(widget.clipboard_get(), text)`.

- **[Achado #10] Ausência de `WM_DELETE_WINDOW`** (`gui.py`): fechar a janela pelo botão do SO não zerava segredos nem chamava `VaultScreen._wipe_secrets()`. Adicionado `root.protocol("WM_DELETE_WINDOW", self._on_close_request)` na classe `App`.

### Corrigido (funcional)

- **[Achado #12] `_focus_next_word` não movia o foco** (`gui.py`): corpo da função continha apenas `grid = self._word_vars[idx + 1]` (stub nunca completado). Corrigido para `self._word_entries[idx + 1].focus_set()`. Lista `self._word_entries` paralela à `self._word_vars` adicionada em `RecoverWordsScreen._build`.

### Testes

- `test_v231.py`: 65 testes cobrindo todos os 12 achados da auditoria + regressões de BUG-01 a BUG-08 + S-01 a S-03 + C-01 a C-05 + F-01 + exports de versão.

---



### Segurança

- **S-01 — AAD no `master_key_blob`** (`core/crypto.py`, `core/vault.py`): o blob da chave mestra cifrado com X25519+AES-GCM agora usa Additional Authenticated Data de domínio (`key_lock:master_key_blob:v2`). Sem esse AAD, um adversário com acesso a dois cofres que compartilhem a mesma chave pública de recovery poderia tentar substituição cruzada de `master_key_blob`. Com AAD, qualquer substituição falha na verificação GCM. `VAULT_VERSION` bumped para `4`. Retrocompatibilidade: vaults v3 são abertos com `use_aad=False` no caminho de recovery.

- **S-02 — Segredo de máquina unificado** (`core/meta.py`, `core/machine_bind.py`): o código anterior mantinha duas cópias do segredo de máquina — uma em `machine_bind.py` e outra em `meta.py`. Isso criava superfície duplicada e risco de inconsistência. Agora há uma única fonte de verdade: `core.machine_bind.get_machine_secret()`. `core/meta.py` delega para ela. Arquivo legado `~/.key_lock_meta/.machine_secret` pode ser removido com segurança.

- **S-03 — `save_vault_with_key`** (`core/vault.py`): nova função que aceita o `bytearray` da chave já derivada, eliminando a necessidade de re-derivar Argon2id a cada operação de save durante uma sessão CLI. Reduz o tempo que a `str` passphrase precisa existir na memória e evita a penalidade de tempo do Argon2id por save.

### Adicionado

- **C-01 — fail_count persistido em disco** (`core/meta.py`): o contador de tentativas erradas de passphrase agora sobrevive ao reinício do processo. Backoff exponencial (até 60 s) é aplicado com base no counter lido do arquivo `*_fail.json`, não apenas da sessão em memória. Counter é zerado após abertura bem-sucedida.

- **C-02 — Limite de tamanho no `.vaultkey`** (`core/vault.py`): `open_vault_with_recovery_file` rejeita arquivos `.vaultkey` maiores que 4096 bytes antes de carregar em memória. Um arquivo real tem ~400 bytes; o limite previne DoS por arquivo gigante ou malicioso.

- **C-03 — Limite de tamanho no `.vault`** (`core/vault.py`): `_load_vault_file` rejeita arquivos `.vault` maiores que 50 MB. Previne DoS por arquivo corrompido ou malicioso.

- **C-04 — Token de ownership no `VaultLock`** (`core/filelock.py`): o arquivo `.lock` agora inclui um token aleatório de 32 hex chars gerado por `secrets.token_hex`. `_remove_lock()` verifica o token antes de remover: só apaga o lock se for o titular. Previne remoção acidental de lock pertencente a outro processo.

- **C-05 — Rejeição de senha vazia em `add_entry`** (`core/vault.py`): entradas com campo `password` vazio são rejeitadas com `ValueError`. Evita criar entradas inutilizáveis silenciosamente.

- **F-01 — Comando `rebind`** (`core/cli.py`, `cli.py`): novo subcomando `python cli.py rebind <arquivo.vault>` que re-vincula o cofre à máquina atual. Útil após transferir o cofre para nova máquina sem copiar o `machine_secret.key`. Requer a passphrase para confirmar identidade antes de alterar o vínculo.

- **`core/__version__`**: exportações `__vault_version__` e `__vaultkey_version__` disponíveis em `core/__init__.py` para integradores e GUI sem necessidade de importar submodules diretamente.

### Corrigido

Todos os bugs abaixo foram documentados nos testes de regressão de `test_v231.py`:

- **BUG-01 — `cmd_rekey` ausente em `core/cli.py`**: a função existia embutida em outro fluxo mas não como função independente chamável pelo dispatcher `main()`. Extraída para função autônoma.

- **BUG-02 — `main()` ausente em `core/cli.py`**: o ponto de entrada `main()` estava faltando, tornando o módulo não-executável diretamente. Adicionado com dispatcher correto para todos os subcomandos.

- **BUG-03 — Corpo de `rekey` dentro de `_display_mnemonic_with_clear`**: lógica de rotação de credenciais estava misturada dentro da função de exibição do mnemônico, causando execução dupla e comportamento incorreto. Separados em funções independentes.

- **BUG-04 — `sys.path.insert(0, dirname(__file__))` em `core/cli.py`**: inserção do diretório `core/` no início do `sys.path` fazia `import mnemonic` encontrar `core/mnemonic.py` (arquivo local) antes do pacote pip `mnemonic`, causando `AttributeError` em runtime. Linha removida; o `sys.path` correto é configurado pelo `cli.py` raiz.

- **BUG-05 — Double-free em `rebind_vault`**: `secure_zero(kdf_key)` era chamado tanto no bloco `except` quanto no `finally`, zerando o buffer duas vezes. Chamada do `except` removida; apenas o `finally` zera.

- **BUG-06 — TOCTOU em `get_machine_secret`** (`core/machine_bind.py`): padrão `if path.exists(): ... path.read_bytes()` não é atômico — outro processo pode substituir o arquivo entre as duas chamadas. Corrigido para `try: path.read_bytes() except FileNotFoundError: criar`.

- **BUG-07 — Colisão em `_meta_path`** (`core/meta.py`): `_meta_path` usava apenas o `stem` do arquivo, fazendo dois cofres com o mesmo nome em diretórios diferentes compartilhar o mesmo metadata — permitindo bypass de anti-rollback cruzado. Corrigido com prefixo de 16 hex chars do SHA-256 do path resolvido.

- **BUG-08 — `VAULTKEY_VERSION` < 3 sem AAD**: o formato `.vaultkey` v2 não tinha AAD de domínio, permitindo substituição cruzada de ciphertext entre `.vaultkey` e `vault_blob`. `VAULTKEY_VERSION` bumped para `3` com `_VAULTKEY_AAD = b"key_lock:vaultkey_blob:v2"`.

### Testes

- `test_v231.py`: suíte de regressão com testes unitários cobrindo todos os fixes e controles acima, executáveis sem dependências externas via mocks.

---

## [2.3.1] — 2026

### Corrigido

- Parâmetros Argon2id do `.vaultkey` elevados de `time=2, mem=32 MB` para `time=4, mem=256 MB` — idênticos ao cofre principal. O arquivo de recuperação protegia o mnemônico completo com parâmetros ~16x mais fracos.
- Estimador de entropia de passphrase endurecido: penalidades reais para padrões humanos (l33t, anos, sufixos comuns). Estimativa anterior superestimava fortemente passphrases como `Senha@2024` (~80 bits → ~30 bits reais).
- AAD adicionado ao blob do `.vaultkey` (`_VAULTKEY_AAD`). `VAULTKEY_VERSION` bumped para `3`.
- `_meta_path` com hash do caminho para evitar colisão entre cofres homônimos.

---

## [2.2.0] — 2026

### Adicionado

- **Vinculação de cofre por máquina** (`core/machine_bind.py`): `HMAC-SHA256(machine_secret, salt)` armazenado como `machine_tag` no vault. Cofre roubado sem `machine_secret.key` não abre em outra máquina.
- **Thread-safety no `VaultLock`**: `threading.Lock` por caminho de vault para proteção intra-processo, complementando o file lock inter-processo.
- **Botão "🔗 Vincular esta máquina"** na GUI.
- `Pillow>=10.0.0` adicionado ao `requirements.txt` para preview de imagens.

### Corrigido

- Timeout de inatividade aumentado de 5 para 10 minutos.
- Bug: popup "sessão expirada" no menu inicial — `_close()` cancela timer antes de sair.
- Bug: força da senha inconsistente no gerador — `machine_generated=True` desativa penalidades estruturais para senhas automáticas.
- Deadlock em `test_concurrent_save_vault_raises` — `barrier.wait()` movida para antes do `with VaultLock`.
- Verificação duplicada `if not mp.exists()` em `get_meta_status()` removida.

---

## [2.1.0] — 2025

### Adicionado

- **File locking** (`core/filelock.py`): previne corrupção silenciosa por acesso simultâneo. `VaultLockError` com PID, hostname e tempo de posse do lock atual.
- **Escritas atômicas**: `tmp + os.replace()` em todos os `.vault` e metadata.
- **Permissões `0o600`** em `.vault`, `.vaultkey`, `.lock` e metadata.
- **Metadata anti-rollback com HMAC** (`core/meta.py` v2): HMAC-SHA256 com `machine_secret` de 256 bits.
- **Rotação completa de credenciais** (`rotate_master_key`, `cli.py rekey`): nova chave, novo salt, novo mnemônico.
- **Auto-wipe de clipboard**: senhas apagadas automaticamente após 30 segundos.
- `SECURITY.md` e `THREAT_MODEL.md` adicionados.

---

## [2.0.0] — 2025

### Segurança (breaking changes)

- **FIX #1 — X25519 substitui Ed25519**: Ed25519 é algoritmo de assinatura; usar sua chave pública como material de cifração é categoria de erro. X25519 (variante DH da Curve25519) com Ephemeral-Static ECDH + HKDF-SHA256 substituiu a abordagem anterior.

- **FIX #4 — Argon2id endurecido**: `memory_cost: 64 MB → 256 MB`, `time_cost: 3 → 4`. Força bruta offline 4x mais cara por tentativa em hardware de commodity.

- **FIX #5 — Higiene de memória**: chaves derivadas armazenadas como `bytearray`; `secure_zero()` implementado para zeragem best-effort após uso.

- **AAD de domínio** em `vault_blob`: `b"key_lock:vault_blob:v2"` adicionado. `VAULT_VERSION` bumped para `3`.

### Adicionado

- `core/passphrase.py`: módulo dedicado para `generate_password()` e `estimate_passphrase_entropy()` (movidos de `core/crypto.py`; re-exportados de lá para compatibilidade).
- Gerador de senhas usa `secrets` module (CSPRNG).
- `core/mnemonic.py`: `format_mnemonic_display()` para exibição numerada em grade.
- `HKDF_INFO_RECOVERY = b"key_lock recovery key v2 x25519"` para separação de domínio no HKDF.

---

## [1.x] — 2024–2025

Versão inicial. Usava Ed25519 para recovery (categoria de erro), Argon2id com parâmetros menores, sem file locking, sem escritas atômicas e sem metadata anti-rollback. Não há suporte ativo para esta linha de versão.
