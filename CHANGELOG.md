## [2.4.6] — julho 2026

Versão de segurança — corrige os 11 achados da auditoria de segurança e revisão de código de 02/07/2026 (relatório `AUDITORIA-Key_Lock-v2.4.5.md`), incluindo a causa raiz do relato de que a recuperação por 24 palavras "parava de funcionar" após uma falha na primeira tentativa.

### Segurança (crítico)

- **[N-01] Escrita irreversível em disco antes de operações que podem falhar em `rotate_master_key()`/`create_vault()`** (`core/vault.py`): as duas funções gravavam o novo `.vault` em disco (via `_atomic_write`) **antes** de gerar o novo mnemônico (`private_key_to_mnemonic`) e o novo `.vaultkey` (`build_vaultkey_file`). Se qualquer uma dessas duas chamadas falhasse — cenário real e não hipotético, por exemplo sob pressão de memória durante o segundo Argon2id de `build_vaultkey_file`, que aloca mais 256 MB logo após a derivação já feita minutos antes — o cofre já tinha sido re-chaveado no disco, mas o mnemônico antigo era invalidado e o novo nunca chegava a existir/ser exibido. Isso explica o relato de "a recuperação pelas 24 palavras não funciona quando se erra pela primeira vez": tecnicamente, da segunda tentativa em diante as palavras antigas realmente deixavam de ser válidas. Corrigido: ambas as funções agora geram e validam **tudo** que pode falhar (mnemônico + `.vaultkey`) antes de tocar o disco; a persistência acontece como último passo, já atômico via `os.replace`.

### Segurança (alto)

- **[N-02] Fluxos de recuperação descartavam o novo mnemônico gerado, mesmo em caso de sucesso** (`gui.py` — `RecoverFileScreen`, `RecoverWordsScreen`): mesmo quando a recuperação funcionava perfeitamente, o retorno de `rotate_master_key()` era descartado (`_, new_vaultkey = ...`) e o usuário nunca via as novas 24 palavras — diferente de `RekeyDlg`/`_InlineRekey`, que já exibiam corretamente via `MnemonicDlg`. Corrigido: os dois fluxos de recuperação agora capturam `new_mnemonic` e exibem `MnemonicDlg` antes de entrar no cofre, no mesmo padrão já usado pela rotação normal de chaves.

- **[N-03] `.vaultkey` gravado com permissão de arquivo insegura em toda a GUI** (`gui.py`, 5 locais): `CreateScreen`, `RecoverFileScreen`, `RecoverWordsScreen`, `RekeyDlg` e `_InlineRekey` usavam `open(vaultkey_path, "w")` simples, criando o arquivo com a permissão padrão do umask do sistema (tipicamente `0644` — legível por outros usuários locais), ao contrário da CLI, que já usava `os.open(..., 0o600)` corretamente. Corrigido: novo helper único `write_vaultkey_file()` em `core/vault_format.py`, reaproveitado pelos 5 pontos da GUI e pelos 3 pontos equivalentes da CLI, sempre com permissão `0600` desde a criação do arquivo.

### Segurança (médio)

- **[N-04] Crash não tratado (`TclError`) no medidor de força de senha/PIN, em 5 telas** (`gui.py`): o callback de `trace_add` ligado ao `StringVar` da nova passphrase/PIN tinha seu ramo de valor vazio fora do `try/except`; como o `StringVar` sobrevive à destruição da tela (mantido vivo pelo próprio trace), um valor `.set()` recebido após a troca de tela disparava um `TclError` não tratado — reproduzido de forma determinística no fluxo de recuperação por 24 palavras usando Tkinter real sob `Xvfb`. Corrigido: novo helper único `_bind_strength_meter()`, com guarda `winfo_exists()` e todo o corpo do callback dentro do `try/except`, reaproveitado nas 5 telas afetadas (`CreateScreen`, `RecoverFileScreen`, `RecoverWordsScreen`, `RekeyDlg`, `_InlineRekey`).

- **[N-05] `.vault` malformado causava `AttributeError`/`KeyError` não tratado** (`core/vault.py`, `core/cli.py`): `_load_vault_file` não validava que o JSON de nível superior era um objeto nem que os campos obrigatórios (`salt`, `master_key_blob`, `vault_blob`) existiam antes de acessá-los — um `.vault` corrompido (ex: JSON válido mas com estrutura errada) gerava traceback cru na CLI (`cmd_open`, `cmd_rebind` não tinham handler genérico). Corrigido: validação de estrutura logo após o parse do JSON, levantando `ValueError` amigável e consistente com o padrão já usado para JSON inválido.

### Segurança (baixo)

- **[N-06] Vazamento de event bindings globais (`bind_all`) a cada ciclo de abrir/fechar cofre** (`gui.py` — `VaultScreen`): `bind_all("<Any-KeyPress>"/"<Any-Button>")` registra o callback na janela raiz do Tk, não no widget da instância; `App._set()` destruía o frame antigo sem desfazer esses binds, acumulando handlers "zumbis" a cada reabertura (incluindo auto-lock por inatividade). Corrigido: novo método `_unbind_activity()`, chamado em `_close()` e `_auto_lock()`, mais uma rede de segurança adicional em `App._set()` que desfaz os binds de qualquer `VaultScreen` sendo substituída.

- **[N-07] Corrida na criação do `machine_secret.key` na primeira execução** (`core/machine_bind.py`): `get_machine_secret()` usava `O_CREAT|O_TRUNC`, permitindo que duas primeiras-execuções concorrentes gerassem segredos diferentes e cada uma retornasse o seu, mesmo que só um fosse persistido — causando `machine_tag` mismatch espúrio no processo "perdedor". Corrigido: `O_CREAT|O_EXCL`; em caso de `FileExistsError`, o segredo já persistido é relido do disco em vez de confiar no valor gerado localmente. Validado sob concorrência real de 8 threads.

- **[N-08] Falha silenciosa podia desativar a verificação de machine-binding sem aviso** (`core/vault.py`): um erro inesperado (não `MachineMismatchError`) durante a leitura do `machine_secret` era engolido por um `except Exception: pass` totalmente silencioso. Corrigido: emite `warnings.warn()` não-fatal, mantendo o comportamento de não bloquear a abertura (machine binding continua sendo defesa em profundidade, não barreira dura — THREAT_MODEL T-01), mas tornando o problema visível.

### Informacional

- **[N-09] Medidor de força do PIN do `.vaultkey` só existia em `CreateScreen`** (`gui.py`): `RecoverFileScreen`, `RecoverWordsScreen`, `RekeyDlg` e `_InlineRekey` validavam apenas o comprimento mínimo do novo PIN, sem indicação visual de força — justamente nos fluxos de recuperação/rotação, onde o usuário está sob mais pressão. Corrigido: as 4 telas agora ligam o mesmo `_bind_strength_meter()` também ao campo de PIN.

- **[N-10] `add_entry` não limitava o tamanho do campo `password`** (`core/vault.py`): `name`/`username`/`url` já tinham teto de comprimento; `password` não. Adicionado limite de 4096 caracteres, consistente com os demais campos.

- **[N-11] Dependências sem teto de versão** (`requirements.txt`): todas as dependências usavam apenas limite inferior aberto. Adicionado teto de versão (compatible release) a cada uma, reduzindo o risco de uma major release incompatível — ou comprometida via supply chain — ser instalada silenciosamente. Documentado no próprio arquivo como gerar um lockfile com hashes (`pip-compile --generate-hashes`) para builds de release reprodutíveis.

### Testes

- Suíte de regressão expandida de 108 para 141 casos (seções 41–51), com um teste nomeado por achado, incluindo reprodução comportamental de N-01 (falha simulada pós-escrita não deixa nenhuma mutação no `.vault`), N-04 (Tkinter real sob `Xvfb`, sem `TclError`), N-05, N-07 (concorrência real de 8 threads) e N-08.

---



Versão de segurança — corrige achados da auditoria adversarial de follow-up (junho/2026).

### Segurança (crítico)

- **[R-01] Rollback completo via deleção do metadata** (`core/meta.py`): `check_and_update_meta` recriava o arquivo de metadata silenciosamente quando ele estava ausente, independente do estado do cofre. Isso permitia um ataque em 3 passos: (1) remover `machine_tag` do .vault JSON; (2) substituir o .vault por versão antiga; (3) deletar o arquivo de metadata. O cofre abria sem bloqueio e sem erro. Corrigido: se o metadata está ausente e o cofre já contém entradas ou arquivos (`has_data = True`), a abertura é bloqueada com mensagem de aviso explícita. Cofres recém-criados sem dados ainda aceitam ausência de metadata (primeira abertura legítima).

### Segurança (médio)

- **[P-01] Type confusion em `version` causa TypeError não tratado** (`core/vault.py`): se um atacante modificar o campo `version` do .vault para string (ex: `"4"` em vez de `4`), as comparações `outer_version >= 3` e `outer_version >= 4` levantavam `TypeError` não capturado, crashando o processo sem mensagem amigável e sem incrementar o fail_count. Corrigido em `_load_vault_file`: o tipo de `version` é validado após parse do JSON; tipo não-inteiro levanta `ValueError` com mensagem clara.

### Segurança (baixo)

- **[B-02] `vault_salt` no `.vaultkey` não era verificado** (`core/vault.py`): `open_vault_with_recovery_file` descartava o `vault_salt` retornado por `parse_vaultkey_file` (`_, = ...`), tornando esse campo metadado inútil que dava falsa impressão de vínculo entre `.vaultkey` e `.vault`. Corrigido: o `vault_salt` do `.vaultkey` é comparado com o `salt` real do `.vault`. Se divergirem, abertura é bloqueada com mensagem "O arquivo .vaultkey não pertence a este cofre .vault."

- **[M-01] `pin_key` era `bytes` imutável, não podia ser zerado** (`core/vault_format.py`): `_derive_pin_key` retornava `bytes` (imutável). O `pin_key` derivado do PIN do usuário ficava na heap até o GC sem possibilidade de zeragem. Corrigido: `_derive_pin_key` agora retorna `bytearray`. Blocos `try/finally` em `build_vaultkey_file` e `parse_vaultkey_file` zeram o `pin_key` após uso.

### Informacional

- **[T-01] `machine_secret` é raiz de confiança dupla** (THREAT_MODEL.md, SECURITY.md): documentado explicitamente que o mesmo `machine_secret` é usado tanto para o `machine_tag` no .vault quanto para o HMAC do metadata anti-rollback. Quem possui o `machine_secret` pode forjar ambos. Isso é uma limitação aceita de design (portabilidade sem dependência de keychain do SO), agora documentada explicitamente nas seções de limitações.

### Ataques investigados e descartados

- **Cross-vault blob substitution**: substituição cruzada de `vault_blob` ou `master_key_blob` entre cofres com salts diferentes é bloqueada pelo GCM authentication tag (chaves distintas). Confirmado por PoC.
- **Rollback via vault mais novo + metadata mais antigo**: `vault_ts > meta_min` atualiza o metadata silenciosamente (comportamento correto). Não é ataque, é operação normal.
- **Old vaultkey + new vault após rekey**: bloqueado corretamente — o mnemônico antigo não decifra o `master_key_blob` novo. Confirmado por PoC.
- **Substituição de vault_blob entre cofres com mesmo salt**: matematicamente impossível (salt é gerado com `os.urandom`, probabilidade de colisão desprezível).

---

## [2.4.3] — junho 2026

Versão de segurança — corrige achados da auditoria externa de segurança completa (junho/2026).

### Segurança

- **[A-01] GUI: `_del_entry` e `_on_added` usavam `save_vault()` em vez de `save_vault_with_key()`** (`gui.py`): ao deletar ou adicionar entradas pela `VaultScreen`, o código chamava `save_vault(contents, self.passphrase, ...)`, que re-executa Argon2id (256 MB) desnecessariamente — ~1s de latência extra por operação — e mantém a `str` passphrase ativa por mais tempo no caminho crítico. Ambas as chamadas substituídas por `save_vault_with_key(contents, self.kdf_key, ...)`, eliminando a re-derivação e reduzindo a exposição da passphrase.

- **[A-02] `_FilesView._save()` usava `save_vault()` em vez de `save_vault_with_key()`** (`gui.py`): o mesmo problema de A-01 afetava o módulo de arquivos cifrados. O `kdf_key` já está disponível via `self._vs.kdf_key`. Corrigido.

- **[A-03] `RekeyDlg` sem confirmação de PIN** (`gui.py`): o diálogo de rotação de credenciais permitia que o usuário definisse o PIN do novo `.vaultkey` em campo único sem confirmação — um typo silencioso tornaria o arquivo inacessível. Adicionado campo "Confirmar PIN do .vaultkey" com validação antes de prosseguir.

- **[A-04] `parse_vaultkey_file` mensagem genérica para formato v1** (`core/vault_format.py`): arquivos `.vaultkey` versão 1 resultavam em erro genérico sem orientação. Adicionada mensagem específica explicando o formato legado e orientando uso do mnemônico de 24 palavras.

- **[A-05] Machine binding bypassável por remoção do campo `machine_tag`** (`core/vault.py`): a verificação de vínculo só ocorre quando `machine_tag` está presente. Um adversário com acesso ao JSON pode remover o campo e abrir o cofre em qualquer máquina. Comportamento documentado como limitação aceita no THREAT_MODEL, mas o código não alertava o usuário. Adicionado `warnings.warn()` quando o campo está ausente, orientando uso do `rebind`.

### Informacional

- **[A-06] Machine binding: limitação de bypass documentada explicitamente** (THREAT_MODEL.md): adversário com `.vault` + passphrase pode remover `machine_tag` e contornar o vínculo de máquina. A proteção é contra acesso *sem* a passphrase, não contra adversário que já possui as credenciais.

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
