# Security Policy — key_lock

Versão da política: 2.4.6 | Atualizado: julho 2026

---

## Versões suportadas

| Versão | Suporte de segurança |
|--------|----------------------|
| 2.4.x  | ✅ Ativa             |
| 2.3.x  | ⚠️ Somente vulnerabilidades críticas |
| 2.2.x  | ❌ Sem suporte       |
| < 2.2  | ❌ Sem suporte       |

> Versão atual recomendada: **2.4.6**

Recomendação: atualize para a versão mais recente. Versões anteriores podem ter vulnerabilidades documentadas no CHANGELOG.

---

## Reportando uma vulnerabilidade

Se você encontrou uma vulnerabilidade de segurança no key_lock, **não abra uma issue pública**. Divulgação pública prematura expõe todos os usuários antes que uma correção esteja disponível.

### Processo de divulgação responsável

1. **Envie um e-mail privado** para `fabricioalmeida.sec@gmail.com` com:
   - Descrição clara da vulnerabilidade
   - Passos para reprodução (PoC se possível)
   - Versão afetada
   - Impacto esperado (confidencialidade, integridade, disponibilidade)
   - Sugestão de correção, se houver

2. Você receberá uma **confirmação em até 72 horas**.

3. Trabalharemos juntos para validar e corrigir o problema.

4. **Após a correção e release**, o problema será divulgado publicamente com crédito ao pesquisador (se desejado).

### Prazos esperados

| Severidade | Avaliação | Correção |
|------------|-----------|----------|
| Crítica    | 3 dias    | 14 dias  |
| Alta       | 7 dias    | 30 dias  |
| Média      | 14 dias   | 60 dias  |
| Baixa      | 30 dias   | Próxima release |

---

## Escopo

### Dentro do escopo

- Vulnerabilidades criptográficas em `core/crypto.py`, `core/vault.py`, `core/vault_format.py`
- Bypass de autenticação ou recuperação não autorizada de passphrase / mnemônico
- Corrupção ou vazamento de dados do cofre
- Leitura não autorizada de arquivos `.vault` ou `.vaultkey`
- Falhas no mecanismo anti-rollback (`core/meta.py`)
- Falhas no file locking que permitam corrupção silenciosa de dados
- Falhas de validação de entrada que permitam injeção ou corrupção
- Problemas de permissão de arquivo que exponham dados sensíveis a outros usuários

### Fora do escopo

- Ataques que requerem acesso físico à máquina com sessão ativa e cofre aberto
- Ataques de engenharia social ao usuário
- Vulnerabilidades em dependências de terceiros sem vetor de exploração direto no key_lock
- Bugs de interface (GUI/CLI) sem impacto de segurança
- Problemas de desempenho não relacionados a segurança

---

## Arquitetura de segurança

### Primitivas criptográficas

| Primitiva         | Uso                                       | Parâmetros                         |
|-------------------|-------------------------------------------|------------------------------------|
| Argon2id          | KDF da passphrase principal e do PIN      | 256 MB, t=4, p=4, 32 bytes output  |
| AES-256-GCM       | Cifração autenticada de todos os blobs    | Nonce de 96 bits por operação      |
| X25519 ECDH       | Cifração da chave mestra para recovery    | Efêmero-estático, fresh key/op     |
| HKDF-SHA256       | Derivação de chave do shared secret       | Salt aleatório de 128 bits         |
| HMAC-SHA256       | Integridade do metadata anti-rollback     | machine_secret de 256 bits         |
| BIP-39 (24 words) | Encoding humano da chave X25519 privada   | 256 bits de entropia               |

### Separação de domínio (AAD)

Todos os blobs AES-GCM usam Additional Authenticated Data distintos para impedir substituição cruzada entre contextos:

| Blob              | AAD                           | Introduzida em |
|-------------------|-------------------------------|----------------|
| `vault_blob`      | `key_lock:vault_blob:v2`      | v2.3.1         |
| `master_key_blob` | `key_lock:master_key_blob:v2` | v2.4.1 (S-01)  |
| blob `.vaultkey`  | `key_lock:vaultkey_blob:v2`   | v2.3.1         |

### Controles operacionais

| Controle | Descrição | Módulo |
|----------|-----------|--------|
| C-01 | fail_count persistido em disco — backoff exponencial sobrevive ao reinício | `core/meta.py` |
| C-02 | Limite de 4 KB para arquivo `.vaultkey` (prevenção de DoS) | `core/vault.py` |
| C-03 | Limite de 50 MB para arquivo `.vault` (prevenção de DoS) | `core/vault.py` |
| C-04 | Token de ownership no `VaultLock` — previne remoção de lock alheio | `core/filelock.py` |
| C-05 | Senha vazia rejeitada em `add_entry` | `core/vault.py` |
| C-06 | PIN do `.vaultkey` com mínimo de 8 caracteres (validado em GUI e CLI) | `core/vault_format.py` |
| C-07 | PIN do `.vaultkey` confirmado em todos os fluxos de criação/rotação na GUI | `gui.py` — `CreateScreen`, `RekeyDlg`, `RecoverFileScreen`, `RecoverWordsScreen` |
| C-08 | `save_vault_with_key` usado em todos os saves de sessão na GUI — elimina re-derivação Argon2id e reduz exposição da passphrase | `gui.py` — `VaultScreen`, `_FilesView` |

### Higiene de memória

- Chaves derivadas (output do Argon2id) são armazenadas como `bytearray` e zeradas com `secure_zero()` após uso
- Shared secrets X25519 são zerados imediatamente após a derivação HKDF
- Nenhuma conversão `bytes(key)` intermediária desnecessária — `bytearray` é passado diretamente para `AESGCM`, `HKDF` e demais APIs
- Na GUI, `_wipe_secrets()` é chamado em: timeout de inatividade (10 min), fechamento manual do cofre e fechamento da janela pelo SO (`WM_DELETE_WINDOW`)
- **Limitação documentada:** a passphrase como `str` Python é imutável e não pode ser zerada; persiste na heap até o GC coletar

### Anti-rollback (fail-closed desde v2.4.2)

- O arquivo de metadata (`~/.key_lock_meta/*.json`) é verificado por HMAC-SHA256 a cada abertura
- Metadata ausente, corrompido ou com HMAC inválido **bloqueia a abertura** por padrão
- `force_accept_meta=True` disponível para aceitar explicitamente, com aviso emitido
- O path do metadata inclui os primeiros 16 hex-chars do SHA-256 do path resolvido — previne colisão entre cofres homônimos em diretórios diferentes

### Proteções de sistema de arquivos

- Arquivos `.vault`, `.vaultkey`, `.lock` e metadata criados com permissões `0o600` (somente dono)
- Escritas atômicas via arquivo temporário + `os.replace()` — previne corrupção por crash
- `VaultLock` usa `O_CREAT | O_EXCL` para aquisição atômica do lock — elimina TOCTOU entre processos
- `machine_secret.key` criado com `os.open()` + `O_CREAT | O_EXCL | 0o600`

---

## Dependências críticas de segurança

| Pacote        | Uso                       | Versão mínima recomendada |
|---------------|---------------------------|---------------------------|
| `argon2-cffi` | Derivação de chave (KDF)  | ≥ 21.3.0                  |
| `cryptography` | AES-GCM, X25519, HKDF    | ≥ 44.0.0                  |
| `mnemonic`    | Encoding BIP-39           | ≥ 0.21                    |

Mantenha as dependências atualizadas. Vulnerabilidades em primitivas criptográficas (especialmente `cryptography`) podem afetar diretamente a segurança do cofre.

---

## Limitações conhecidas e aceitas

1. **Strings Python não são zeráveis.** A passphrase principal fica na heap durante a sessão. Aceito como limitação da plataforma.

2. **HMAC anti-rollback não resiste a adversário com acesso ao `machine_secret.key`.** Um atacante que consegue ler esse arquivo pode recriar o HMAC. É defesa em profundidade, não garantia absoluta.

3. **Sem suporte oficial a Windows.** `os.replace()` pode falhar com arquivo aberto por antivírus. Testado em Linux e macOS.

4. **O cofre não protege contra malware com privilégios equivalentes ao usuário.** Keyloggers, screen recorders e memory dumpers estão fora do escopo de proteção.
