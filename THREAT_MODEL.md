# Modelo de Ameaças — key_lock

Versão: 2.4.2 | Atualizado: junho 2026

---

## O que o key_lock protege

key_lock é um cofre de senhas local. Não há servidor, sincronização automática ou conta externa. Todos os segredos residem no arquivo `.vault` no disco do usuário, cifrado em repouso. O modelo de ameaças reflete essa postura: a segurança é garantida pelo que está no arquivo e pelas primitivas que o protegem — não por perímetros de rede.

---

## Ativos a proteger

| Ativo                        | Sensibilidade | Localização em repouso              |
|------------------------------|---------------|-------------------------------------|
| Senhas armazenadas           | Crítica       | `.vault` cifrado com AES-256-GCM    |
| Passphrase principal         | Crítica       | Memória durante sessão aberta (str) |
| Mnemônico de recuperação     | Crítica       | Papel físico e/ou `.vaultkey` cifrado |
| Chave privada X25519         | Crítica       | Derivada do mnemônico, não persistida diretamente |
| Chave derivada Argon2id      | Alta          | Memória (bytearray, zerada após uso) |
| `machine_secret.key`         | Alta          | `~/.config/key_lock/` com `0o600`   |
| Metadata anti-rollback       | Média         | `~/.key_lock_meta/` com HMAC        |

---

## Adversários e cenários

### ✅ PROTEGIDO — Adversário com acesso ao arquivo `.vault` (cofre fechado)

**Cenário:** Atacante obtém uma cópia do `.vault` — backup comprometido, HD roubado, armazenamento em nuvem onde o usuário sincronizou manualmente.

**Proteção:**
- Cifrado com AES-256-GCM: sem a chave correta, o ciphertext é ilegível e qualquer adulteração é detectada pela tag GCM.
- A chave é derivada via Argon2id (256 MB, t=4, p=4), tornando força bruta offline muito cara mesmo com hardware de ponta.
- A chave mestra de recovery é protegida por X25519 Ephemeral-Static ECDH: o atacante precisaria da chave privada do mnemônico para derivar a chave de sessão.
- `vault_blob` e `master_key_blob` usam AADs distintos (v2.4.0 S-01), impedindo substituição cruzada entre cofres que compartilhem a mesma chave pública de recovery.

**Limitação:** Se a passphrase tiver menos de ~40 bits de entropia real, força bruta offline se torna viável com hardware dedicado (GPU farm, ASIC).

---

### ✅ PROTEGIDO — Adversário com acesso ao arquivo `.vaultkey`

**Cenário:** O arquivo `.vaultkey` é obtido sem o PIN correspondente.

**Proteção:**
- O mnemônico dentro do `.vaultkey` é cifrado com AES-256-GCM usando chave derivada do PIN via Argon2id (mesmos parâmetros do cofre principal — 256 MB, t=4).
- Limite de tamanho de 4 KB validado antes da leitura (C-02), prevenindo DoS via arquivo malicioso.
- O conteúdo é serializado como base64url opaco, sem estrutura legível a olho nu.

**Limitação:** Um PIN fraco (ex: "1234", "0000") pode ser quebrado offline mesmo com Argon2id se o espaço de tentativas for pequeno.

---

### ✅ PROTEGIDO — Ataque de rollback com backup antigo

**Cenário:** Atacante (ou erro do usuário) substitui o `.vault` atual por uma cópia mais antiga em que uma senha importante ainda estava presente.

**Proteção:**
- `~/.key_lock_meta/` rastreia o timestamp mínimo aceitável por cofre.
- Cofres com `last_saved` inferior ao registrado levantam `ValueError` com aviso explícito.
- O metadata é protegido por HMAC-SHA256 usando o `machine_secret` (256 bits aleatórios, `0o600`).
- O caminho do metadata inclui os primeiros 16 hex-chars do SHA-256 do path resolvido, evitando colisões entre cofres com o mesmo nome em diretórios diferentes.
- **Desde v2.4.2 (fail-closed):** se o arquivo de metadata estiver ausente, corrompido ou com HMAC inválido, a abertura do cofre é **bloqueada por padrão**. Antes dessa versão, corromper o arquivo de metadata era suficiente para bypass silencioso do anti-rollback (sem necessidade do `machine_secret`). O usuário pode usar `force_accept_meta=True` explicitamente para aceitar metadata não verificado após confirmação manual — um aviso é sempre emitido nesse caso.

**Limitação:** Um adversário com acesso leitura a `machine_secret.key` pode recalcular o HMAC e forjar um metadata válido. A proteção é contra adulteração/corrupção do metadata e restauração acidental de backups, não contra adversário privilegiado com acesso ao `machine_secret`.

---

### ✅ PROTEGIDO — Acesso concorrente ao cofre

**Cenário:** Duas instâncias do key_lock tentam escrever no mesmo `.vault` ao mesmo tempo.

**Proteção:**
- `VaultLock` usa dois níveis: `threading.Lock` (intra-processo) + arquivo `.lock` (inter-processo).
- A criação do arquivo `.lock` usa `O_CREAT | O_EXCL` — operação atômica no kernel que elimina a janela TOCTOU entre checagem e escrita (corrigido em v2.4.2).
- O arquivo `.lock` contém PID, hostname e token aleatório de ownership (C-04) — só o titular pode remover o lock.
- Locks stale (processo morto ou timeout de 5 minutos) são detectados e removidos automaticamente.
- Escritas são atômicas via `tmp + os.replace()` — sem janela de corrupção por crash.

**Limitação:** Sem suporte a locking de rede (NFS/SMB). Em drives de rede, o file lock não garante exclusividade entre máquinas diferentes.

---

### ✅ PROTEGIDO — Força bruta de passphrase online (tentativa repetida)

**Cenário:** Atacante com acesso à interface tenta passphrase incorretas em sequência.

**Proteção:**
- `open_vault_with_passphrase` aplica backoff exponencial persistido em disco (C-01): a partir da 3ª falha, espera cresce até 60 segundos.
- O contador de falhas sobrevive ao reinício do processo (arquivo `*_fail.json` em `~/.key_lock_meta/`).
- O counter é zerado após abertura bem-sucedida.

**Limitação:** Não há bloqueio permanente (lockout) — apenas slowdown. Um atacante com acesso direto ao arquivo pode pular a camada de backoff e atacar offline.

---

### ✅ PROTEGIDO — Cofre transferido para máquina não autorizada

**Cenário:** Um `.vault` é copiado para outra máquina sem autorização. O `machine_secret.key` não acompanhou.

**Proteção:**
- `machine_tag = HMAC-SHA256(machine_secret, salt)` é armazenado no vault.
- Na abertura, o tag é verificado em tempo constante (`hmac.compare_digest`). Falha levanta `MachineMismatchError`.
- Para autorizar outra máquina legitimamente, o admin copia `machine_secret.key` para o mesmo path.
- Alternativa: usar o mnemônico e depois `rebind` para re-vincular à nova máquina.

**Limitação:** Se o atacante obtiver tanto o `.vault` quanto o `machine_secret.key`, a vinculação não oferece proteção adicional além do Argon2id.

---

### ⚠️ PARCIALMENTE PROTEGIDO — Adversário com acesso ao sistema de arquivos (cofre fechado)

**Cenário:** Atacante lê o sistema de arquivos do usuário mas o cofre não está aberto.

**Proteção:** Todos os dados sensíveis estão cifrados. O atacante só pode iniciar força bruta offline (limitado pelo Argon2id).

**Limitação:** O `machine_secret.key` em `~/.config/key_lock/machine_secret.key` com `0o600` é legível por qualquer processo rodando como o mesmo usuário. Roubar esse arquivo permite criar um `machine_tag` válido — mas ainda não abre o cofre sem a passphrase ou o mnemônico.

---

### ❌ NÃO PROTEGIDO — Adversário com acesso à máquina e cofre aberto

**Cenário:** Sessão ativa, cofre aberto na GUI ou CLI.

**Exposição:**
- A passphrase como `str` Python é imutável: não pode ser zerada, persiste na heap até o GC coletar.
- As entradas decifradas estão em memória como dicionários Python.
- Um heap dump, `ptrace` com privilégios suficientes, ou ferramenta de debug pode extrair esses dados.

**Mitigação parcial:** Chaves derivadas (`bytearray`) são zeradas via `secure_zero()` após uso. O intervalo de exposição é minimizado. O timeout de inatividade da GUI fecha o cofre automaticamente após 10 minutos. **Desde v2.4.2:** a zeragem ocorre também no fechamento manual via botão "Fechar" (`VaultScreen._close`) e ao fechar a janela pelo botão do sistema operacional (`WM_DELETE_WINDOW`) — lacunas que existiam nas versões anteriores.

**Recomendação:** Fechar o cofre quando não estiver em uso ativo. Não deixar o cofre aberto em sessões compartilhadas ou desassistidas.

---

### ❌ NÃO PROTEGIDO — Malware com privilégios de usuário

**Cenário:** Keylogger, screen recorder, ou dumper de memória instalado na máquina.

**Posição:** Fora do escopo. O key_lock não pode proteger contra código malicioso rodando com os mesmos privilégios do usuário. Use um sistema operacional atualizado e sem software suspeito.

---

### ❌ NÃO PROTEGIDO — Engenharia social

**Cenário:** Atacante convence o usuário a revelar passphrase ou mnemônico.

**Posição:** Fora do escopo técnico. Treinamento de usuário.

---

## Decisões de design documentadas

### Por que X25519 e não Ed25519?
Ed25519 é um algoritmo de *assinatura*. Usar sua chave pública diretamente como material de chave de cifragem (mesmo via HKDF) é uma categoria de erro: a chave nunca foi projetada para esse uso. X25519 é a variante Diffie-Hellman da Curve25519, projetada especificamente para acordo de chaves. (FIX #1, v2.0)

### Por que ECDH efêmero-estático?
A chave pública de recovery fica armazenada no `.vault`. Se usássemos apenas essa chave diretamente para cifrar (e.g., ECIES simplificado sem ephemeral), cada operação de cifragem produziria o mesmo blob derivado. Com ephemeral-static ECDH, cada `encrypt_master_key_with_recovery` gera um par efêmero novo, garantindo que dois blobs cifrados com a mesma chave pública sejam criptograficamente independentes.

### Por que Argon2id com 256 MB?
Parâmetros menores (64 MB / t=3, como na v1.x) custam ~4x menos por tentativa de força bruta em hardware dedicado. Com 256 MB, mesmo GPUs com muita VRAM têm throughput drasticamente reduzido. O custo para o usuário legítimo é ~0,7–1,2 segundos em hardware moderno — aceitável.

### Por que AAD em todos os blobs?
AES-GCM sem AAD autentica apenas a confidencialidade dos dados. Com dois cofres usando a mesma chave pública de recovery, um adversário poderia tentar substituir o `master_key_blob` de um cofre pelo do outro. AAD de domínio independente por tipo de blob torna essa substituição detectável na verificação GCM.

### Por que o metadata anti-rollback não usa o keychain do sistema operacional?
Portabilidade e ausência de dependência de `SecretService` (Linux), `Keychain` (macOS) ou `DPAPI` (Windows). O `machine_secret` em arquivo `0o600` oferece proteção adequada contra adulteração casual sem criar dependência de infraestrutura externa. Trade-off aceito conscientemente.

### Por que reads não adquirem file lock?
Inspeção read-only é sempre possível por design. O risco de ler um vault parcialmente escrito é eliminado pelo padrão `tmp + os.replace()` (atômico no POSIX). Adicionar lock em leitura criaria deadlocks em workflows legítimos (ex: GUI aberta + CLI listando entradas) sem ganho de segurança real.

---

## Limitações conhecidas

1. **Python strings são imutáveis e não podem ser zeradas.** A passphrase persiste na heap. Aceito por limitação da plataforma.

2. **Windows: `os.replace()` pode falhar** se o arquivo `.vault` estiver aberto por antivírus em tempo real. Sem suporte oficial a Windows nesta versão.

3. **HMAC anti-rollback não resiste a adversário com acesso total.** Defesa em profundidade, não garantia absoluta.

4. **IDs de entrada usam `uuid.uuid4()`** para unicidade, não para segurança. São identificadores, não segredos.

5. **Argon2id com 256 MB pode ser lento** em sistemas com menos de 512 MB de RAM livre. Os parâmetros são constantes — não há modo "rápido" intencional.

6. **O metadata anti-rollback vaza o path do cofre** na mensagem de erro (`Para aceitar este vault, delete: /path/...`). Intencional para usabilidade — o usuário precisa saber qual arquivo deletar. Em ambiente corporativo, esse comportamento deveria ser configurável.
