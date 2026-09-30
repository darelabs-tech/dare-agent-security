# Guia: testar o servidor MCP de um cliente (Ubuntu)

Como instalar o DARE Agent Security na máquina do cliente e fazer o primeiro
teste no servidor MCP dele. Leva cerca de 15 minutos.

## 0. Antes de começar

- **Autorização por escrito** do cliente para testar o servidor, de preferência
  em **homologação**, não em produção.
- A máquina precisa rodar o servidor MCP (se ele for local/stdio) ou alcançar a
  URL HTTPS dele.
- O que o teste faz: conecta no servidor, negocia o protocolo e **lista**
  ferramentas, recursos e prompts. Ele **nunca chama uma ferramenta** e nunca lê
  o conteúdo de um recurso. Nada é enviado para fora da máquina.

## 1. Instalar

O binário do Linux é estático: roda em qualquer versão do Ubuntu (x86_64 ou
ARM), sem dependências.

**Com internet (recomendado):**

```bash
curl -fsSL https://raw.githubusercontent.com/darelabs-tech/dare-agent-security/main/installers/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
dare-agent-security --version
```

O instalador baixa a última versão publicada e **confere o SHA-256**. Se o
checksum não bater, ele recusa a instalação. Enquanto só houver pré-releases
(`-rc`), ele usa a mais nova e avisa. Para fixar uma versão:

```bash
curl -fsSL https://raw.githubusercontent.com/darelabs-tech/dare-agent-security/main/installers/install.sh \
  | DARE_SECURITY_VERSION=v1.0.0-rc2 sh
```

**Sem internet no cliente:** leve o arquivo
`dare-agent-security-v1.0.0-rc2-linux-x86_64.tar.gz` e o `.sha256` num pendrive:

```bash
sha256sum -c dare-agent-security-v1.0.0-rc2-linux-x86_64.tar.gz.sha256   # precisa dizer OK
tar -xzf dare-agent-security-v1.0.0-rc2-linux-x86_64.tar.gz
mkdir -p ~/.local/bin
cp dare-agent-security-v1.0.0-rc2-linux-x86_64/dare-agent-security ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
dare-agent-security --version
```

**Desinstalar:** `rm ~/.local/bin/dare-agent-security`.

## 2. Rodar o teste

### Servidor local (stdio) — o caso mais comum

Descubra primeiro como o cliente inicia o servidor. Normalmente está na
configuração do Claude Desktop, Cursor ou do agente dele (`command` + `args`).
Tudo depois de `--` é esse comando, exatamente como está lá.

```bash
dare-agent-security discover --stdio \
  --target-id cliente-x \
  --pass-env PATH --pass-env HOME \
  --output-dir resultado-cliente-x \
  -- npx -y @cliente/mcp-server
```

Por segurança, **o servidor sobe com o ambiente vazio**: nem `PATH` é repassado.
Cada variável de que ele precisa tem de ser liberada pelo nome com `--pass-env`:

| O servidor usa | Acrescente |
|---|---|
| `npx`, `node`, `uvx`, `python` pelo nome | `--pass-env PATH --pass-env HOME` |
| uma chave ou URL no ambiente (ex.: `CLIENTE_API_KEY`, `DATABASE_URL`) | `--pass-env CLIENTE_API_KEY` |

O **valor** vem do terminal de quem roda o comando: exporte a variável antes
(`export CLIENTE_API_KEY=...`). O valor nunca é gravado em nenhum arquivo nem
mostrado na tela. Nunca coloque a chave direto no comando, porque ela ficaria no
histórico do shell.

Para ter também o inventário completo em JSON:

```bash
dare-agent-security discover --stdio --json --target-id cliente-x \
  --pass-env PATH --pass-env HOME -- npx -y @cliente/mcp-server > inventario-cliente-x.json
```

### Servidor remoto (HTTPS)

```bash
dare-agent-security discover --url https://mcp.cliente.com.br/mcp \
  --target-id cliente-x --output-dir resultado-cliente-x
```

**Limitação atual:** a descoberta por URL ainda não envia token. Se o servidor
exigir login (OAuth ou Bearer), ela para no handshake. Nesse caso, peça ao
cliente para rodar o mesmo servidor localmente, em homologação, e use o modo
stdio acima.

## 3. Ler o resultado

A tela mostra o resumo:

```text
Tools                   8
Tool behavior indicators
Read-only               3
State-changing          3
Destructive             1      ← ferramentas que apagam ou alteram dados
Open-world              1      ← ferramentas que alcançam sistemas externos
Authentication          ...
```

A pasta `resultado-cliente-x/` contém:

| Arquivo | O que é |
|---|---|
| `summary.md` | resumo com o veredito agregado |
| `evidence/MCP-DISCOVERY-001..004.json` | 4 verificações: protocolo negociado, só métodos passivos usados, inventário completo, nenhuma credencial no resultado |
| `ci-result.json` | o mesmo veredito, em formato de máquina (usado pela GitHub Action) |

**O que levar para a conversa com o cliente:** ferramentas destrutivas ou
open-world sem necessidade clara, ferramentas sem classificação ("Unknown"),
descrições que dão instruções ao modelo e o estado de autenticação.

**Antes de levar os arquivos embora:** eles contêm nomes e descrições das
ferramentas do cliente, mas nenhum valor de variável e nenhuma credencial. Peça
ao cliente para revisar mesmo assim.

## 4. Se der erro

| Mensagem | Causa provável | O que fazer |
|---|---|---|
| `adapter transport error (handshake)` | o servidor não subiu ou morreu | rode o comando depois de `--` sozinho no terminal; normalmente falta uma variável: acrescente `--pass-env NOME` |
| `invalid discovery target (shell-program)` | o comando é `bash`/`sh -c ...` | aponte para o executável real, sem shell |
| `invalid discovery target (pass-env-name)` | nome inválido em `--pass-env` | só o nome (`API_KEY`), nunca `NOME=valor` |
| `--pass-env applies only to --stdio targets` | `--pass-env` junto com `--url` | tire o `--pass-env` |
| código de saída `2` | resultado parcial (ex.: inventário incompleto) | veja `summary.md` e `evidence/` |

Códigos de saída: `0` sucesso, `1` erro de ambiente, `2` resultado parcial ou
reprovado, `3` alvo ou uso inválido.

## 5. O que este teste não cobre

Ele inventaria e classifica, mas não ataca o servidor. Os testes adversariais
(prompt injection, abuso de ferramenta, identidade, RAG, memória) rodam hoje
sobre cenários de laboratório. Adaptá-los ao agente do cliente é a etapa
seguinte da POC; veja `demo/ROTEIRO-POC.pt-BR.md`.
