# /dare-llm-integration

Integração segura e eficiente com LLMs (Gemini, Claude, OpenAI, Ollama) em projetos DARE.

## Como usar

```
/dare-llm-integration                       # audita uso de LLM no projeto
/dare-llm-integration scaffold              # gera LLMProvider + cache + rate limit
/dare-llm-integration prompts               # extrai prompts inline para arquivos versionados
```

## Os 5 pilares

### 1. LLMProvider abstraction

Nunca chame SDK do Gemini/OpenAI direto em Handler ou Service de negócio. Sempre via interface `LLMProvider`.

### 2. Cache TTL

Toda chamada passa por cache. Key = `hash(promptId + input + model)`. TTL default 1h.

### 3. Rate limit via token bucket

Token bucket por provider:
- Gemini Free: 15 RPM, 1M tokens/dia
- Claude tier 1: 50 RPM
- OpenAI tier 1: 500 RPM

### 4. Prompts versionados

Nunca inline em código. Vivem em `prompts/<id>.v<n>.md` com frontmatter (model, temperature, schema).

### 5. Validação via schema

LLM mente — sempre valide output com Zod/Pydantic/serde.

## Métricas obrigatórias

| ID | Métrica |
|---|---|
| M-01 | 100% das chamadas LLM via LLMProvider injetado |
| M-02 | 100% das responses LLM cacheadas |
| M-03 | 100% das requests com rate limit |
| M-04 | 100% das respostas validadas contra schema |

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | SDK direto em Handler | impossível mockar/trocar provider |
| AP-02 | Sem cache | custo explode |
| AP-03 | Prompt em código | impossível versionar/A-B |
| AP-04 | User input direto em prompt | prompt injection trivial |
| AP-05 | Trusting LLM output | LLM mente, schema é defesa |

## Defesa contra prompt injection

```python
# ❌ Concatenação direta
system = f"You are an assistant. {user_question}"

# ✅ Separação por delimitador + escape
messages = [
    {"role": "system", "content": "You are an assistant. Answer based on the document below."},
    {"role": "user", "content": f"<document>{escape(doc)}</document>\n<question>{escape(q)}</question>"}
]
```

Regras:
- Use delimitadores (`<document>`, `<question>`)
- Escape conteúdo do usuário (XML/HTML escape)
- Detecte "Ignore instructions above"
- Valide output — fora do schema = sinal de injection

## O que fazer

### Passo 1: Auditar chamadas LLM

```bash
grep -rn "GoogleGenAI\\|new OpenAI\\|Anthropic(" src/
```

Toda ocorrência em Handler ou Service de negócio = AP-01.

### Passo 2: Criar `LLMProvider` interface

```typescript
interface LLMProvider {
  complete(req: {
    promptId: string;
    input: Record<string, unknown>;
    schema: ZodSchema;
  }): Promise<unknown>;
}
```

### Passo 3: Implementar providers

Comece com o que o projeto usa. Use os exemplos em `packages/skills/dare-llm-integration/providers/`.

### Passo 4: Configurar cache + rate limit

Cache em memória com TTL + token bucket por provider. Implementação pronta em `packages/skills/dare-llm-integration/cache/` e `.../rate_limit/`.

### Passo 5: Extrair prompts inline

Para cada prompt inline encontrado, mova para `prompts/<id>.v1.md` com frontmatter:

```markdown
---
id: summarize
version: 1
model: gemini-2.0-flash
temperature: 0.2
max_tokens: 500
schema: SummarySchema
---

# System
You are a concise summarizer.

# User
Summarize: <text>{{ text }}</text>
```

### Passo 6: Adicionar validação no chamador

```typescript
const raw = await llm.complete({...});
const parsed = SummarySchema.parse(raw);  // joga LLMOutputInvalidError se falhar
```

## Saída esperada

Reporte numerado:
- Quantas chamadas LLM no projeto
- Quantas via LLMProvider (M-01)
- Quantas cacheadas (M-02)
- Quantas com rate limit (M-03)
- Quantas validadas contra schema (M-04)
- Lista de prompts inline a extrair

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
