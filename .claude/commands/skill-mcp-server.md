# /skill-mcp-server

Padrões DARE para servidores MCP (Model Context Protocol) em TypeScript ou Python. Tools, resources, prompts; transports stdio/SSE/HTTP; validação Zod/Pydantic; autorização por tool; tracing; testes; publicação.

## Como usar

```
/skill-mcp-server                            # audita server MCP atual
/skill-mcp-server scaffold ts                # scaffold TypeScript stdio
/skill-mcp-server scaffold py                # scaffold Python stdio
```

## O que é MCP

Protocolo aberto da Anthropic para conectar agentes a fontes de dados e ações. Server expõe:
- **Tools** — funções chamáveis (ex: `create_issue`)
- **Resources** — dados leitáveis (ex: schemas)
- **Prompts** — templates parametrizados

Transports: **stdio** (local), **SSE** (remoto streaming), **HTTP** (remoto stateless).

## Stack (TypeScript)

- Node 20+ + TS 5.5+
- `@modelcontextprotocol/sdk`
- Zod para schemas
- vitest

## Stack (Python)

- Python 3.11+
- `mcp` (SDK oficial)
- Pydantic v2
- pytest + pytest-asyncio

## Estrutura

```
mcp-server/
├── src/
│   ├── index.ts            ← stdio entrypoint
│   ├── server.ts
│   ├── tools/
│   ├── resources/
│   ├── prompts/
│   └── schemas/
└── tests/
```

## Exemplo (TypeScript stdio)

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const CreateIssueInput = z.object({
  title: z.string().min(1).max(255),
  description: z.string().optional(),
  priority: z.enum(['low', 'medium', 'high']).default('medium'),
  team_id: z.string().uuid(),
});

const server = new Server(
  { name: 'meu-server', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: 'create_issue',
    description: 'Create a new issue in Linear',
    inputSchema: CreateIssueInput.shape,
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const input = CreateIssueInput.parse(req.params.arguments);
  const result = await linearClient.createIssue(input);
  return { content: [{ type: 'text', text: JSON.stringify(result) }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
```

## Exemplo (Python stdio)

```python
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field
import asyncio

app = Server("meu-server")

class CreateIssueInput(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    priority: str = Field(default="medium", pattern="^(low|medium|high)$")
    team_id: str

@app.list_tools()
async def list_tools():
    return [Tool(
        name="create_issue",
        description="Create a new issue",
        inputSchema=CreateIssueInput.model_json_schema(),
    )]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    input_data = CreateIssueInput.model_validate(arguments)
    result = await linear_client.create_issue(input_data)
    return [TextContent(type="text", text=result.model_dump_json())]

async def main():
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
```

## Resources e Prompts

```typescript
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [{ uri: 'linear://schema', name: 'Schema', mimeType: 'application/json' }],
}));

server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: [{
    name: 'triage_issue',
    description: 'Triage and assign priority',
    arguments: [{ name: 'description', required: true }],
  }],
}));
```

## Autorização por tool

```typescript
if (input.confirm !== 'YES_I_AM_SURE') throw new Error('confirm required');
if (!callerHasRole('admin')) throw new Error('admin only');
```

## Observabilidade

**stdio: logs em stderr SEMPRE** (stdout é o protocolo).

```typescript
console.error(JSON.stringify({
  ts: new Date().toISOString(),
  tool: req.params.name,
  duration_ms: Date.now() - start,
  success: true,
}));
```

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Logs no stdout (stdio) | Quebra o protocolo |
| AP-02 | Tool sem schema | Cliente passa lixo |
| AP-03 | Sem validação no server | Confia no client (errado) |
| AP-04 | Tool destrutiva sem confirm | Agente apaga sem querer |
| AP-05 | Secrets em código | Use env vars |
| AP-06 | Tool name vago (`do_thing`) | Agente não sabe quando usar |
| AP-07 | Description vago | Erra na escolha |
| AP-08 | Resource sem mimeType | Cliente não parseia |

## Testes

```typescript
// Unit
test('valida input', () => {
  const valid = CreateIssueInput.parse({ title: 'Test', team_id: '550e8400-e29b-41d4-a716-446655440000' });
  expect(valid.priority).toBe('medium');
});

// E2E com client MCP
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
const client = new Client({ name: 'test', version: '0.0.0' }, { capabilities: {} });
await client.connect(transport);
const tools = await client.listTools();
expect(tools.tools.map(t => t.name)).toContain('create_issue');
```

## Configuração no Claude Desktop

```json
{
  "mcpServers": {
    "meu-server": {
      "command": "node",
      "args": ["/abs/path/dist/index.js"],
      "env": { "LINEAR_API_KEY": "lin_api_..." }
    }
  }
}
```

## Publicação

- README com tools, env vars, exemplo de config
- LICENSE MIT
- `package.json` ou `pyproject.toml` versionado
- npm publish (TS) ou PyPI (Python)
- Para SSE/HTTP: Docker multi-stage

## O que fazer

1. Decidir transport (stdio para local; SSE/HTTP para remoto)
2. Listar tools/resources/prompts no DESIGN.md
3. Scaffold com SDK oficial
4. Schema Zod/Pydantic para cada tool
5. Logs em stderr, JSON estruturado
6. Testes vitest/pytest + E2E com client MCP
7. README + LICENSE MIT + publicação

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
