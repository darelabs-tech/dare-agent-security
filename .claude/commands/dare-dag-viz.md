# /dare-dag-viz — Visualizar DAG com Excalidraw

Gera diagrama interativo `.excalidraw` a partir do `dare-dag.yaml` atual, com cores semânticas por complexidade e status visual das tasks.

## O que faz

1. **Lê** `DARE/dare-dag.yaml` (grafo de tasks + dependências)
2. **Mapeia** cada task para um retângulo Excalidraw com:
   - Cor baseada em `complexity` (LOW=azul, MED=laranja, HIGH=rosa)
   - Status visual (PENDING/RUNNING/DONE/FAILED)
   - ID + nome da task
3. **Agrupa** tasks por `rank` em colunas verticais (swim lanes)
4. **Cria** setas para cada dependência (`depends_on`)
5. **Salva** em `DARE/dag-graph.excalidraw`

Output é um arquivo **editável e interativo** — abre direto em https://excalidraw.com.

## Convenções visuais

Referência: `/docs/DESIGN-TOKENS-EXCALIDRAW.md`

**Cores por complexidade:**
- 🔵 **Azul** (#e3f2fd) = LOW
- 🟠 **Laranja** (#fff3e0) = MEDIUM
- 🔴 **Rosa** (#fce4ec) = HIGH

**Status:**
- ⏳ PENDING = cinza, stroke normal
- ⚙️ RUNNING = azul, stroke pontilhado
- ✅ DONE = verde
- ❌ FAILED = vermelho

**Posicionamento:**
- Cada task ocupa 120×60px
- Tasks no mesmo rank ficam lado a lado (swim lane)
- Setas conectam dependências

## Exemplo de output

Arquivo `DARE/dag-graph.excalidraw` com estrutura:

```
Rank 1
├── task-001 (LOW, DONE)
├── task-002 (HIGH, PENDING)

Rank 2
├── task-003 (MEDIUM, RUNNING) ← depende de task-001
├── task-004 (LOW, PENDING) ← depende de task-001

Rank 3
└── task-005 (HIGH, PENDING) ← depende de task-003 e task-004
```

## Como usar

### Primeira vez

```bash
/dare-dag-viz
```

Claude Code vai:
1. Ler `DARE/dare-dag.yaml`
2. Gerar JSON `.excalidraw`
3. Salvar em `DARE/dag-graph.excalidraw`
4. Output: "✅ DAG gerado — abra em https://excalidraw.com"

### Atualizar após mudanças

Sempre que você atualiza `dare-dag.yaml`:

```bash
/dare-dag-viz
```

Isso regenera o diagrama com as novas tasks/dependências.

### Abrir e editar

1. Acesse https://excalidraw.com
2. File → Open → selecione `DARE/dag-graph.excalidraw`
3. Edite livremente:
   - Mova elementos
   - Customize cores/textos
   - Adicione anotações
4. Salve no mesmo arquivo

Dica: Se editou manualmente e quer regenerar com `dare-dag-viz` de novo, faça backup antes.

## Detalhes técnicos

### Estrutura do JSON gerado

```json
{
  "elements": [
    {
      "id": "task-001",
      "type": "rectangle",
      "x": 20, "y": 20,
      "width": 120, "height": 60,
      "backgroundColor": "#e3f2fd",
      "stroke": "#1976d2",
      "text": "task-001\nSetup Auth\n[LOW]",
      "fontSize": 12,
      "roundness": { "type": 2, "value": 6 }
    },
    {
      "type": "arrow",
      "startBinding": { "elementId": "task-001" },
      "endBinding": { "elementId": "task-003" },
      "stroke": "#999"
    }
  ],
  "appState": {
    "gridMode": "grid",
    "gridSize": 20
  }
}
```

### Algoritmo de posicionamento

1. **Calcular ranks** — depth-first do DAG
   ```
   rank = 1 + max(rank of dependencies)
   ```

2. **Agrupar por rank**
   ```
   Rank 1: [task-001, task-002]
   Rank 2: [task-003, task-004]
   ```

3. **Posicionar**
   ```
   x = 20 + (taskIndex * 140)
   y = 20 + (rank - 1) * 160
   ```

4. **Desenhar setas**
   ```
   Para cada depends_on: arrow(source → target)
   ```

## Campos esperados em dare-dag.yaml

```yaml
tasks:
  task-001:
    name: "Setup Auth"
    complexity: "LOW"           # ← determina cor
    rank: 1                     # ← se não existir, é calculado
    depends_on: []              # ← usada para setas
    status: "DONE"              # ← determina stroke/fill
    subtask_prompt: "..."       # ← (opcional)
```

**Campos obrigatórios:** `name`, `complexity`  
**Campos opcionais:** `rank` (calculado), `status` (default PENDING), `depends_on` (default [])

## Troubleshooting

### "File not found: DARE/dare-dag.yaml"
Certifique-se de que está em um projeto DARE. Se não, rode:
```bash
dare discover
```

### "JSON inválido"
Valide seu `dare-dag.yaml`:
```bash
dare dag validate
```

### Diagrama muito grande/pequeno
Abra em Excalidraw e ajuste com Ctrl+Mouse ou pinch zoom.

## Próximos passos

- 🎨 Customize as cores em `docs/DESIGN-TOKENS-EXCALIDRAW.md`
- 📤 Exporte para PNG com botão "Export to Image" no Excalidraw
- 🔄 Atualize após cada `dare design` ou `dare execute`
- 📊 Compartilhe com stakeholders (Excalidraw é colaborativo)

## Referência de design

Ver `/docs/DESIGN-TOKENS-EXCALIDRAW.md` para detalhes de cores, fonts, tamanhos, e créditos.

## Licença

Esta skill é parte do DARE CLI e está sob licença MIT (D-001).

Você pode usar, modificar, compartilhar e distribuir livremente.

Créditos: Inspiração na [Excalidraw Diagram Skill](https://github.com/coleam00/excalidraw-diagram-skill) por Cole Medin.
