# Comando: /dag-viz

## Descrição

Gera diagrama interativo `.excalidraw` a partir do `DARE/dare-dag.yaml` atual. Cada task vira um retângulo com cor baseada em complexidade e status visual, agrupado em colunas verticais (swim lanes) por rank, com setas conectando dependências.

## Instruções para o Cursor Composer

1. **Leia o DAG:** Abra `DARE/dare-dag.yaml`. Valide sintaxe YAML. Extraia tasks, complexidade, dependências e status.

2. **Leia a skill de visualização:** Consulte `.cursor/rules/skill-dag-viz.mdc` (se existir) para convenções visuais e tokens de design.

3. **Calcule ranks:**
   - Tasks sem `depends_on` → rank 1
   - Demais: rank = 1 + max(rank das dependências)
   - Agrupe por rank para formar swim lanes verticais

4. **Gere elementos Excalidraw:**
   - Para cada task, crie retângulo 120×60px:
     - Cor de fundo por `complexity`:
       - LOW → azul `#e3f2fd`, stroke `#1976d2`
       - MEDIUM → laranja `#fff3e0`, stroke `#f57c00`
       - HIGH → rosa `#fce4ec`, stroke `#c2185b`
     - Stroke por `status`:
       - PENDING → linha sólida cinza padrão
       - RUNNING → linha pontilhada azul
       - DONE → linha sólida verde `#388e3c`
       - FAILED → linha sólida vermelha `#d32f2f`
     - Texto: `task-id\ntask-name\n[COMPLEXITY]`
   - Para cada dependência em `depends_on`, crie seta de source → target, stroke cinza `#999`.

5. **Posicione elementos:**
   - X = 20 + (taskIndex_no_rank × 140)
   - Y = 20 + (rank − 1) × 160

6. **Salve:** Escreva resultado em `DARE/dag-graph.excalidraw` no formato JSON Excalidraw 2.x.

7. **Mensagem final:**
   ```
   DAG gerado: DARE/dag-graph.excalidraw
   Abra em https://excalidraw.com (File → Open) para visualizar e editar.
   ```

## Estrutura JSON Excalidraw esperada

```json
{
  "type": "excalidraw",
  "version": 2,
  "source": "dare-dag-viz",
  "elements": [
    {
      "id": "task-001",
      "type": "rectangle",
      "x": 20, "y": 20,
      "width": 120, "height": 60,
      "backgroundColor": "#e3f2fd",
      "strokeColor": "#1976d2",
      "strokeStyle": "solid",
      "fillStyle": "solid",
      "roundness": { "type": 2, "value": 6 }
    },
    {
      "type": "text",
      "x": 25, "y": 25,
      "text": "task-001\nSetup Auth\n[LOW]",
      "fontSize": 12,
      "containerId": "task-001"
    },
    {
      "type": "arrow",
      "startBinding": { "elementId": "task-001" },
      "endBinding": { "elementId": "task-003" },
      "strokeColor": "#999"
    }
  ],
  "appState": {
    "gridMode": "grid",
    "gridSize": 20
  },
  "files": {}
}
```

## Campos esperados em `dare-dag.yaml`

```yaml
tasks:
  task-001:
    name: "Setup Auth"
    complexity: "LOW"          # LOW | MEDIUM | HIGH
    rank: 1                    # opcional (calculado se ausente)
    depends_on: []             # default []
    status: "DONE"             # PENDING | RUNNING | DONE | FAILED (default PENDING)
    subtask_prompt: "..."      # opcional
```

**Obrigatórios:** `name`, `complexity`.
**Opcionais:** `rank`, `depends_on`, `status`.

## Como abrir o resultado

1. Acesse https://excalidraw.com
2. File → Open → selecione `DARE/dag-graph.excalidraw`
3. Edite livremente (mover, colorir, anotar)
4. Salve no mesmo arquivo

## Atualizar após mudanças

Sempre que `dare-dag.yaml` for modificado, rode `/dag-viz` para regenerar.

> Dica: faça backup se editou manualmente — a regeneração sobrescreve.

## Troubleshooting

- **"File not found: DARE/dare-dag.yaml"** — projeto não tem DAG. Rode `/generate-tasks` primeiro para gerá-lo.
- **"JSON inválido"** — valide com `dare dag validate` (se CLI disponível) ou inspecione manualmente.
- **Diagrama muito grande** — abra em Excalidraw e ajuste com Ctrl+Mouse / pinch zoom.

## Convenções visuais

- **Azul** (`#e3f2fd`) = LOW complexity
- **Laranja** (`#fff3e0`) = MEDIUM
- **Rosa** (`#fce4ec`) = HIGH
- **Verde** (`#388e3c`) = DONE
- **Vermelho** (`#d32f2f`) = FAILED
- **Pontilhado azul** = RUNNING
- **Cinza padrão** = PENDING

## Próximos passos

- Exporte para PNG no Excalidraw para incluir em README ou PR
- Compartilhe o link colaborativo do Excalidraw com stakeholders
- Atualize após cada `/generate-tasks` ou `/run-dag`

---

Skill MIT — parte do DARE Method.
Inspiração: [Excalidraw Diagram Skill](https://github.com/coleam00/excalidraw-diagram-skill) por Cole Medin.
