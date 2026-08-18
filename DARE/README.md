# dare-agent-security — DARE Framework

## Design → Architect → Review → Execute

### Estrutura
- `DARE/` — documentação de design e execução
- `DARE/EXECUTION/` — tasks executadas e telemetria
- `templates/` — templates de documentação DARE

### Ralph Loop
Antes de marcar qualquer task como DONE:
1. Build ✅
2. Test ✅
3. Lint ✅

### Fluxo de Trabalho
1. `/generate-design` — cria DESIGN.md
2. `/generate-blueprint` — cria BLUEPRINT.md
3. `/generate-tasks` — cria TASKS.md
4. `/execute-task` — executa cada task com Ralph Loop
