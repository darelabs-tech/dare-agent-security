# TASKS DE IMPLEMENTAÇÃO: [Nome do Projeto]

Este documento contém o desdobramento do Blueprint aprovado em tarefas atômicas e executáveis para a IA.
Cada tarefa listada aqui possui um arquivo correspondente no diretório `DARE/EXECUTION/` contendo sua especificação detalhada.

## FASES DE IMPLEMENTAÇÃO

### Fase 1: [Nome da Fase, ex: Setup e Banco de Dados]
- [ ] **Task 001:** [Objetivo curto, ex: Criar Migration e Model de Usuário]
- [ ] **Task 002:** [Objetivo curto, ex: Configurar Traits e Classes Base]

### Fase 2: [Nome da Fase, ex: Autenticação]
- [ ] **Task 003:** [Objetivo curto, ex: Implementar AuthController (Login/Register)]
- [ ] **Task 004:** [Objetivo curto, ex: Criar Middlewares de verificação de permissão]

## DEPENDÊNCIAS

- A **Fase 2** depende da conclusão 100% da **Fase 1**.
- A **Task 004** depende da **Task 003**.

## INSTRUÇÕES PARA EXECUÇÃO

Para executar uma tarefa, use o comando `/execute-task [id-da-task]` no Cursor Composer.
Exemplo: `/execute-task task-001`

A IA lerá o arquivo `DARE/EXECUTION/task-001.md`, implementará o código, rodará os testes e validará os critérios de sucesso. Após a execução, marque a tarefa como concluída (com um `x` entre os colchetes `[x]`) neste documento.
