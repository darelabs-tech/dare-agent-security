# Comando: /execute-task

## Descrição
Este comando finaliza o Método DARE (Execute) implementando o código e validando os testes de uma tarefa específica isolada.

## Instruções para o Cursor Composer

1. **Identifique a Tarefa:** Leia o `$ARGUMENTS` (ID da tarefa ou caminho do arquivo, ex: `task-001` ou `DARE/EXECUTION/task-001.md`).
2. **Leia a Especificação da Tarefa:** Abra e leia a especificação detalhada da tarefa em `DARE/EXECUTION/[id].md`.
3. **Analise o Contexto Global:** Leia o arquivo `.cursorrules` (ou equivalente) e a arquitetura geral em `DARE/BLUEPRINT.md` para garantir que o código será gerado dentro dos padrões do projeto.
4. **Implemente o Código:**
   - Execute passo a passo as instruções da seção "ESPECIFICAÇÃO DE IMPLEMENTAÇÃO".
   - Crie ou modifique os arquivos necessários.
   - Siga rigorosamente os padrões de código, tratamento de erros e convenções definidos nas regras globais e exemplos fornecidos.
5. **O Loop de Validação (Ralph Loop):**
   - Após a implementação, execute OBRIGATORIAMENTE os comandos definidos na seção "CRITÉRIOS DE SUCESSO (VALIDATION GATES)".
   - Exemplo: `php artisan test --filter=NomeDoTeste` ou `./vendor/bin/pint`.
   - Se algum comando falhar, LEIA O ERRO, CORRIJA O CÓDIGO e RODE O COMANDO NOVAMENTE até que todos passem com sucesso.
6. **Mensagem Final:** Após o sucesso dos testes, atualize o status da tarefa no arquivo `DARE/TASKS.md` (marque com um `[x]`) e informe ao usuário: "Tarefa [ID] implementada e validada com sucesso. Os testes passaram."
