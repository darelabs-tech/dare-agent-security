# Comando: /generate-dockerfile

## Descrição
Este comando analisa a stack do projeto (definida no DESIGN.md ou .cursorrules) e gera um `Dockerfile` otimizado para produção e desenvolvimento.

## Instruções para o Cursor Composer

1. **Analise o Contexto:** Leia o arquivo `.cursorrules` e o `DARE/DESIGN.md` (se existir) para identificar a stack tecnológica principal (Linguagem, Framework, Versões).
2. **Leia a Skill Docker:** Leia as regras em `.cursor/rules/skill-docker.mdc` para aplicar as melhores práticas de containerização.
3. **Gere o Dockerfile:**
   - Crie um Dockerfile na raiz do projeto (`./Dockerfile`).
   - **Para PHP/Laravel:** Use multi-stage build. Instale extensões necessárias (pdo_mysql/pgsql, mbstring, exif, pcntl, bcmath, gd). Configure o `www-data` e ajuste permissões de `/var/www/html/storage` e `bootstrap/cache`.
   - **Para Python:** Use `python:slim`. Crie um usuário não-root. Copie `requirements.txt` primeiro, instale dependências e depois copie o código.
   - **Para Go:** Use multi-stage. Estágio 1: `golang:alpine` para build (`go build -o app`). Estágio 2: `alpine` ou `scratch` rodando apenas o binário.
   - **Para Node/Vue:** Estágio 1: `node:alpine` para build (`npm run build`). Estágio 2: `nginx:alpine` para servir a pasta `dist`.
4. **Gere o .dockerignore:** Crie um arquivo `.dockerignore` na raiz do projeto ignorando pastas desnecessárias (`node_modules`, `vendor`, `.git`, `.env`, `tests`, `DARE`).
5. **Mensagem Final:** Informe ao usuário: "Dockerfile e .dockerignore gerados com sucesso e otimizados para a stack [NOME_DA_STACK]. Revise os arquivos gerados. Para criar a orquestração de serviços, execute `/generate-docker-compose`."
