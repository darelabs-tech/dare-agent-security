# Comando: /generate-docker-compose

## Descrição
Este comando analisa a arquitetura definida no BLUEPRINT.md e gera um `docker-compose.yml` completo com todos os serviços necessários (App, DB, Cache, etc).

## Instruções para o Cursor Composer

1. **Leia o Documento Blueprint:** Acesse o `DARE/BLUEPRINT.md` (se existir) para identificar as dependências do sistema (ex: PostgreSQL, Redis, Mailhog).
2. **Leia o Contexto Global:** Leia o `.cursorrules` para confirmar as versões do banco de dados e outras ferramentas.
3. **Leia a Skill Docker:** Leia `.cursor/rules/skill-docker.mdc` para aplicar boas práticas (Healthchecks, Redes, Volumes).
4. **Gere o docker-compose.yml:**
   - Crie um arquivo `docker-compose.yml` na raiz do projeto.
   - **Serviço App:** Use o `build: .` (Dockerfile gerado). Exponha a porta correta. Defina variáveis de ambiente ou carregue do `.env`. Configure `depends_on` para DB/Cache.
   - **Serviço Webserver (Laravel):** Se for Laravel, crie um serviço `nginx` dependente do `app` (PHP-FPM) e configure os volumes para compartilhar a pasta `/var/www/html`.
   - **Serviço Banco de Dados:** Adicione o banco de dados (ex: `postgres:16-alpine` ou `mysql:8.0`). Defina variáveis de ambiente para usuário, senha e database (`POSTGRES_DB`, `POSTGRES_USER`). Adicione um `healthcheck` para testar a conexão (`pg_isready -U user`). Crie um volume nomeado para os dados (`db_data:/var/lib/postgresql/data`).
   - **Serviço Cache (Opcional):** Se o projeto usar Redis, adicione o serviço `redis:7-alpine`.
   - **Redes e Volumes:** Defina as redes customizadas (ex: `app-network`) e volumes (`db_data`, `redis_data`) no final do arquivo.
5. **Mensagem Final:** Informe ao usuário: "Arquivo docker-compose.yml gerado com sucesso. Todos os serviços (App, [DB], [Cache]) foram configurados com healthchecks, volumes persistentes e redes isoladas. Revise as portas e variáveis de ambiente no .env antes de executar `docker-compose up -d`."
