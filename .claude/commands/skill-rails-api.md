# /skill-rails-api

Padrões DARE para APIs em Ruby on Rails 8 — API mode, ActiveRecord, Solid Queue, Solid Cable, Action Cable, strong params, Services, serializers (Blueprinter/Alba), Devise/JWT, rack-attack, rswag.

## Como usar

```
/skill-rails-api                          # audita projeto Rails
/skill-rails-api scaffold users           # gera controller + service + blueprint + tests
/skill-rails-api migrate-controllers      # extrai lógica de controllers para services
```

## Stack canônica

- Ruby 3.3+
- Rails 8.x (`rails new --api`)
- PostgreSQL 16
- Solid Queue (jobs) + Solid Cable (websockets) — built-in Rails 8
- Devise + devise-jwt (ou JWT puro)
- Pundit ou CanCanCan (autorização)
- Blueprinter ou Alba (serializers)
- rack-attack (rate limit)
- rswag (OpenAPI)
- RSpec + FactoryBot + Faker
- Rubocop rails-omakase
- bundler-audit (CVEs)

## Layered Design

| Camada | Pasta Rails |
|---|---|
| Handler | `app/controllers/api/v1/` |
| Service | `app/services/` |
| Repository | `app/repositories/` (opcional) |
| Model | `app/models/` |
| Presenter | `app/blueprints/` ou `app/serializers/` |

## Controllers

```ruby
module Api::V1
  class UsersController < ApplicationController
    before_action :authenticate_user!

    def create
      result = RegisterUser.new(user_params).call
      if result.success?
        render json: UserBlueprint.render(result.user), status: :created
      else
        render json: { error: result.error_code }, status: :conflict
      end
    end

    private

    def user_params
      params.require(:user).permit(:email, :name, :password)
    end
  end
end
```

## Service Object

```ruby
class RegisterUser
  Result = Struct.new(:success?, :user, :error_code)

  def initialize(params)
    @params = params
  end

  def call
    return Result.new(false, nil, 'USER_EXISTS') if User.exists?(email: @params[:email])
    user = User.create!(@params)
    Result.new(true, user, nil)
  end
end
```

## Model

```ruby
class User < ApplicationRecord
  has_secure_password
  validates :email, presence: true, uniqueness: true, format: URI::MailTo::EMAIL_REGEXP
  validates :name, presence: true
  validates :password, length: { minimum: 12 }, if: :password_required?
end
```

## Blueprinter (serializer)

```ruby
class UserBlueprint < Blueprinter::Base
  identifier :id
  fields :email, :name
  field :created_at do |u| u.created_at.iso8601 end
end
```

## Auth (devise-jwt)

```ruby
# config/initializers/devise.rb
config.jwt do |jwt|
  jwt.secret = Rails.application.credentials.devise_jwt_secret_key!
  jwt.dispatch_requests = [['POST', %r{^/api/v1/login$}]]
  jwt.revocation_requests = [['DELETE', %r{^/api/v1/logout$}]]
  jwt.expiration_time = 15.minutes.to_i
end
```

## rack-attack

```ruby
class Rack::Attack
  throttle('login/ip', limit: 5, period: 15.minutes) do |req|
    req.ip if req.path == '/api/v1/login' && req.post?
  end
  throttle('api/ip', limit: 100, period: 1.minute) do |req|
    req.ip if req.path.start_with?('/api/')
  end
end
```

## Solid Queue (jobs)

```ruby
class SendWelcomeEmailJob < ApplicationJob
  queue_as :default
  def perform(user_id)
    user = User.find(user_id)
    UserMailer.welcome(user).deliver_now
  end
end
```

## Solid Cable + Action Cable

```ruby
class NotificationsChannel < ApplicationCable::Channel
  def subscribed
    stream_for current_user
  end
end

# Broadcast
NotificationsChannel.broadcast_to(user, type: 'message.sent.v1', payload: {...})
```

## OpenAPI (rswag)

```ruby
# spec/integration/users_spec.rb
path '/api/v1/users' do
  post 'Creates a user' do
    parameter name: :user, in: :body, schema: { ... }
    response '201', 'user created' do ... end
  end
end

# rake rswag:specs:swaggerize  →  swagger/v1/swagger.yaml
```

## Testes RSpec

```ruby
# Service
RSpec.describe RegisterUser do
  it 'falha se email já existe' do
    User.create!(email: 'x@y.com', name: 'X', password: 'longsecret123')
    result = described_class.new(email: 'x@y.com', name: 'Y', password: 'longsecret123').call
    expect(result.error_code).to eq 'USER_EXISTS'
  end
end

# Request
RSpec.describe 'POST /api/v1/users', type: :request do
  it 'cria com sucesso' do
    post '/api/v1/users', params: { user: {...} }, headers: auth_headers
    expect(response).to have_http_status(:created)
  end
end
```

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | Query AR no controller | Service object |
| AP-02 | Lógica no controller | Service object |
| AP-03 | `render json: user` | Blueprinter/Alba |
| AP-04 | Fat Model | Concerns + Services |
| AP-05 | Skip strong params | `permit(...)` sempre |
| AP-06 | Sem rack-attack em login | rate limit obrigatório |
| AP-07 | JWT secret em código | `credentials.yml.enc` |
| AP-08 | Logs com PII | `filter_parameters` |
| AP-09 | N+1 sem `includes` | `bullet` gem em dev |
| AP-10 | Sem `--api` no Rails new | use modo API |

## Segurança

- `has_secure_password` (BCrypt default Rails OK; trocar para Argon2 se quiser)
- `force_ssl = true` em prod
- `secure_headers` gem ou nativo Rails 8
- `rack-cors` com origens específicas
- `filter_parameters` para password/token/secret
- bundler-audit no CI

## CI

```bash
bundle exec rubocop
bundle exec rspec
bundle exec bundler-audit check --update
```

## O que fazer

1. Audit:
   ```bash
   grep -rn "\.where\|\.create" app/controllers/
   grep -rn "render json: @" app/controllers/
   grep -rn "params\[:" app/controllers/ | grep -v "permit"
   ```
2. Lógica > 10 linhas no controller → Service `.call`
3. `render json: object` → `BlueprintRender(object)`
4. Configurar rack-attack + filter_parameters
5. Documentar endpoints com rswag + gerar OpenAPI

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
