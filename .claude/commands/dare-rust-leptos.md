# /dare-rust-leptos

Guia de desenvolvimento Leptos para projetos DARE. Cobre decisão de variante, idioms obrigatórios, antipatterns, tipos compartilhados e templates de tasks.

## Como usar

```
/dare-rust-leptos                    ← decide variante + configura workspace
/dare-rust-leptos --csr              ← guia específico para CSR + trunk
/dare-rust-leptos --fullstack        ← guia específico para SSR + cargo-leptos
/dare-rust-leptos --shared-types     ← padrão cfg_attr para tipos server + WASM
```

---

## 1. Decisão de variante: CSR vs Fullstack

| Critério | CSR (trunk) | Fullstack (cargo-leptos) |
|---|---|---|
| SEO necessário | ❌ | ✅ |
| Time-to-interactive crítico | ❌ | ✅ |
| Dashboard interno / admin | ✅ | ✅ |
| Backend Axum existente | indiferente | ✅ integração direta |
| Simplicidade de deploy | ✅ arquivos estáticos (CDN) | ⚠️ binário Axum |
| Server functions (`#[server]`) | ❌ não existe | ✅ |

**Regra de ouro:**
- Se o projeto vive atrás de login e SEO não importa → **CSR**
- Se precisa de SEO, carregamento inicial rápido, ou server functions → **Fullstack**
- Se já tem `rust-axum` como backend no monorepo → **Fullstack** (workspace unificado)

---

## 2. Ferramentas — nunca misturar

| Variante | Build | Dev server | Test |
|---|---|---|---|
| CSR | `trunk build --release` | `trunk serve` | `cargo test --workspace` |
| Fullstack | `cargo leptos build --release` | `cargo leptos watch` | `cargo test --workspace` |

> ⚠️ `cargo leptos test` **não existe**. Use sempre `cargo test --workspace`.
> ⚠️ Não use `trunk` para fullstack nem `cargo leptos` para CSR — ferramentas erradas para o target errado.

---

## 3. Idioms obrigatórios Leptos 0.7

### Estado reativo
```rust
// ✅ Fine-grained signals — só re-renderiza o que usa o signal
let (count, set_count) = signal(0);
let doubled = move || count.get() * 2;  // derived (memo inline)

// Para estado complexo ou compartilhado entre componentes:
let count = RwSignal::new(0);  // read + write em um só
```

### Dados assíncronos
```rust
// ✅ Resource — fetch declarativo, integra com Suspense
let user = Resource::new(|| user_id(), |id| async move { fetch_user(id).await });

// ✅ Suspense — loading state automático
view! {
    <Suspense fallback=|| view! { <p>"Loading..."</p> }>
        {move || user.get().map(|u| view! { <p>{u.name}</p> })}
    </Suspense>
}

// ❌ Nunca — Effect que faz fetch (re-executa em todo render)
Effect::new(move |_| { spawn_local(async { fetch_user(id).await }); });
```

### Mutações
```rust
// ✅ Action — para submits, forms, operações que mudam estado
let save = Action::new(|input: &String| {
    let input = input.clone();
    async move { api::save(input).await }
});

view! {
    <button on:click=move |_| save.dispatch("hello".to_string())>
        "Save"
    </button>
    <Show when=move || save.pending().get()>
        <p>"Saving..."</p>
    </Show>
}
```

### Renderização condicional e listas
```rust
// ✅ Show — condicional com lazy evaluation
view! {
    <Show when=move || logged_in.get() fallback=|| view! { <Login/> }>
        <Dashboard/>
    </Show>
}

// ✅ For — lista reativa com key para reconciliação eficiente
view! {
    <For
        each=move || items.get()
        key=|item| item.id
        children=move |item| view! { <ItemRow item=item/> }
    />
}
```

### Server functions (fullstack only)
```rust
// ✅ #[server] macro — compila para HTTP call no client, fn real no server
#[server(SaveUser, "/api")]
pub async fn save_user(name: String) -> Result<User, ServerFnError> {
    // Este código só roda no server (feature = "ssr")
    let user = db::create_user(name).await?;
    Ok(user)
}

// No componente — usa como Action normal
let save = ServerAction::<SaveUser>::new();
```

---

## 4. Tipos compartilhados server + WASM

Tipos que precisam existir tanto no server (SQLx, Axum) quanto no client (WASM) usam `cfg_attr`:

```rust
// crates/<projeto>-domain/src/lib.rs  (ou src/models.rs)
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]  // só no server
#[derive(Clone, Debug, Serialize, Deserialize)]       // server + WASM
pub struct SecurityEvent {
    pub id: uuid::Uuid,
    pub attack_type: String,
    pub risk_score: f32,
    pub blocked: bool,
}
```

**Cargo.toml do crate domain:**
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
uuid = { version = "1.10", features = ["v4", "serde"] }

[dependencies.sqlx]
version = "0.8"
features = ["postgres", "runtime-tokio", "uuid"]
optional = true

[features]
ssr = ["dep:sqlx"]
```

> O crate domain é compilado duas vezes: uma para x86 (server, com sqlx) e uma para wasm32 (client, sem sqlx). O `cfg_attr` garante que `sqlx::FromRow` só aparece na compilação server.

---

## 5. Configuração workspace misto (WASM + nativo)

Quando o workspace tem crates Leptos/WASM **e** crates nativos (ex: `napi-rs`, `aya`, Axum):

```toml
# .cargo/config.toml na raiz do workspace
# NÃO definir [build] target global aqui.
# Cada crate define seu próprio target via features e cargo-leptos/trunk.
```

```toml
# Cargo.toml do workspace
[workspace]
resolver = "2"
members = [
  "crates/ars-core",      # lib nativa (x86)
  "crates/ars-server",    # bin nativo — Axum
  "crates/ars-web",       # bin+lib WASM — Leptos
  "crates/ars-cli",       # bin nativo
]
# crates napi-rs ficam em workspace separado ou excluídos do members padrão
```

```toml
# crates/ars-web/Cargo.toml — features separam server de WASM
[features]
default = []
hydrate = ["leptos/hydrate"]
ssr = [
  "dep:axum",
  "dep:leptos_axum",
  "dep:tokio",
  "leptos/ssr",
]
```

> ⚠️ **Antipattern crítico**: adicionar `[build] target = "wasm32-unknown-unknown"` no `.cargo/config.toml` raiz quebra todos os crates nativos. `cargo leptos` e `trunk` gerenciam o target WASM internamente — não interfira.

---

## 6. Antipatterns a evitar

| Antipattern | Por quê | Alternativa |
|---|---|---|
| `wasm_bindgen` direto | Bypassa abstrações do Leptos, código frágil | Use APIs do Leptos (`web_sys` via feature quando necessário) |
| `panic!` em componentes | Derruba o app inteiro sem `ErrorBoundary` | `Result<_, ServerFnError>` + `ErrorBoundary` |
| `Effect` que faz fetch | Re-executa a cada render, difícil de cancelar | `Resource::new()` |
| `tokio::spawn` no client | `tokio` não existe no WASM | `spawn_local()` (wasm) ou só em server functions |
| `std::thread` no client | Não existe no WASM | Leptos signals para paralelismo reativo |
| `cargo leptos test` | Não existe — comando inválido | `cargo test --workspace` |
| `[build] target` global | Quebra crates nativos no workspace misto | Sem target global; cargo-leptos gerencia internamente |

---

## 7. Templates de tasks DARE para Leptos

Cole no `DARE/dare-dag.yaml` após gerar o blueprint:

```yaml
# Task 1 — Workspace + AppShell + Router
- id: leptos-001
  title: "Workspace, AppShell e Router base"
  description: |
    Configurar Cargo workspace com resolver = "2".
    Criar App component com leptos_router::Router.
    Criar layout base (header, main, footer).
    Rota "/" → HomePage component.
    Ralph Loop: cargo leptos build --release + cargo test --workspace + cargo clippy
  depends_on: []

# Task 2 — Form com Action + server function
- id: leptos-002
  title: "Form com Action e validação server-side"
  description: |
    Criar #[server] fn para processar o form.
    Criar componente com ActionForm ou Action manual.
    Validar input no server (retorna ServerFnError em caso de erro).
    Exibir pending state com Action::pending() signal.
    Ralph Loop: cargo leptos build --release + cargo test --workspace
  depends_on: [leptos-001]

# Task 3 — Lista paginada com Resource + Suspense
- id: leptos-003
  title: "Lista paginada com Resource, Suspense e error handling"
  description: |
    Criar Resource que recebe página como signal de parâmetro.
    Envolver em Suspense com fallback de loading.
    Usar ErrorBoundary para erros de fetch.
    Adicionar paginação com For component e key por ID.
    Ralph Loop: cargo leptos build --release + cargo test --workspace
  depends_on: [leptos-001]
```

---

## 8. O que fazer agora

1. **Leia `DARE/DESIGN.md`** para entender quais componentes e server functions são necessários
2. **Rode `cargo leptos watch`** (fullstack) ou **`trunk serve`** (CSR) para confirmar que o scaffold compila
3. **Gere `DARE/BLUEPRINT.md`** com `/dare-blueprint` — inclua:
   - Tabela de componentes (nome, props, signals usados)
   - Lista de server functions com assinatura
   - Tipos compartilhados no crate domain
4. **Use `/dare-rust-workspace`** se precisar decidir estrutura multi-crate

$ARGUMENTS
