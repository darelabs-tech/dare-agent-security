# /dare-frontend-design

Arquitetura frontend DARE para projetos React e Vue. Detecta god components, fetch inline em JSX/template, e gera scaffold DARE-compliant.

## Como usar

```
/dare-frontend-design                    # audita projeto atual
/dare-frontend-design lint               # roda checks AP-01 a AP-06
/dare-frontend-design scaffold <página>  # gera Page + Container + Hook + Presentational
```

## Arquitetura

```
Page  →  Container (lógica)  →  Presentational (puro)
           ↑
        Hook (fetch + cache)
```

## As 4 regras

### 1. Componente < 300 linhas

Se passar de 300, quebrar em sub-componentes, hooks ou helpers.

### 2. Zero `fetch()` em JSX/template

Use TanStack Query (React/Vue), SWR ou similar. Hook devolve `{ data, isLoading, error }`.

### 3. Error Boundary em cada Page

React: `<ErrorBoundary>` wrapping rotas.
Vue: `onErrorCaptured` em layout/page-level.

### 4. Bundle size monitorado

`rollup-plugin-visualizer`, `webpack-bundle-analyzer`. Limite por chunk (ex: <300KB inicial).

## Métricas obrigatórias

| ID | Métrica |
|---|---|
| M-01 | 100% de componentes < 300 linhas |
| M-02 | 0 `fetch()` direto em JSX/template |
| M-03 | 100% de páginas com error boundary |
| M-04 | Bundle config presente |

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | God component (>300 linhas) | Quebrar em sub-componentes + hooks |
| AP-02 | Fetch em JSX | Mover para hook |
| AP-03 | Booleanos isLoading espalhados | Discriminated union de estados |
| AP-04 | Sem error boundary | Wrap em `<ErrorBoundary>` |
| AP-05 | Estilo inline pesado | CSS module/styled |
| AP-06 | Props drilling profundo | Context/Zustand/Pinia |

## O que fazer

### Passo 1: Detectar god components

```bash
find src/ -name "*.tsx" -o -name "*.vue" | xargs wc -l | sort -rn | head -20
```

### Passo 2: Detectar fetch inline

```bash
grep -rn "fetch(\|axios\." src/components/ src/pages/
```

### Passo 3: Migrar para hooks de dados

```tsx
// Antes
function UserList() {
  const [users, setUsers] = useState([]);
  useEffect(() => { fetch('/api/users').then(r => r.json()).then(setUsers); }, []);
  return <ul>{users.map(...)}</ul>;
}

// Depois
function UserList() {
  const { data, isLoading, error } = useUsers();
  if (isLoading) return <Spinner />;
  if (error) return <ErrorMessage error={error} />;
  return <ul>{data.map(...)}</ul>;
}

function useUsers() {
  return useQuery({ queryKey: ['users'], queryFn: () => api.users.list() });
}
```

### Passo 4: Error boundaries

```tsx
// React
class ErrorBoundary extends React.Component { ... }

<ErrorBoundary fallback={<ErrorPage />}>
  <UserList />
</ErrorBoundary>
```

```vue
<!-- Vue -->
<script setup>
import { onErrorCaptured } from 'vue';
onErrorCaptured((err) => { logError(err); return false; });
</script>
```

### Passo 5: Bundle analyzer

```typescript
// vite.config.ts
import { visualizer } from 'rollup-plugin-visualizer';
export default {
  plugins: [visualizer({ open: false, gzipSize: true })],
  build: { chunkSizeWarningLimit: 300 }
};
```

## Stack recomendada

| Camada | React | Vue |
|---|---|---|
| Roteamento | React Router / Next | Vue Router / Nuxt |
| Estado server | TanStack Query | TanStack Vue Query |
| Estado client | Zustand / Jotai | Pinia |
| Styling | Tailwind / CSS Modules | Tailwind / SCSS |
| Testes | Vitest + Testing Library | Vitest + Testing Library |

## Saída esperada

Reporte:
- Top 10 componentes com mais linhas
- Lista de `fetch()`/`axios` inline em componentes
- Páginas sem error boundary
- Configuração de bundle (presente/ausente)

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
