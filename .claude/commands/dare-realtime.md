# /dare-realtime

Comunicação real-time (WebSocket, SSE) DARE-compliant — eventos tipados, subscriptions autorizadas, reconexão com backoff, zero ghost listeners.

## Como usar

```
/dare-realtime                    # audita uso de WS/SSE no projeto
/dare-realtime scaffold ws        # gera event registry + subscription manager + reconnect
/dare-realtime audit ghosts       # detecta listeners sem cleanup
```

## Os 4 pilares

### 1. Schema validation de eventos

Todo evento WS/SSE tem schema JSON. Server valida antes de emitir, client valida antes de processar.

### 2. Registro central de tipos

Um único `event_registry.ts` lista todos os event types com versão (`.v1`, `.v2`).

### 3. Reconexão com exponential backoff

```typescript
class ReconnectStrategy {
  private attempt = 0;
  next(): number {
    const base = Math.min(1000 * 2 ** this.attempt, 30_000);
    return base + Math.random() * 1000; // jitter
  }
  reset() { this.attempt = 0; }
}
```

### 4. Subscription manager (zero ghost listeners)

Map de subscriptions com cleanup automático on disconnect.

## Métricas obrigatórias

| ID | Métrica |
|---|---|
| M-01 | 100% de event types com JSON Schema |
| M-02 | 100% de subscriptions autorizadas |
| M-03 | 0 ghost listeners após desconexão |
| M-04 | Estratégia de reconexão configurada |

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | Evento sem schema | Adicionar no registry |
| AP-02 | `socket.on()` sem cleanup | SubscriptionManager |
| AP-03 | Reconexão sem backoff | Exponential + jitter |
| AP-04 | Sem autorização de subscription | `authorize()` antes de `subscribe()` |
| AP-05 | Broadcast sem filtro | Rooms por tenant |
| AP-06 | Estado stale após reconectar | Resync via REST/snapshot |

## O que fazer

### Passo 1: Event Registry

```typescript
export const EventRegistry = {
  'user.created.v1': { schema: UserCreatedSchema, requires: 'admin' },
  'message.sent.v1': { schema: MessageSentSchema, requires: 'participant' },
};
```

### Passo 2: Subscription Manager

```typescript
class SubscriptionManager {
  private subs = new Map<string, Set<string>>();

  subscribe(connId: string, event: string) {
    if (!this.subs.has(connId)) this.subs.set(connId, new Set());
    this.subs.get(connId)!.add(event);
  }

  onDisconnect(connId: string) {
    this.subs.delete(connId); // cleanup SEMPRE
  }
}
```

### Passo 3: Reconnect com backoff

```typescript
const strategy = new ReconnectStrategy();
socket.on('disconnect', () => {
  setTimeout(() => socket.connect(), strategy.next());
});
socket.on('connect', () => {
  strategy.reset();
  resyncState(); // buscar eventos perdidos via REST
});
```

### Passo 4: Autorização por subscription

```typescript
socket.on('subscribe', (eventType) => {
  if (!authorize(socket.user, eventType)) {
    return socket.emit('error', { code: 'FORBIDDEN' });
  }
  subscriptionManager.subscribe(socket.id, eventType);
});
```

### Passo 5: Validação no server e client

```typescript
// Server antes de emitir
const valid = EventRegistry[eventType].schema.safeParse(payload);
if (!valid.success) return log.error('invalid event', valid.error);
io.to(room).emit(eventType, valid.data);

// Client antes de processar
socket.on(eventType, (payload) => {
  const valid = EventRegistry[eventType].schema.safeParse(payload);
  if (!valid.success) return log.warn('invalid event received');
  handleEvent(valid.data);
});
```

## Stack recomendada

| Stack | WebSocket | SSE |
|---|---|---|
| Node | `socket.io`, `ws` | `eventsource` + endpoint custom |
| Rails | Action Cable | Rack streaming |
| Rust/Axum | `tokio-tungstenite` | `axum::sse::Sse` |
| FastAPI | `fastapi.WebSocket` | `EventSourceResponse` |
| Go | `gorilla/websocket` | stdlib `http.Flusher` |

## Boas práticas

1. **SSE para server→client unidirecional** (logs, métricas)
2. **WS para bidirectional** (chat, colaboração)
3. **Rooms/channels por tenant** — evita cross-tenant
4. **Heartbeat ping-pong** — detectar conexão zumbi
5. **Backpressure** — drop eventos antigos se client lento
6. **Replay limitado** — últimos N eventos por room para reconexão recente

## Saída esperada

Reporte:
- Lista de event types e seus schemas (ou falta de)
- Subscriptions sem autorização
- Listeners sem cleanup (grep `socket.on` sem `removeListener` ou cleanup)
- Stack escolhida e configuração de reconnect

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
