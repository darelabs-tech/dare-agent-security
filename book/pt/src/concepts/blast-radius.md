# Raio de Impacto (Blast Radius)

`dare-agent-security validate blast-radius` pega um grafo de ataque escrito por
[`validate attack-paths`](attack-paths.md) e um conjunto de pontos de partida
comprometidos, chamados **sementes** (seeds). Ele informa o que cada semente consegue
alcançar. Para cada alvo alcançado, informa também se um controle observado se mantendo
fica entre a semente e esse alvo.

Ele só lê arquivos locais. Não executa motor, não envia nada e não executa nenhum
alcance.

## A pergunta que responde

> Se este principal, esta credencial, este conteúdo ou este componente fosse
> comprometido, quais alvos sensíveis o atacante alcançaria pelas relações que os
> motores observaram? Para cada alvo, alguma rota chega lá sem cruzar um controle que se
> manteve?

Um caminho de ataque parte de um ponto de entrada designado. Um raio de impacto parte do
que você diz que foi comprometido, e informa o alcance em contagens e rotas, nunca como
pontuação.

## Entradas

```bash
dare-agent-security validate blast-radius \
  --graph .dare-agent-security/attack-paths/attack-graph.json \
  --compromise compromise.json \
  --output-dir .dare-agent-security/blast-radius
```

- **`--graph`** é o `attack-graph.json` v2. Ele é admitido com limite de 16 MiB, até 64
  níveis de JSON e sem link simbólico, e depois validado pelo contrato v2. Um grafo
  editado depois que `validate attack-paths` o selou é recusado.
- **`--compromise`** nomeia as sementes. Como alternativa, **`--seed-entry-points`**
  usa como semente todo ponto de entrada do grafo. Exatamente um dos dois é obrigatório.

  ```json
  {"schema_version": "1", "scenario_id": "inbound-token-leak",
   "graph_id": "graph:<64 hex>",
   "seeds": [{"node_id": "node:credential:inbound-token", "kind": "CREDENTIAL_LEAK"}]}
  ```

  `graph_id` vincula o cenário a um grafo, e um cenário de outro grafo é recusado. Uma
  semente nomeia um `node_id`, ou um `entity_id` que nomeie exatamente um nó. São até 64
  sementes.
- **Limites.** Um valor acima do máximo é recusado, não ajustado. O cenário pode
  reduzir um limite ainda mais.

  | Limite | Padrão | Máximo |
  |---|---|---|
  | `--max-depth` (arestas por percurso) | 8 | 12 |
  | `--max-states` (por busca) | 1.000.000 | 1.000.000 |
  | Estados no total | 5.000.000 | fixo |

## Tipos de semente

| Tipo | Serve para | O atacante começa como |
|---|---|---|
| `PRINCIPAL_TAKEOVER` | humano, agente, identidade | esse principal, agindo como ele mesmo |
| `CREDENTIAL_LEAK` | credencial | um portador dessa credencial |
| `CONTENT_INJECTION` | dado | conteúdo sem principal próprio, que conduz o agente que alcança |
| `COMPONENT_COMPROMISE` | ferramenta, servidor MCP, capacidade, serviço downstream | o próprio componente, sem principal próprio |

Um tipo que não serve para o seu nó é recusado. Com `--seed-entry-points`, a classe do
ponto de entrada define o tipo: principal de baixo privilégio ou agente par vira
takeover; entrada não confiável, conteúdo externo, documento recuperado ou escrita em
memória vira injeção; componente da cadeia de suprimentos vira comprometimento de
componente.

Um componente comprometido não ganha um principal que nunca adquiriu. Ele segue por
acessos sem principal nomeado, pelas credenciais que usa e pelas delegações que faz. Mas
um acesso que o grafo diz rodar sob um principal nomeado é recusado, a menos que o
percurso tenha adquirido esse principal. O passo é contado, não dado.

## Como o alcance é calculado

Cada passo segue a mesma regra de continuidade dos [caminhos de ataque](attack-paths.md).
A delegação repassa autoridade. Uma credencial a amplia. O conteúdo conduz o agente que
alcança. Um acesso só continua sob um ator que age pelo principal atual. Um passo que
nenhuma regra explica não é dado, e é contado em `refused_steps`.

Cada semente é buscada duas vezes:

- **Visão estrutural:** todas as relações.
- **Visão não contida:** só as relações em que nenhum controle foi observado se
  mantendo. Uma aresta está mantida quando tem guardas e todas são `PASS`.

| Exposição | Significado |
|---|---|
| `EXPOSED` | a visão não contida alcança o alvo; a rota é informada, com os controles que falharam ou ficaram indecididos |
| `CONTAINED` | só a visão estrutural alcança o alvo, e a busca não contida terminou; a **fronteira** lista as arestas mantidas na rota estrutural |
| `CONTAINMENT_UNKNOWN` | só a visão estrutural alcança o alvo, e a busca não contida foi cortada por um limite, então a contenção não foi demonstrada |

A busca percorre passeios (walks), não só caminhos simples. Todo estado de autoridade
alcançável dentro de `--max-depth` é encontrado, então `CONTAINED` nunca é afirmado
enquanto existir um passeio não contido dentro dos limites. O **delta de remediação**
informa, para cada aresta que falhou numa rota exposta, quantos alvos expostos as suas
sementes deixariam de alcançar se os controles dessa aresta se mantivessem.

## Saídas

| Arquivo | Conteúdo |
|---|---|
| `blast-radius.json` | por semente, o registro das duas buscas, cada alvo com exposição e rotas, e contagens de impacto por visão (alvos por classe, tenants alcançados, fronteiras de confiança cruzadas, credenciais privilegiadas adquiridas); depois totais, fronteira e delta de remediação |
| `graph.mmd`, `graph.dot` | o subgrafo alcançado, com tags `[seed …]`, `[exposed]`, `[contained]` e `[unknown]` e rótulos de aresta `held` / `FAIL <propriedade>`, tudo escrito como texto |
| `summary.md` | as contagens, as rotas por semente (no máximo 50, o resto no JSON), a fronteira, o delta, o registro da busca e o que o resultado não afirma |

As mesmas entradas produzem arquivos idênticos byte a byte, e nenhuma saída carrega
horário. Cada arquivo é verificado contra valores com formato de credencial antes que o
primeiro seja gravado.

## Códigos de saída

| Código | Significado |
|---|---|
| 0 | Nenhum alvo `EXPOSED`, e nada foi truncado |
| 1 | Erro interno |
| 2 | Um alvo `EXPOSED`, ou uma busca truncada |
| 3 | Recusa: grafo ou cenário inválido, semente desconhecida, ambígua ou de tipo incompatível, ou limite fora da faixa. Nada é escrito |

## O que um resultado não afirma

- **`CONTAINED` não significa "seguro".** Significa apenas que toda rota até o alvo
  dentro de `--max-depth` cruza um controle observado se mantendo nas execuções que você
  forneceu.
- **Não alcançado não é inalcançável.** Uma relação que nenhum artefato e nenhuma linha
  do modelo declara não está no grafo.
- **Nenhum alcance foi executado.**
- **O delta de remediação não é um ranking de risco.** Ele conta o que os controles de
  uma aresta conteriam se se mantivessem.
