# Caminhos de Ataque Derivados de Evidência

`dare-agent-security validate attack-paths` pega os artefatos que os motores de
validação já escreveram e os une em um único grafo de ataque. Em seguida, enumera os
caminhos que vão de onde um atacante pode começar até o que um atacante quer, e marca
cada caminho com o estado dos controles que o guardam.

Ele só lê arquivos locais. Não executa motor, não envia nada e não executa nenhum
caminho.

## A pergunta que responde

> Dado o que os motores observaram, quais cadeias de relações levam de um ponto de
> entrada a um alvo sensível? Em cada cadeia, todo controle que a guarda se manteve,
> algum falhou, ou algum nunca foi decidido?

Um único achado `FAIL` diz que uma fronteira quebrou. Um caminho diz ao que essa
quebra se conecta.

## Entradas

```bash
dare-agent-security validate attack-paths \
  --artifacts .dare-agent-security/rag-security \
  --artifacts .dare-agent-security/identity-security \
  --system-model system-model.json \
  --output-dir .dare-agent-security/attack-paths
```

- **`--artifacts`** recebe o diretório de saída de um motor, de 1 a 64 deles. Cada
  diretório contém o resultado e a evidência de exatamente um motor. O diretório também
  precisa das entradas do motor que o resultado fixa, em `inputs/`:

  | Motor | O que `inputs/` contém |
  |---|---|
  | tool, identity, memory, RAG, MCP Auth | `scenario.json`, o cenário que o resultado nomeia por digest |
  | supply chain, A2A | nada para um id de cenário embutido; caso contrário `scenario.json` mais o diretório `evidence/` (modo static) ou a captura (replay) |
  | prompt injection, multi-turn | nada: resultado e evidência bastam |
  | remote (`validate replay-capture`) | nada |
  | runtime telemetry | `policy.json`, a política de tempo de execução que o resultado fixa por digest; sem ela a execução é contada como só-resultado e não projeta nada |

  Cada entrada é revinculada ao digest que seu resultado fixa, com a própria função de
  digest do motor responsável. Várias coisas são recusadas: um cenário editado, um
  byte de evidência alterado, um link simbólico, um caminho que sai do diretório, um
  arquivo acima de 16 MiB, JSON com mais de 64 níveis e a mesma execução passada duas
  vezes. Uma recusa sai com `3` e não escreve nada.
- **`--system-model`** (opcional) nomeia as entidades do seu sistema e diz qual id
  local de motor é qual entidade. Sem ele, as execuções não são unidas: cada nó fica
  restrito à execução que o produziu. Veja a
  [referência do system model](https://darelabs-tech.github.io/dare-agent-security/en/reference/attack-path-system-model.html)
  (em inglês).
- **Limites.**

  | Limite | Padrão | Máximo |
  |---|---|---|
  | `--max-path-edges` | 8 | 12 |
  | `--max-paths` | 10.000 | 10.000 |
  | `--max-paths-per-pair` | 64 | 64 |
  | Passos de busca | 5.000.000 | fixo |

  Um valor acima do máximo é recusado, não ajustado.

## Como o grafo é construído

1. **Projeção.** O resultado de cada motor vira nós, arestas e guardas por uma tabela
   fixa por motor:
   - um documento recuperado `TRANSFERS_TO` o principal que o leu;
   - um principal `USES_CREDENTIAL`;
   - um agente par `CALLS` o agente sob teste;
   - um pacote `TRANSFERS_TO` o componente que depende dele;
   - e assim por diante.

   Cada aresta cita os registros de evidência que a observaram, ou a entrada fixada
   que a declara.
2. **Guardas.** Uma propriedade que o motor testou vira uma guarda nas arestas que ela
   protege, com o veredito do motor. Quando um `FAIL` nomeia entidades específicas, o
   `FAIL` fica nas arestas que as tocam, e as demais arestas guardadas daquela execução
   passam a `INCONCLUSIVE`. Nenhum veredito é decidido de novo.
3. **Identidade.** Dois motores que mencionam `user-7` **não** são tratados como a
   mesma pessoa. Nós só se unem quando o system model dá alias de ambos para uma
   entidade.
4. **Designação.** Pontos de entrada são:
   - entrada não confiável, conteúdo externo, documento recuperado, escrita em memória;
   - agente par, componente da cadeia de suprimentos, principal de baixo privilégio.

   Alvos são:
   - recursos sensíveis, credenciais privilegiadas e capacidades destrutivas;
   - recursos de outro tenant;
   - publicação externa.

   Os motores designam o que só eles podem afirmar, e o system model pode acrescentar
   ou excluir qualquer designação.

## Caminhos viáveis e descontínuos

Um caminho é **viável** quando cada passo é explicado pela autoridade que o caminho
carregou até ali:
- uma delegação ou autenticação repassa autoridade;
- conteúdo que chega a um agente o conduz;
- um acesso feito por um ator que age sob o principal atual continua o caminho.

O primeiro passo que nada explica torna o caminho **`DISCONTINUOUS`**. Um exemplo é um
acesso feito sob um principal que o caminho nunca adquiriu. Esse passo é informado com
o seu índice. Um caminho descontínuo é listado à parte. Ele nunca reprova o gate e
nunca forma um ponto de estrangulamento.

## Estado de controle

Cada caminho viável recebe exatamente um estado de controle:

| Estado | Significado |
|---|---|
| `CONTROL_FAILED` | Uma guarda do caminho é `FAIL`. As guardas que falharam são listadas |
| `CONTROL_UNDECIDED` | Nenhuma guarda falha, mas uma aresta está `INCONCLUSIVE`, em `ERROR` ou sem guarda alguma. As arestas indecididas são listadas |
| `CONTROLS_HELD` | Toda aresta do caminho tem guarda, e toda guarda é `PASS` |

O estado de um caminho nunca é melhor que o da sua aresta mais fraca. Arestas
estruturais (`BELONGS_TO_TENANT`, `ENFORCED_BY`) declaram fatos, não acessos, e por
isso não exigem guarda. Uma relação que só o system model declara é `INFERRED` e nunca
é avaliada. Um caminho que passa por ela é, na melhor das hipóteses,
`CONTROL_UNDECIDED`.

**Pontos de estrangulamento** são as arestas que todo caminho reprovado até um alvo
compartilha. Corrigir um deles corta todos os caminhos reprovados enumerados até aquele
alvo. Ele é marcado `partial` quando a enumeração foi truncada. É uma contagem, não uma
pontuação.

## Saídas

| Arquivo | Conteúdo |
|---|---|
| `attack-graph.json` | o grafo v2: nós, arestas com evidência e guardas, pontos de entrada, alvos, e os artefatos e o modelo de origem |
| `attack-paths.json` | caminhos viáveis, caminhos descontínuos, pontos de estrangulamento e o registro da enumeração (limites, passos usados, truncamento e o limite que a interrompeu) |
| `projection-report.json` | por artefato: entradas verificadas, contagem de fatos, o que não foi projetado e por quê; aliases usados e não usados |
| `graph.mmd`, `graph.dot` | visões com evidência e estado de controle escritos como texto |
| `summary.md` | contagem por estado de controle, os caminhos, os pontos de estrangulamento e o que o resultado não afirma |

Os mesmos artefatos, em qualquer ordem, produzem arquivos idênticos byte a byte.
Nenhuma saída carrega horário.

## Códigos de saída

| Código | Significado |
|---|---|
| 0 | Todo caminho viável é `CONTROLS_HELD` (ou não há nenhum), e nada foi truncado |
| 1 | Erro interno |
| 2 | Um caminho viável é `CONTROL_FAILED` ou `CONTROL_UNDECIDED`, ou a enumeração foi truncada |
| 3 | Recusa: entrada inválida ou não vinculada, ou limite acima do máximo. Nada é escrito |

Um gate não passa sobre o que não foi decidido.

## O que um resultado não afirma

- **`CONTROLS_HELD` não significa "seguro".** Significa que todo controle que guarda um
  caminho enumerado foi observado se mantendo nas execuções que você forneceu, e nada
  além disso.
- **Caminhos mais longos que `--max-path-edges` não são cobertos.** Também não é coberta
  nenhuma relação que nenhum artefato e nenhuma linha do system model declare. Um
  caminho ausente não prova que nenhum caminho existe.
- **Saída `0` sem caminhos pode significar que nada foi testado.** Um motor que você
  não executou não contribui com aresta. Uma cadeia que depende dessa relação
  simplesmente não aparece.
- **Nenhum caminho foi executado.** Os caminhos são construídos a partir do que os
  motores observaram, e a maioria dos motores executa cenários sintéticos. O resumo
  informa quantos artefatos vieram de execuções sintéticas e quantos de execuções
  remotas autorizadas.

## Integração com o produto

A fixture do produto pode nomear um grafo escrito por este comando, com
`"attack_graph_v2": "<caminho dentro do alvo>"`. `dare-agent-security assess` então
valida o grafo com o contrato v2 e o grava como o `attack-graph.json` da execução. O
produto não constrói o grafo por conta própria.
