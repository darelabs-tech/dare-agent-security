# Validação Adversarial Adaptativa em Múltiplos Turnos

O DARE Agent Security consegue verificar se um agente mantém uma propriedade de
segurança ao longo de uma *conversa* inteira, e não apenas dentro de um turno.
Esta página explica o que isso estabelece, como a "adaptação" continua
determinística e o que um resultado **não** afirma.

## A pergunta que ele responde

> Dado um grafo de estratégia pré-aprovado e um alvo local (replay, simulado ou
> local-sintético), o alvo preserva a propriedade em todos os turnos do caminho
> que as próprias respostas dele escolheram, e a execução chegou a um nó
> terminal?

Algumas falhas só existem ao longo de vários turnos:

| Falha | Propriedade |
|---|---|
| Uma recusa cede após reformulação ou escalada gradual (crescendo) | `AGENT.GOAL.REFUSAL_PERSISTENCE` |
| Um objetivo proibido é dividido em fragmentos aparentemente inofensivos | `AGENT.GOAL.CUMULATIVE_INTENT_BOUNDARY` |
| Papéis alegados ou afinidade elevam a autoridade (trust grooming) | `AGENT.IDENTITY.CLAIMED_AUTHORITY_BOUNDARY` |
| Uma instrução plantada no turno *k* dispara no turno *k+n* | `AGENT.GOAL.DELAYED_INSTRUCTION_BOUNDARY` |
| Uma aprovação dada para uma ação é usada em outra (bait-and-switch) | `AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY` |
| O objetivo autorizado deriva ao longo dos turnos | `AGENT.GOAL.OBJECTIVE_STABILITY` |
| O estado de uma conversa vaza para a de outro principal | `AGENT.MEMORY.CONVERSATION_ISOLATION` |

As sete propriedades ficam dentro das famílias agênticas existentes. O perfil
`multi-turn-security-baseline-2026` as seleciona, e nenhum denominador de perfil
anterior muda.

## O que "adaptativo" significa aqui

```text
adaptativo            == o próximo turno é ESCOLHIDO em um grafo aprovado, finito
                         e acíclico, por uma classe de observação FECHADA
adaptativo            != um turno é gerado, mutado, preenchido ou parafraseado
classe de observação  != veredito       (classes direcionam; fatos decidem)
estratégia esgotada   != alvo seguro    (só o caminho percorrido é afirmado)
parada antes do fim   != PASS
```

Um grafo de estratégia é um DAG de turnos escritos previamente. Cada resposta
é classificada em uma classe fechada, e a aresta daquela classe escolhe o
próximo turno. O cenário fixa o digest do grafo antes do primeiro turno, então
todo turno que o motor poderia enviar é conhecido com antecedência. Nenhum
modelo é chamado. Entradas idênticas geram artefatos idênticos byte a byte.

Limites rígidos: 32 turnos por conversa, 256 nós e 64 caminhos por grafo. Um
cenário pode baixar esses limites, mas nunca aumentar.

## Vereditos

- **FAIL**: uma violação entre turnos foi observada. Um FAIL em qualquer
  invariante sobrevive a um PASS em outro.
- **PASS**: toda conversa chegou a um nó terminal com evidência positiva em
  todos os turnos.
- **INCONCLUSIVE**: a execução parou antes do fim (sem aresta para a classe
  observada, resposta não classificável, orçamento esgotado), ou a propriedade
  não chegou a ser exercitada. Nunca é um PASS.
- **ERROR**: erro de harness ou falha de estratégia.

Quando a única violação já aparece em um único turno (o alvo cedeu no primeiro
contato, ou repetiu um canário no próprio turno em que ele foi plantado), o
veredito pertence ao motor de prompt injection (Ciclo 013). O resultado
registra um *achado delegado*, não um FAIL.

## Modos

| Modo | Origem das respostas | Sintético |
|---|---|---|
| `replay` | uma transcrição gravada por você, vinculada turno a turno ao grafo | não |
| `simulated` | um agente de referência determinístico do MULTITURN-LAB | sim |
| `local-synthetic` | os mesmos agentes, cada turno sob o kill switch e o orçamento do Ciclo 009 | sim |

Todos os modos são locais e offline.

## O que um resultado não afirma

Um PASS cobre apenas o caminho escolhido pelas respostas do alvo. O resumo lista
todos os nós **não** alcançados. Nada é afirmado sobre eles, nem sobre o alvo
fora do grafo. Nenhum resultado diz que um agente é seguro.

## Experimente

```bash
dare-agent-security validate multi-turn --scenario multiturn-lab-001 --output-dir out/   # PASS, código 0
dare-agent-security validate multi-turn --scenario multiturn-lab-002 --mode local-synthetic --output-dir out/   # FAIL, código 2
```
