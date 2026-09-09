# Segurança A2A e de Comunicação Entre Agentes

O DARE Agent Security consegue validar se uma relação agente-a-agente
permaneceu dentro das fronteiras aprovadas para ela: quem o peer de fato era, o
que a mensagem realmente provou, o que o peer tinha permissão de pedir e até
onde a autoridade viajou. Esta página descreve o que isso estabelece e,
igualmente importante, o que não estabelece.

## A pergunta que ele responde

O motor responde a uma única pergunta:

> Os Agent Cards locais, as trocas capturadas, os resultados de verificação
> registrados, os registros de delegação e a política local mostram que todos os
> invariantes de comunicação entre agentes aplicáveis permaneceram satisfeitos?

Ele não é um cliente A2A, um crawler de descoberta, um provedor de identidade
nem uma ferramenta de teste de intrusão. Ele não contata nada. Um peer que
pareça desconhecido não é um achado. Um achado exige um fato determinístico que
contradiga um invariante declarado.

## As relações em que tudo se apoia

```text
agente externo listado         != peer confiável
Agent Card descoberto          != identidade autenticada
Agent Card assinado            != provedor autorizado
identidade TLS do servidor     != autorização em nível de agente
esquema de segurança declarado != autenticação bem-sucedida
autenticação bem-sucedida      != autorização de skill
mensagem válida no schema      != mensagem autêntica
mensagem autêntica             != instrução autorizada
conteúdo do peer               != instrução privilegiada
taskId coincidente             != principal/contexto coincidentes
delegação                      != amplificação de privilégio
reenvio de mensagem            != replay seguro
compatibilidade de protocolo   != permissão para fazer downgrade
declaração de extensão         != autoridade da extensão
URL de webhook                 != permissão para conectar
valor de roteamento de tenant  != prova de autorização de tenant
```

Cada uma delas é um ponto em que duas coisas parecidas não são a mesma coisa, e
cada uma é a razão de existir do invariante correspondente.

> **Um Agent Card é uma afirmação do agente que ele descreve.** Ele pode dizer
> que um peer é operado pela Acme e suporta OAuth; ele não pode dizer que a Acme
> foi aprovada nem que o OAuth teve sucesso. A aprovação vem de uma política
> local que a implantação controla, e um card que declara `"trusted": true`
> sobre si mesmo é recusado, não acreditado.
>
> **Descoberta não é identidade.** Encontrar um card em um endereço diz que algo
> foi publicado ali. Não diz nada sobre quem respondeu quando uma mensagem foi
> enviada.
>
> **Uma assinatura em um card não é autorização.** Um card corretamente assinado
> prova que o card não foi alterado. Se o provedor dele é aceito por esta
> implantação é outra pergunta, respondida pela política.
>
> **Identidade de transporte não é identidade de agente.** Um certificado TLS
> válido identifica um servidor. Uma skill A2A é invocada por um *sujeito*, e as
> duas coisas não estão na mesma camada.
>
> **Autenticação não é autorização.** Um peer que se autenticou perfeitamente
> estabeleceu quem é. O que ele pode fazer, e em nome de quem, ainda não foi
> perguntado.
>
> **Uma assinatura sobre uma mensagem não é uma assinatura sobre *esta*
> mensagem.** A substituição mais importante é uma assinatura genuína e válida
> retirada de outra troca. Só comparar o digest do envelope coberto distingue as
> duas.
>
> **Conteúdo do peer é dado.** Se ele virou instrução é um fato sobre o
> consumidor local, não sobre o texto — e é a única coisa que a fronteira de
> autoridade pergunta.
>
> **Um `taskId` coincidente é um identificador de correlação coincidente.** Duas
> mensagens podem correlacionar perfeitamente e carregar principals iniciadores
> diferentes, que é o modo de falha mais parecido com um sistema funcionando.
>
> **Uma repetição não é um achado de replay.** Uma leitura repetida é normal, e
> uma repetição com chave de idempotência ou sobre uma skill que a política
> declara idempotente está comprovadamente segura. O que não está é uma mudança
> de estado não idempotente repetida sem nenhuma das duas.
>
> **Uma alegação de tenant é um valor de roteamento escolhido pelo remetente.**
> Onde a política não registra nada sobre o sujeito, a alegação não pode ser nem
> confirmada nem contraditada, e a resposta é *indecidível* em vez de qualquer
> um dos veredictos.

## Os catorze invariantes

| | Invariante | Pergunta |
|---|---|---|
| I01 | vínculo de descoberta preservado | o card em mãos é o card que a política aprovou? |
| I02 | identidade do peer vinculada | a parte autenticada é o agente, a audiência e o tenant pretendidos? |
| I03 | autenticidade da mensagem estabelecida | a evidência de autenticação vincula *esta* mensagem? |
| I04 | requisito de segurança satisfeito | o mecanismo usado satisfaz um requisito aprovado? |
| I05 | skill autorizada | o sujeito efetivo pode invocar a skill que foi invocada? |
| I06 | fronteira de autoridade da mensagem preservada | o conteúdo controlado pelo peer permaneceu dado? |
| I07 | vínculo de task/contexto preservado | task, contexto e principal iniciador permaneceram os mesmos? |
| I08 | propagação de autoridade limitada | a autoridade se manteve ou estreitou a cada salto? |
| I09 | fronteira de tenant preservada | a troca permaneceu dentro do tenant aprovado? |
| I10 | fronteira de escopo de dados preservada | a divulgação permaneceu dentro do que a política permitia? |
| I11 | fronteira de replay preservada | uma ação repetida foi comprovadamente segura de repetir? |
| I12 | integridade da negociação de protocolo | a versão e a interface usadas eram permitidas pela política? |
| I13 | fronteira de confiança de extensão preservada | as extensões foram declaradas, aprovadas e não autoritativas? |
| I14 | fronteira de push notification preservada | um callback divulga apenas até onde foi aprovado? |

## Três respostas, não duas

Todo invariante pode reportar que **se manteve**, que foi **violado**, ou que a
evidência não permitiu decidir. A terceira não é uma versão mais fraca da
primeira.

A evidência de verificação carrega um de quatro status, e apenas dois decidem
alguma coisa:

| Status | Significado | Pode satisfazer um PASS | É falha concreta |
|---|---|---|---|
| `VALID` | um verificador checou e se manteve | sim | não |
| `INVALID` | um verificador checou e falhou | não | **sim** |
| `INDETERMINATE` | um verificador não conseguiu decidir | não | não |
| `UNRECORDED` | ninguém checou | não | não |

Evidência ausente nunca é lida como sucesso. Um operador que vê PASS acredita
que uma pergunta foi feita e respondida; se a pergunta nunca foi feita, essa
crença é todo o dano.

Separadamente, um invariante sem nenhum sujeito na evidência é *não aplicável*,
não indeciso. Uma troca que não registra nenhum callback não deixou de provar
nada sobre callbacks — a pergunta não se coloca, e reportá-la como INCONCLUSIVE
tornaria ilegível toda execução limpa.

## O que o motor nunca faz

Ele não contata nenhum agente. Não baixa Agent Card, não consulta `.well-known`
nem registries, não resolve JWK, JWKS ou `jku`, não obtém nem apresenta segredo
OAuth, OIDC, bearer, API key ou client credentials, não executa handshake TLS,
não envia mensagem, não cria nem cancela task remota e não invoca callback. Ele
não executa nada que apareça na evidência que lê.

Uma URL de interface, issuer, token endpoint, localização de key set, URL de
Agent Card ou webhook lida de um documento local é **metadado inerte**. Ela é
retida para que um relatório possa nomear onde o peer disse morar, e resolvida
por nada.

Isso é estrutural, não prometido: o motor não declara cliente HTTP, pilha TLS,
biblioteca JWT, resolvedor JWKS, cliente OAuth nem runtime assíncrono, e um
teste falha se algum aparecer.

## O que significa um PASS

> Um PASS significa que os invariantes aplicáveis permaneceram satisfeitos sob a
> evidência local analisada.

Não é uma afirmação de que um agente remoto é seguro, de que um peer é confiável
ou de que uma troca que ninguém capturou foi segura. O artefato e o resumo dizem
isso no próprio texto, porque um leitor pode ver apenas um dos dois.

## Com o que isso compõe

Este motor carrega apenas a *projeção* A2A de relações que outros ciclos possuem,
e não assume autoridade de veredicto sobre nenhuma delas: injeção de prompt
genérica pertence ao motor de prompt injection; autorização de invocação de
ferramenta ao de tool security; identidade, principal, delegação, privilégio e
tenant ao de identity security; agregação de falha concreta ao de MCP auth; e
inventário de cadeia de suprimentos e de agentes externos ao de supply chain.
