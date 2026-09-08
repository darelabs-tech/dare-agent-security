# Validação de Cadeia de Suprimentos Agêntica e AI-BOM

O DARE Agent Security pode validar se os componentes que formam um sistema
agêntico são os que foram aprovados: sua identidade, seus bytes, sua origem, o
que os atesta, como dependem uns dos outros, quais capacidades carregam, de qual
modelo base derivam e com qual conjunto de dados foram treinados. Esta página
descreve o que isso estabelece e, com a mesma importância, o que não estabelece.

## A pergunta que ele responde

O motor responde a uma única pergunta:

> Os documentos locais de bill of materials, proveniência e atestação mostram
> que cada componente continua vinculado ao artefato, à origem e à aprovação que
> foram registrados para ele?

Não é um rastreador de SBOM, um auditor de registries, um scanner de
vulnerabilidades nem uma ferramenta de conformidade de licenças. Um componente
que parece desconhecido não é um achado. Um achado exige um fato determinístico
que contradiga um invariante declarado.

## As relações em que tudo se apoia

```text
inventário                    != confiança
nome do componente            != identidade do componente
string de versão              != artefato imutável
presença de digest            != proveniência
proveniência presente         != proveniência confiável
evidência de assinatura válida != signatário autorizado
AI-BOM completo               != cadeia de suprimentos segura
dependência declarada         != dependência observada
mesmo nome e versão           != mesmo artefato
URL do componente             != autorização para buscar
inventário de agente externo  != autorização A2A
```

Cada uma é um ponto em que duas coisas parecidas não são a mesma coisa, e cada
uma é a razão de existir do invariante correspondente.

> **Um bill of materials é uma afirmação de quem o produziu.** Ele pode dizer
> que um componente é fornecido pela Acme; não pode dizer que a Acme foi
> aprovada. A aprovação vem de um manifesto local sob controle da implantação, e
> um documento que declara `"trusted": true` sobre si mesmo é recusado em vez de
> acreditado.
>
> **Uma versão não é um artefato.** Duas builds podem publicar a mesma versão,
> então `react@1.0.0` nomeia uma coordenada e não um conjunto de bytes. Uma
> imagem com a tag `latest` é identificada por algo que pode mudar sob ela — a
> menos que haja um digest registrado ao lado, caso em que o digest é a
> identidade e a tag é apenas uma convenção de nomes.
>
> **Um digest não é proveniência.** O digest diz o que o artefato *é*; a
> proveniência diz de onde ele veio e quem o construiu. Um componente pode ter um
> digest perfeito e nenhuma proveniência.
>
> **Proveniência presente não é proveniência confiável.** Um registro que nomeia
> o componente certo, o artefato errado e um builder aprovado é proveniência de
> uma *build diferente* — relatá-lo como satisfeito seria relatar a substituição
> como aquilo que ela substituiu.
>
> **Uma assinatura criptograficamente válida feita por um signatário não
> aprovado é uma assinatura válida e não autorizada.** Se a assinatura foi
> verificada e se o signatário foi aprovado são perguntas diferentes com
> respostas diferentes.
>
> **O nome de um modelo nada diz sobre sua linhagem.** Um modelo base
> substituído deixa `llama-3-8b-finetuned` exatamente como estava, e é por isso
> que a base aprovada é expressa como id de componente e não como nome.

## Nada é buscado, executado ou assinado

Nenhum registry de pacotes, model hub, registry de contêineres, host Git,
transparency log, serviço de assinatura, servidor de chaves ou base de
vulnerabilidades é contatado. Nenhuma assinatura ou atestação é emitida. Nenhum
artefato, modelo, arquivo compactado ou código nomeado em um documento importado
é executado, carregado ou extraído. Não há mudança de estado nem egresso
externo.

Isso importa mais aqui do que na maioria das validações, porque os documentos
que este motor lê são **cheios de coordenadas**. Um componente CycloneDX carrega
um purl; um pacote SPDX carrega um download location; uma atestação nomeia um
repositório. Cada um deles é um lugar de onde algo poderia ser buscado, e todos
são metadados inertes:

> Uma coordenada nomeia algo. Nomear algo não é autorização para ir buscá-lo.

O limite é estrutural, não uma regra que alguém precisa lembrar. O motor não
declara cliente HTTP, cliente de registry, cliente OCI, biblioteca Git, runtime
de modelo nem extrator de arquivos, e o comando não expõe nenhuma flag
`--registry`, `--fetch`, `--download`, `--sign`, `--key` ou `--token`, porque
não existe caminho de código que tal flag pudesse alcançar.

## Três respostas, não duas

Cada verificação distingue *comparado e divergente* de *nada a comparar*:

| Veredito | Significado | O que o operador faz |
|---|---|---|
| `PASS` | o invariante se aplicava e a evidência necessária estava presente | nada |
| `FAIL` | uma contradição determinística foi observada | investigar o componente nomeado |
| `INCONCLUSIVE` | o invariante se aplicava e faltava evidência decisiva | coletar a evidência que o relatório nomeia |
| `ERROR` | a execução não conseguiu ler o que deveria avaliar | corrigir a entrada e executar de novo |

Um invariante **sem sujeito na evidência** — linhagem de modelo em um sistema que
não roda modelo nenhum — não é aprovado nem indeciso. A pergunta não surge, o
invariante é marcado como inaplicável e não puxa o veredito da execução para
baixo. Sem essa distinção, um resultado limpo seria inalcançável para qualquer
implantação que não contenha um exemplar de cada coisa, e um operador que nunca
vê `PASS` deixa de ler a diferença entre `PASS` e `INCONCLUSIVE`.

## `PASS` exige evidência positiva

A forma mais barata de fazer toda verificação de cadeia de suprimentos passar é
entregar ao motor um **bill of materials vazio**: nenhum componente, nenhum
digest, nada de que discordar. Por isso cada invariante declara os canais de
observação que uma execução precisa ter produzido antes de poder reportar
`PASS`, e uma execução que nada observou não satisfaz nenhum deles.

O contrato tem um segundo passo fácil de esquecer: um canal pode estar
*presente* e não carregar nada a comparar. Uma projeção de capacidades com
conjunto aprovado e sem conjunto observado descreve o que era permitido, não uma
diferença. Isso reporta `INCONCLUSIVE`, não `PASS`.

## Todo invariante aplicável é avaliado

Um cenário nomeia um invariante, e essa seleção é um rótulo de cobertura — nunca
um filtro. Todo invariante aplicável é avaliado sobre a mesma evidência, e toda
violação concreta é retida.

Isso importa porque falhas de cadeia de suprimentos vêm em grupo. Substituir um
artefato quebra a integridade *e* a proveniência que vinculava o digest antigo
*e* a atestação que o avalizava. Uma execução que reportasse apenas a primeira
subestimaria o que viu, e o operador corrigiria uma de três.

## O que está fora de escopo

- **Autorização de invocação de ferramentas.** Se uma ferramenta *pode ser
  usada* é pergunta de outro motor. Uma ferramenta pode estar perfeitamente
  autorizada e ser o artefato errado; e pode ser o artefato certo e ser invocada
  por quem não deveria.
- **Segurança agente-a-agente.** Um agente externo em um inventário é uma linha
  dizendo que um documento o nomeou. Não é autorização para comunicar, delegar
  ou confiar.
- **Dados de vulnerabilidade.** Nenhuma base de CVE é consultada. Um componente
  corretamente identificado nada diz sobre estar vulnerável.
- **Licença, PII, direitos autorais, viés e equidade.** Perguntas reais sobre
  conjuntos de dados, e nenhuma delas é uma pergunta de cadeia de suprimentos. O
  motor vê a identidade e o digest de um dataset e nunca o seu conteúdo — não
  conseguiria avaliar viés nem se quisesse, e um campo que convidasse à tentativa
  seria uma promessa que ele não pode cumprir.

## Quanto vale um `PASS`

Um `PASS` diz que os invariantes aplicáveis se sustentaram sob os documentos
efetivamente lidos. Não é uma afirmação de que a cadeia de suprimentos é segura,
de que nenhum componente foi substituído ou de que um bill of materials está
completo. Um AI-BOM completo é um inventário, e um inventário não é confiança.

A referência canônica em inglês tem o detalhamento de corpus, formatos e flags:
[Extending Agentic Supply Chain
Validation](https://darelabs-tech.github.io/dare-agent-security/en/reference/extending-supply-chain-security.html).
