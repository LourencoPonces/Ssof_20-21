# Notes

Static Analysis Techniques
- Control-Flow Analysis
- Abstract Interpretation
- Type amd Effect Systems
- Model Checking
- Program Verification

## Questions

1. Pode haver sinks que nao sejam function calls?
2. Quando e que há efectivamente uma vulnerabilidade? Source e depois sink ou também Source, Sanitizer, Sink?
3. O que é que gera taint ao certo? `a = func()` é tainted? Qaundo func é uma função desconhecida, não declarada
4. program8.js -> vuln nas linhas 1 e 2
5. Uma variavel desconhecida no programa e uma source? Caso sim, essa source da origem a uma vulnerabilidade com qualquer sink?
ex: aqui o `a` nunca foi declarado. Mesmo que ele nao exista nos `sources`, e considerado como source?
```
sink(a)
```
Se assim o for, porque e que e precisa a lista de sources?

6. Source e sink de vulnerabilidades diferentes geram uma vulnerabilidade?
    Nao

7. Porque e que precisamos de `sinks` no Taint? Eles so sao preenchidos quando criamos uma vulnerabilidade
    A vulnerabilidade ate podia ser criada com uma taint (que por sua vez tinha as informacoes de source e sanitizers)

## Ideas

### Idea 1:
Analisar o programa e registar todos os flows de informacao
    Ignorar se vem de sources ou sinks?

No final analizar cada vulnerabilidade (patterns) e verificar se
algum sink tem um flow de um source (sem passar por sanitizers)
Se tiver, reportamos essa vulnerabilidade

#### Types:
##### Member Expression
- a.b.c.d
- a[1]
- a.b
- a['b']

# Patterns:

