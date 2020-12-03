# Notes

Static Analysis Techniques
- Control-Flow Analysis
- Abstract Interpretation
- Type amd Effect Systems
- Model Checking
- Program Verification

## Questions

1. Pode haver sinks que nao sejam function calls?
    SIM! document.innerHTML -> XSS

2. Quando e que há efectivamente uma vulnerabilidade? Source e depois sink ou também Source, Sanitizer, Sink?
    Temos de reportar tudo porque nao temos a certeza se os sanitizers estao corretos

3. O que é que gera taint ao certo? `a = func()` é tainted? Qaundo func é uma função desconhecida, não declarada
    *semelhante a resposta em 5*

4. program8.js -> vuln nas linhas 1 e 2

5. Uma variavel desconhecida no programa e uma source? Caso sim, essa source da origem a uma vulnerabilidade com qualquer sink?
ex: aqui o `a` nunca foi declarado. Mesmo que ele nao exista nos `sources`, e considerado como source?
```
sink(a)
```
Se assim o for, porque e que e precisa a lista de sources?

    assumimos que a slice produzida tem toda a informacao relevante
    portanto so assumimos que esta tainted se for source ou estiver tainted

6. Source e sink de vulnerabilidades diferentes geram uma vulnerabilidade?
    Nao

7. Porque e que precisamos de `sinks` no Taint? Eles so sao preenchidos quando criamos uma vulnerabilidade
A vulnerabilidade ate podia ser criada com uma taint (que por sua vez tinha as informacoes de source e sanitizers)

8. Precisamos de ser mais precisos e de separar as vulnerabilidades em diferentes vulns, mas pode haver mais do que um sink numa vuln?
    "ha uns flows que podem ser sanitizados e outros que nao sao, por isso e que se introduziu 
    (nao percebi bem esta parte)"
Nao percebi bem... Prefiro perguntar em horario de duvidas

9. Os sanitizers podem ser outra coisa que nao funcoes?

10. Um literal pode ser source/sink/sanitizer?

11.
a) lancamos vulnerabilidade em a, por f_1 poder fazer `snk1 = src1` ou `snk1(src1)`?
b) na linha `sink(c)` devemos apresentar a vulnerabilidade com o sink `snk3`?
c) os sanitizadores passados como argumentos passam no sanitizador?

```
a = f_1(src1, san1, snk1)
b = src(src2, san2, snk2)
c = snk(src3, san3, snk3) -> { V, sources:[src3], sinks:[snk], sanitizers: []}
d = san(src4, san4, snk4)
sink(a) -> { V, sources:[src1], sinks:[sink], sanitizers: [] }
sink(b) -> { V, sources:[src, src2], sinks:[sink], sanitizers: [] }
sink(c) -> { V, sources:[src3], sinks:[sink], sanitizers: [] }
sink(d) -> { V, sources:[src4], sinks:[sink], sanitizers: [san] }
```

sanitizer(arguments)

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

Flow: 

self.possible_patterns: {
    'pattern_name': {
        pattern: <Pattern>
        sources: [ passed by these sources ]
        sinks: [ passed by these sinks ]
        sanitizers: [ passed by these sanitizers ]
    }
}


1. 
if(source) {
    sink = true;
} else {
    sink = false;
}

2. 
if(source ) {
    a = true;
} else {
    a = false;
}
sink = a;

(sinks, sources, sanitizers) + (sources)

{vulnA, sinks: [a], sources: [src1]}
{vulnB, sinks: [snk2], sources: [a]}

v1 = a

v1(src1)
snk2(v1)

{VulnA, [v1], [src1]} {VulnA, [snk2], [v1]}

a = sink
a = source

b = sink
b(source)

sink1 = source
sink2 = sink1


a = src;
b = "b";
c = "c";
i = 0
while (i < ?) {
    c = b;
    snk = c;
    b = a;
}

# Ideia
analisar o block de tras para a frente e da frente para tras

## TODOS
Make bash script to prepare the outputs folder and other things
Outputs sanitizers ands sinks in the wrong order
Read files the 2 functions are similar
