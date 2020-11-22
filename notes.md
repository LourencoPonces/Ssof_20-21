# Notes

Static Analysis Techniques
- Control-Flow Analysis
- Abstract Interpretation
- Type amd Effect Systems
- Model Checking
- Program Verification

# Questions

1. Pode haver sinks que nao sejam function calls?
2. Quando e que há efectivamente uma vulnerabilidade? Source e depois sink ou também Source, Sanitizer, Sink?

# Ideas

## Idea 1:
Analisar o programa e registar todos os flows de informacao
    Ignorar se vem de sources ou sinks?

No final analizar cada vulnerabilidade (patterns) e verificar se
algum sink tem um flow de um source (sem passar por sanitizers)
Se tiver, reportamos essa vulnerabilidade


# Patterns:
