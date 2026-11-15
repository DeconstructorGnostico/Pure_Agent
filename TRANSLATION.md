# About this English edition

- Original (Spanish): https://github.com/DeconstructorGnostico/Agente_puro. It was not modified.
- Version: 3.0.0. Behavior is meant to match the Spanish version exactly.
- Tests: Spanish original unittest: 264 OK (261 without Hypothesis); English edition unittest: 264 OK (261 without Hypothesis).
- Checked for equivalence: same pass/fail on every test, plus identical demo and benchmark/evaluation results case by case where the project has them.

## Stays in Spanish (by design)

DEV/TEST datasets and seeds (`bench/seeds_*.py`, `bench/dataset_*.jsonl`; frozen benchmark; case texts, labels and order unchanged, only identifiers and JSON keys translated), Spanish attack/harm regex patterns and stop-word lexicons (the agent is bilingual by design), Spanish demo/bank input sentences, ASCII diagrams.

These are inputs the system is evaluated on, or bilingual detection data. Translating them would change the published numbers.

## Not included

Nothing.

## Freeze hashes (English edition)

SHA-256 over the package's `*.py` files concatenated in alphabetical order:

- `pure_agent_v3/**/*.py`: `538b027d3f623ed52fa027cb6f328c9933d9d64e4b7b65eeb93dc568cddc8227`
- `bench/seeds_test.py`: `1e9a0fcd470fa0cbca31a17b3d9d8adc200a2b7b249f58500e506860e0d029f2`
- `bench/dataset_test.jsonl`: `51f4467c0b55807a038add9f255908170ff8568551cab3a956bff3e650e91571`
