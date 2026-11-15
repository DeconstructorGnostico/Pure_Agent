# Changelog

## 3.0.0-en — 2026-11-15 (English edition)

- Full English translation of code identifiers, enum values, messages, comments, docstrings and docs (from the Spanish Agente_puro 3.0.0).
- Behavior unchanged: tests (unittest: 264 OK (261 without Hypothesis)) and benchmarks/evaluations match the Spanish version case by case.
- Hardcoded `/workspace` paths replaced with relative paths (the v3 adapter uses the sibling folder `pure_agent_v3` or the `AGENT_PURE_V3_ROOT` variable).
- New freeze SHA-256 (alphabetical concatenation of `*.py`):
- `pure_agent_v3/**/*.py`: `538b027d3f623ed52fa027cb6f328c9933d9d64e4b7b65eeb93dc568cddc8227`
- `bench/seeds_test.py`: `1e9a0fcd470fa0cbca31a17b3d9d8adc200a2b7b249f58500e506860e0d029f2`
- `bench/dataset_test.jsonl`: `51f4467c0b55807a038add9f255908170ff8568551cab3a956bff3e650e91571`
