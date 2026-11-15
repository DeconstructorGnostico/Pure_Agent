# External sets (public, without credentials) are never used to adjust rules.

- `deepset_prompt_injections.jsonl`: deepset/prompt-injections (Hugging Face), Apache-2.0 license. It contains 662 English and German texts (train 546 + test 116); label 1 = injection.
- `external_dano.jsonl`: local copy of `nre-eval/data`, which was downloaded earlier:
  - XSTest (Röttger et al., 2023): 250 safe and 200 insecure.
  - AdvBench harmful_behaviors (Zou et al., 2023): 520.
  - Aya Red-Teaming in Spanish (Cohere for AI, 2024): 782.
Each set maintains the license of its original source.
