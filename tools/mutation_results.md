# Mutation testing light

Mutants applied: 22 · dead: 21 · score: 21/22

| id | file | mutation | result | s |
|---|---|---|---|---|
| M01 | decision.py | decide: unknown criticism executes | DEAD | 5.5 |
| M02 | decision.py | choose_candidate without filter | DEAD | 5.4 |
| M03 | decision.py | reprocess delivers what did not pass quality | DEAD | 5.7 |
| M04 | decision.py | quality control without threshold | DEAD | 5.2 |
| M05 | zero_trust.py | Zero-Trust allow-all | DEAD | 5.4 |
| M06 | causal.py | action caused by data passes as rooted | DEAD | 5.2 |
| M07 | causal.py | causal chain without prev_hash | DEAD | 5.2 |
| M08 | intent.py | spec violation does not block | DEAD | 5.3 |
| M09 | persistence.py | anchor is not checked when loading (H-22) | DEAD | 5.3 |
| M10 | persistence.py | no disk verification to another connection | DEAD | 5.3 |
| M11 | root/governor.py | Token expired accepted | DEAD | 5.2 |
| M12 | root/governor.py | token replay accepted | SURVIVES | 5.1 |
| M13 | root/normalization.py | no homoglyph map | DEAD | 5.3 |
| M14 | root/firewall.py | no pattern pretend_without_rules | DEAD | 5.4 |
| M15 | amm_core.py | Insecure route reaches the controller (H-20) | DEAD | 5.3 |
| M16 | amm_core.py | orphan action does not block | DEAD | 5.4 |
| M17 | gateway.py | tokens invented by the model are discarded in silence | DEAD | 5.3 |
| M18 | door.py | closed list amplified | DEAD | 5.3 |
| M19 | deconstructor.py | claim_id empty contradicts | DEAD | 5.5 |
| M21 | amm_core.py | to allow acceptance of orphan action | DEAD | 5.2 |
| M22 | root/normalization.py | no variant of separate letters (H-23) | DEAD | 5.3 |
| M20 | evidence.py | never verified model statements (H-25) | DEAD | 5.4 |

Note M12: Repeated nonce control is deep defense. A token is bound to A action (subject = action hash, ticket = id) and the state machine already prevents running the same action twice; after restarting, session keys change and the old token is invalid (HALT). We do not find a route in which only the nonce stops it: equivalent mutant in current practice, control is retained.
