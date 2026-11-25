# V01 — Independent recomputation

Mode: `offline`; status: **pass**.

A separate code path reads the frozen outcomes, the attribution file, the shipped suite counts and the claim registry; it imports none of the project's analysis modules.

| claim | scope | recomputed | expected | match |
|---|---|---|---|---|
| S1-ROWS | study1 | 10536 | 10536 | True |
| S1-ATTACK | study1 | 10439 | 10439 | True |
| S1-BENIGN | study1 | 97 | 97 | True |
| S1-BLOCK-SET-BAND-SPLIT | study1 | 784 | 784 (784) | True |
| S1-BLOCK-SET-HARD-FIRST | study1 | 784 | 784 (784) | True |
| S1-BLOCK-SET-SYMMETRIC-DIFFERENCE | study1 | 0 | 0 (0) | True |
| S1-ATTACK-NO-RELAXATION-LOG-AND-ALLOW | study1 | 4.4257 (462) | 4.4257 (462) | True |
| S1-BENIGN-NO-RELAXATION-LOG-AND-ALLOW | study1 | 37.1134 (36) | 37.1134 (36) | True |
| S1-ATTACK-NO-RELAXATION-BLOCK | study1 | 8.8514 (924) | 8.8514 (924) | True |
| S1-BENIGN-NO-RELAXATION-BLOCK | study1 | 46.3918 (45) | 46.3918 (45) | True |
| S1-ATTACK-GLOBAL-CAP-LOG-AND-ALLOW | study1 | 2.9505 (308) | 2.9505 (308) | True |
| S1-BENIGN-GLOBAL-CAP-LOG-AND-ALLOW | study1 | 26.8041 (26) | 26.8041 (26) | True |
| S1-ATTACK-GLOBAL-CAP-BLOCK | study1 | 7.3762 (770) | 7.3762 (770) | True |
| S1-BENIGN-GLOBAL-CAP-BLOCK | study1 | 38.1443 (37) | 38.1443 (37) | True |
| S1-ATTACK-BAND-SPLIT-LOG-AND-ALLOW | study1 | 3.0846 (322) | 3.0846 (322) | True |
| S1-BENIGN-BAND-SPLIT-LOG-AND-ALLOW | study1 | 28.866 (28) | 28.866 (28) | True |
| S1-ATTACK-BAND-SPLIT-BLOCK | study1 | 7.5103 (784) | 7.5103 (784) | True |
| S1-BENIGN-BAND-SPLIT-BLOCK | study1 | 41.2371 (40) | 41.2371 (40) | True |
| S1-ATTACK-HARD-FIRST-LOG-AND-ALLOW | study1 | 3.0846 (322) | 3.0846 (322) | True |
| S1-BENIGN-HARD-FIRST-LOG-AND-ALLOW | study1 | 28.866 (28) | 28.866 (28) | True |
| S1-ATTACK-HARD-FIRST-BLOCK | study1 | 7.5103 (784) | 7.5103 (784) | True |
| S1-BENIGN-HARD-FIRST-BLOCK | study1 | 38.1443 (37) | 38.1443 (37) | True |
| S1-PREFIX-NO-RELAXATION-BLOCK | study1 | 10.5 (42) | 10.5 (42) | True |
| S1-PREFIX-GLOBAL-CAP-BLOCK | study1 | 7.0 (28) | 7.0 (28) | True |
| S1-PREFIX-BAND-SPLIT-BLOCK | study1 | 7.0 (28) | 7.0 (28) | True |
| S1-PREFIX-HARD-FIRST-BLOCK | study1 | 7.0 (28) | 7.0 (28) | True |
| REV-COMPOSITIONS | reversal | 1501380 | 1501380 | True |
| REV-CROSSING-L1 | reversal | 0.10713 | 0.10713 | True |
| REV-CROSSING-GAP | reversal | 0.010565 | 0.010565 | True |
| REV-TIE-L1 | reversal | 0.121979 | 0.121979 | True |
| REV-TIE-GAP | reversal | 0.0 | 0.0 | True |
| REV-STRICT-L1 | reversal | 0.10713 | 0.10713 | True |
| REV-STRICT-GAP | reversal | 0.010565 | 0.010565 | True |
| POWER-OBSERVED | power | 0.081 | 0.081 | True |
| POWER-MIN-P | power | 0.25 | 0.25 | True |
| POWER-MDE-010 | power | 8.97 | 8.97 | True |
| POWER-MDE-020 | power | 12.95 | 12.95 | True |
| FLIP-TOTAL | flips | 15 | 15 | True |
| FLIP-CONCORDANT | flips | 6 | 6 | True |
| FLIP-ZERO | flips | 3 | 3 | True |
| FLIP-UNRECORDED | flips | 6 | 6 | True |
| FLIP-BOUND-LOW | flips | 6 | 6 | True |
| FLIP-BOUND-HIGH | flips | 12 | 12 | True |
| S2-CELLS | study2 | — | 629 | NOT EXECUTED |
| S2-ASR-NONE | study2 | — | 47.695 | NOT EXECUTED |
| S2-UTIL-NONE | study2 | — | 50.079 | NOT EXECUTED |
| S2-ASR-TOOL-FILTER | study2 | — | 6.836 | NOT EXECUTED |
| S2-UTIL-TOOL-FILTER | study2 | — | 56.28 | NOT EXECUTED |
| S2-ASR-SPOTLIGHTING | study2 | — | 41.653 | NOT EXECUTED |
| S2-UTIL-SPOTLIGHTING | study2 | — | 55.644 | NOT EXECUTED |
| S2-ASR-PI-DETECTOR | study2 | — | 7.949 | NOT EXECUTED |
| S2-UTIL-PI-DETECTOR | study2 | — | 21.145 | NOT EXECUTED |
| S2-ASR-REPEAT-USER-PROMPT | study2 | — | 27.822 | NOT EXECUTED |
| S2-UTIL-REPEAT-USER-PROMPT | study2 | — | 67.25 | NOT EXECUTED |
| S2-PREFIX-GAP | study2 | — | 4.25 | NOT EXECUTED |
| S2-BANKING-GAP | study2 | — | 10.417 | NOT EXECUTED |

Executed checks: 43; not executed: 13; all executed checks match: True.

## Not executed

- S2-CELLS (study2)
- S2-ASR-NONE (study2)
- S2-UTIL-NONE (study2)
- S2-ASR-TOOL-FILTER (study2)
- S2-UTIL-TOOL-FILTER (study2)
- S2-ASR-SPOTLIGHTING (study2)
- S2-UTIL-SPOTLIGHTING (study2)
- S2-ASR-PI-DETECTOR (study2)
- S2-UTIL-PI-DETECTOR (study2)
- S2-ASR-REPEAT-USER-PROMPT (study2)
- S2-UTIL-REPEAT-USER-PROMPT (study2)
- S2-PREFIX-GAP (study2)
- S2-BANKING-GAP (study2)

## Blocked layers

- Study 2 run tree: offline mode uses shipped suite counts
- 13 registry entries were not executed in this mode and are not counted as passed
- Study 2 external recomputation: run tree not required in offline mode

## Scope

The offline mode covers counts, all eight attack and eight benign rates, the bounded REVIEW logic, the prefix counts, the composition-induced reversal geometry, power and the full flip classification. The external mode adds the AgentDojo run tree. The full mode would require the Arrow dump and a live replay; it reports BLOCKED rather than crashing.

Reproduce: `python audit/independent_review/recompute.py --mode offline`
