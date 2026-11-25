# S02 — Evaluation fault suite

Twelve injected faults and eight negative controls, run on copies of the frozen examples. The example files are hashed before and after.

## Faults

| id | kind | description | detected | evidence |
|---|---|---|---|---|
| F01 | validate | missing enforcement semantics | True | design.enforcement_semantics is required; design.enforcement_semantics must be one of ('log_and_allow', 'block', 'unknown') |
| F02 | validate | missing metric uncertainty | True | uncertainty.attack_trace_block_rate is required for a reported metric |
| F03 | validate | illegal aggregation rule | True | design.aggregation_rule must be one of ('no_relaxation', 'global_cap', 'band_split', 'hard_first') |
| F04 | validate | metric reported as a percentage above one | True | metrics.attack_trace_block_rate must lie in [0, 1] |
| F05 | validate | negative metric | True | metrics.benign_trace_block_rate must lie in [0, 1] |
| F06 | validate | missing provenance source | True | provenance.source must be a non-empty string |
| F07 | validate | malformed SHA-256 digest | True | provenance.sha256 must be a lowercase hex digest or null |
| F08 | claims | block rate described as attack success | True | an attack trace block rate is not an attack success rate |
| F09 | claims | claimed value outside tolerance | True | claimed 0.4 but the report has 0.4124 (tolerance 0.001) |
| F10 | compare | frame-only comparison across benchmarks | True | not_comparable; The benchmark or protocol differs; without a declared common protocol the reports are not comparable. |
| F11 | compare | two design coordinates differ | True | not_comparable; More than one coordinate differs, or the changed coordinates do not form one admissible question. |
| F12 | compare | no shared metric | True | not_comparable;  |

## Negative controls

| id | kind | description | rejected | evidence |
|---|---|---|---|---|
| N01 | validate | another rule | False |  |
| N02 | validate | another semantics | False |  |
| N03 | validate | different interval values | False |  |
| N04 | validate | all six metrics | False |  |
| N05 | validate | derived provenance | False |  |
| N06 | claims | ASR claim backed by ASR | False | {'claim': 'The gate reaches 12 percent attack success', 'claim_type': 'descriptive', 'metric': 'end_to_end_asr', 'value': 0.12, 'tolerance': 0.001, 'contract_valid': True, 'eligible_for_causal_assessment': False, 'causal_validity_established': False, 'passed': True, 'errors': []} |
| N07 | compare | same-benchmark frame comparison | False | population; Frames differ but the mechanism is the same. Verify that both frames are subsets of one declared population. |
| N08 | compare | same-frame semantics comparison | False | design_sensitivity; The same mechanism is evaluated under a different rule or semantics; report both semantics for a gate with a REVIEW state. |

Detected 12 of 12 faults; 0 of 8 controls were falsely rejected; originals unchanged: True.

## What is not claimed

- Synthetic faults validate the implementation, not real-world accuracy.
- The suite covers twelve fault classes and eight controls, not every possible reporting error.
- No original artifact is modified; every case works on a copy.

Reproduce: `python experiments/faults/run_fault_suite.py`
