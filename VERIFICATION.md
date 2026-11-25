# Verification record

Generated from the working tree on 2026-11-25. These are the actual command
outputs used for the fourth-round final acceptance; the first two commands need
no external data beyond what is shipped here.

## Test suite

Development repository:

```text
python -m pytest -q tests backend/tests
851 passed, 2 skipped
```

Anonymous artifact:

```text
python -m pytest -q tests backend/tests
169 passed, 32 skipped
```

Twenty-six skipped tests are `tests/test_derive_live_latency.py`; they require
the private live workspace, which is not shipped. The skip is explicit in the
test module, not a deletion. The remaining six were already skipped in the
development tree. The Route B subset used by the artifact gate is green in both
environments.

## Claim Auditor fault suite

```text
python experiments/faults/run_fault_suite.py
{'faults': 12, 'detected': 12, 'controls': 8, 'false_rejections': 0,
 'originals_unchanged': True}
```

Fifty-three additional adversarial contract cases are in
`tests/evaluation_faults/test_adversarial_contract.py`. They cover missing and
unknown claim types, malformed and out-of-range intervals narrowed away from the
report bounds, NaN and non-finite values, excessive tolerances, unit and
denominator mismatches, overlapping partial-identification intervals, evidence
from another mechanism or metric, treatment/control and sample-size mismatches,
single-group intervals masquerading as equivalence, and a counterfactual file
whose SHA-256 is correct but whose content does not support the claim. The
auditor is a structured evidence-contract checker, not a causal validity
verifier.

## Independent recomputation

```text
python audit/independent_review/recompute.py --mode offline
43 of 43 offline registry entries match; 13 Study 2 entries are not executed
and are listed separately.
```

`--mode external` was run in the development tree against the cached AgentDojo
run directory (12,890 files, 135,758,439 bytes); all 56 registry entries
matched. The registry is `audit/independent_review/CLAIM_REGISTRY.json`; every
entry records the paper location, source files, metric definition, expected
count, denominator, value, tolerance, and verification status.

The gate was also exercised negatively. Removing one attack row makes the
count check fail and the script exits 1; deleting an input or
`reversal_distance.json` writes a canonical `status: "BLOCKED"` JSON and exits
2; flipping one trace outside the prefix from block to allow makes the exact
784 count fail without changing the denominator; and offline entries whose
scope is absent are listed under `not_executed`, never counted as passes. The
artifact manifest has the same property: `scripts/verify_artifact_manifest.py`
exits 1 when a listed file is tampered with, missing, or unlisted.

The checks cover Study 1 counts and rates, Study 2 counts and rates, the
crossing / tie / strict reversal distances, exact McNemar power and MDE, and the
6--12 intervention-record bound. The script imports none of the project's
analysis modules.

## Figure reproduction

```text
python scripts/draw_route_b_figures.py
```

The two Route B figure PDFs are regenerated from the frozen result files; a
quoted value that moves fails the script.

## Manuscript

The compiled preprint is 20 pages: a 13-page body, references starting on
page 14, and six appendices. `paper/preprint/MANIFEST.json` lists every source
file with its SHA-256 and byte count. This artifact's `MANIFEST.json` does the
same for the shipped code and results.

## Double-blind export

The R5 export rebuilds this snapshot and the preprint, then scans both archives
for the engine token, the author handle, absolute home paths, and CJK text. The
last run produced:

```text
route_b_preprint_r5.zip      22 files, 0 forbidden, 0 CJK
route_b_review_bundle_r5.zip 200 files, 0 forbidden, 0 CJK
BUNDLE_MANIFEST.json         199 entries, 0 mismatches
```

`HASH_MAP.json` now records an explicit anonymisation whitelist
(`repo`, `url`, `cell_run_id`, and similar fields) and lists any non-whitelisted
field difference. A renamed suite, arm, task, attack type, metric definition,
or model version fails the build.

## What is not verified here

No live model call is made. The blocked end-to-end protocol is released as a
specification, not as a result. The external AgentDojo run tree and the frozen
dump are staged separately because they are large or carry payloads; see
DATASET.md.
