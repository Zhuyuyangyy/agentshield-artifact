# T02 — Partial identification of REVIEW semantics

Frozen corpus: 10,439 attack and 97 benign traces. No model calls.

## Statement

For a fixed trace let `b_log` be 1 if some step is BLOCK, and `b_block`
be 1 if some step is BLOCK or REVIEW. For any per-call resolution of
REVIEW to execute or stop, `b_log <= b_f <= b_block`. Both endpoints are
attained (resolve every REVIEW to execute, or every REVIEW to stop), so
the interval is sharp. At the aggregate level every integer count
between the two endpoints is attainable.

Per-sequence exhaustion: 1,092 sequences of length 1–6; all inside: True; all sharp: True.
Aggregate exhaustion over 9 two-step sequences and 6 review slots: full integer range 5..8: True.

## Bound widths on the frozen corpus

| label | rule | log rate | block rate | width (pp) | review-only traces |
|---|---|---|---|---|---|
| attack | no_relaxation | 0.0443 | 0.0885 | 4.43 | 462 |
| attack | global_cap | 0.0295 | 0.0738 | 4.43 | 462 |
| attack | band_split | 0.0308 | 0.0751 | 4.43 | 462 |
| attack | hard_first | 0.0308 | 0.0751 | 4.43 | 462 |
| benign | no_relaxation | 0.3711 | 0.4639 | 9.28 | 9 |
| benign | global_cap | 0.2680 | 0.3814 | 11.34 | 11 |
| benign | band_split | 0.2887 | 0.4124 | 12.37 | 12 |
| benign | hard_first | 0.2887 | 0.3814 | 9.28 | 9 |

The width is the fraction of traces whose verdict the deployment
decides: they contain a REVIEW and no BLOCK. It is not a confidence
interval and not a post-intervention outcome.

On attack traces the width is rule-invariant: the review-only set is identical under all four rules (True), 462 traces, 4.43 points. On benign traces the width depends on the rule (9.28 to 12.37 points), so the aggregation choice is visible only on the benign side.

## What is not claimed

- The width is not a confidence interval; it is the exact range under the stated resolution model.
- No claim that the deployment resolves REVIEW independently per call.
- No claim about post-intervention task outcome; this is trace blocking.

Reproduce: `python experiments/identifiability/review_bounds.py`
