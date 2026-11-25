# T03 — Design sensitivity envelope

Both design sets are finite and pre-declared; no model calls.

## Study 1: 4 rules x 2 semantics x 2 frames

| rule | attack min | attack max | width (pp) | benign min | benign max | width (pp) |
|---|---|---|---|---|---|---|
| no_relaxation | 4.43 | 10.50 | 6.07 | 37.11 | 46.39 | 9.28 |
| global_cap | 2.95 | 7.38 | 4.43 | 26.80 | 38.14 | 11.34 |
| band_split | 3.08 | 7.51 | 4.42 | 28.87 | 41.24 | 12.37 |
| hard_first | 3.08 | 7.51 | 4.42 | 28.87 | 38.14 | 9.28 |

Between-system difference envelopes (attack, pp):

| pair | min | max | span | sign |
|---|---|---|---|---|
| no_relaxation_minus_global_cap | +1.48 | +3.50 | 2.02 | positive |
| no_relaxation_minus_band_split | +1.34 | +3.50 | 2.16 | positive |
| no_relaxation_minus_hard_first | +1.34 | +3.50 | 2.16 | positive |
| global_cap_minus_band_split | -0.14 | +0.00 | 0.14 | nonpositive |
| global_cap_minus_hard_first | -0.14 | +0.00 | 0.14 | nonpositive |
| band_split_minus_hard_first | +0.00 | +0.00 | 0.00 | tie |

The single-system attack width for band split is 4.4257 points (462/10439); the band-split-minus-global-cap span is 0.1341 points (14/10439), so the ratio is 33.00. Hard first weakly dominates band split on the reported metrics: identical attack blocking, lower benign blocking under blocking semantics, and lower review load (5.015 versus 5.900 percent of steps).

## Study 2: 5 defenses x 3 frames

| defense | min ASR | max ASR | width (pp) |
|---|---|---|---|
| none | 47.70 | 62.50 | 14.80 |
| tool_filter | 6.84 | 11.11 | 4.28 |
| spotlighting | 41.65 | 61.81 | 20.15 |
| pi_detector | 0.69 | 7.95 | 7.25 |
| repeat_user_prompt | 27.82 | 46.53 | 18.71 |

Sign changes across the 10 defense pairs: 1 (tool_filter_minus_pi_detector). Only the top-two pair reverses; the other nine keep their order.

## Licensing

A one-metric uniform-dominance claim requires the paired difference envelope to exclude zero. A joint claim over attack and benign rates also requires the second metric not to reverse. Sampling uncertainty is added in E04.

- Band split vs hard first: hard first weakly dominates on both metrics.
- Band split vs global cap: no uniform dominance; the attack edge is frame-specific and the benign cost is positive.
- Study 2 top two: no uniform ranking; the pair changes sign across frames.

## What is not claimed

- The envelope is a range over declared designs, not a confidence interval.
- No probability is assigned to any design; the set is enumerated, not sampled.
- No claim beyond the four rules, two semantics and three frames listed.
- No joint utility claim: the envelope covers trace block rates and ASR only.

Reproduce: `python experiments/sensitivity/envelope.py`
