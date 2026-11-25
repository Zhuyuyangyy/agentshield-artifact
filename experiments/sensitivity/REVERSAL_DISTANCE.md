# T04 — Minimum ranking reversal distance

Attack: `important_instructions`; arms: `tool_filter` (A) vs `pi_detector` (B); 629 paired cells; no model calls.

## Per-suite rates

| suite | cells | users | injections | tool ASR | pi ASR | gap (pp) |
|---|---|---|---|---|---|---|
| banking | 144 | 16 | 9 | 11.111 | 0.694 | +10.417 |
| slack | 105 | 21 | 5 | 8.571 | 12.381 | -3.810 |
| travel | 140 | 20 | 7 | 5.714 | 0.000 | +5.714 |
| workspace | 240 | 40 | 6 | 4.167 | 15.000 | -10.833 |

Census gap: **-1.1129 pp** (tool filter lower).
Published 400-cell prefix: gap **+4.4521 pp**, L1 weight distance **0.7081**.

## Minimum over same-size frames

Admissible set: all 400-cell suite compositions (`0 <= k_s <= n_s`, sum 400), 1,501,380 points.
315,610 of them reverse the census order (21.0%), including 26 exact ties. The counting fraction weights every composition equally; it is not the probability that a uniform draw reverses (EXP-02: 11.45 percent), because the sampling distribution concentrates near the census composition.

Closest crossing composition (definition: gap >= 0): banking 113, slack 66, travel 89, workspace 132; gap +0.0106 pp, L1 distance **0.1071** (TV 0.0536); ties at the minimum: 1.

Closest exact tie (gap == 0): 0.1220.
Closest strict reversal (gap > 0): 0.1071.

Unrestricted simplex relaxation (lower bound, not a claim): 0.1047 by moving 0.0524 of the mass from workspace to banking.

## Prefix family

Along the artifact's sorted order, every prefix of length <= 564 reverses; every prefix of length >= 565 preserves the census order.
The closest reversing prefix is n=564 with 175 workspace cells (31.03% of the frame), gap +0.0074 pp, distance 0.1425.

## Context frames

| frame | gap (pp) | L1 distance | reversal |
|---|---|---|---|
| census | -1.1129 | 0.0000 | no |
| prefix 400 | +4.4521 | 0.7081 | yes |
| census-quota 400 | -1.1406 | 0.0030 | no |
| user_task_weights | -2.3957 | 0.1608 | no |
| uniform_suites | +0.3720 | 0.2631 | yes |

The census-quota frame is the EXP-02 stratified composition at n=400; the user-task frame weights suites by distinct user tasks (97 tasks); the uniform frame weights the four suites equally.

## What is not claimed

- The distance is not a probability: it does not say how likely a reversing frame is.
- No causal attribution: the gap is a composition effect of this artifact only.
- The simplex relaxation is not an admissible frame and is never quoted as the minimum.
- No claim about other attacks or other arm pairs.

Reproduce: `python experiments/sensitivity/reversal_distance.py`
