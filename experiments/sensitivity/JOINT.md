# E04 — Joint design and sampling uncertainty

Design envelopes from T03, paired cell intervals recomputed from the frozen outcomes (seed 20261123), clustered census intervals from E01.

## Rule

A strict uniform-dominance claim requires (i) a one-sign design envelope that excludes zero, (ii) every configuration's paired cell interval excluding zero, and (iii) the clustered census intervals excluding zero. Any failure downgrades the verdict.

## Contrasts

| contrast | design min | design max | configs excluding 0 | census clustered excludes 0 | verdict |
|---|---|---|---|---|---|
| band_minus_hard|attack_trace_block_rate | +0.000 | +0.000 | 0/4 | no | set_identity |
| band_minus_hard|benign_trace_block_rate | +0.000 | +3.093 | 0/2 | no | not_resolvable |
| band_minus_global|attack_trace_block_rate | +0.000 | +0.135 | 2/4 | no | census_cell_only |
| band_minus_global|benign_trace_block_rate | +2.062 | +3.093 | 0/2 | no | not_resolvable |

The band-split-minus-hard-first attack contrast is a set identity, not a sampling question: every configuration and every resample gives exactly zero. The band-split-minus-global-cap attack contrast is positive at the census (cell interval excludes zero) but exactly zero on the prefix and not supported by the user or two-way census intervals. The benign contrasts have positive point estimates but intervals that include zero.

Study 2 top two: design envelope [-1.11, +10.42] pp, sign change; no sampling interval can license a uniform ranking.

## What is not claimed

- No confidence interval is attached to the design envelope; it is a range over enumerated configurations.
- No uniform-dominance claim is licensed anywhere in this corpus.
- The prefix has no clustered interval; clustering is reported at the census only.
- Study 2 has no per-step actions, so only its frame envelope is used.

Reproduce: `python experiments/sensitivity/joint.py`
