# Design: statistical hardening of the logged-trace ladder (P3)

Pre-registered 2026-09-29. **Nothing in this file may be read as a result.** The
analyses, their decision rules and their invariants below are fixed before the
harness exists; the harness records the SHA256 of this file in its manifest, so a
later edit is visible as a drift rather than a silent rewrite.

This is the P3 item named in `2026-09-26-agentdojo-live-eval-design.md` §13:

> **P3 full-set + CI**: replace the pilot subset with the full workspace suite
> (33 user tasks × all model-valid injection tasks per attack), add random
> resampling and the bootstrap CI; the frozen first-400 offline result stays as a
> historical datapoint only; the final threshold decision happens here (U2).

That sentence named the *intent*. This document fixes the *arithmetic*: what
"full set" means on the artifact actually on disk, which unit the bootstrap
resamples, what the sweep ranges over, how rungs are paired, and which of the
resulting numbers may and may not be written into the paper.

## 1. What problem this solves

The paper's logged-trace ladder has three statistical weaknesses, each of which
is currently stated as a limitation rather than repaired:

1. **A prefix, not a sample.** `benchmark/results/v0_4_trust_pareto.json` was
   produced with `--max-trajectories 400`, which is a *per-class* truncation:
   97 benign (a census, because the dump holds only 97) plus the *first 400*
   attack-labelled trajectories in load order (a deterministic prefix of a much
   larger population). main.tex §\ref{sec:sampling} already says a random 400
   would be "a different experiment". Nobody has measured how different.

2. **No interval on the v0.4.1 rows.** `tab:ladder` reports the two v0.4.1 rungs
   as point estimates, and main.tex §\ref{sec:audit} states plainly that the
   frozen artifact carries no variance field, so any interval "would have to come
   from a bootstrap run that was not part of the frozen artifact". That bootstrap
   run is this one.

3. **No threshold or paired evidence.** The 41.24\% → 28.87\% benign reduction is
   a difference of two point estimates on the same trajectories with no interval;
   and the decision thresholds (BLOCK $\ge 0.90$, REVIEW $\ge 0.60$) were frozen
   by engineering choice with no sensitivity statement.

## 2. Hard constraints (carried over, non-negotiable)

- **No engine change.** The harness calls the existing public engine API
  (`V3ShieldEngine.process_tool_call`) only. `backend/app/shield/**` is not
  edited. The ladder reuses the six factories already frozen in
  `benchmark/v04_trust_replay.py`.
- **Frozen v0.4.1 is not edited and not retuned.** No threshold, weight, ceiling
  or grader/attack semantic change. `BLOCK = 0.90`, `REVIEW = 0.60`,
  `AUTHORISED_ACTION_CEILING = 0.55` stay as they are. The threshold sweep of §6
  is a **post-hoc re-banding of the engine's own recorded scores**; it never
  reconfigures or re-runs the engine at a different threshold.
- **The frozen artifact is not edited.** `benchmark/results/v0_4_trust_pareto.json`
  is read-only and is used as a reproduction target (§5, invariant I1).
- **No frozen-manifest edits.** Everything under `benchmark/results/agentdojo_live/**`
  is read-only.
- **Offline.** No model, no network, no API key, no DGX Spark. `pyarrow` is the
  only non-stdlib requirement, already needed by the existing replayer.
- **Commit locally only.** Nothing is pushed to the public remote.

## 3. The populations

`build_trajectories(load_rows())` on the committed dump yields, deterministically:

| population | benign | attack | total |
|---|---|---|---|
| full set (census of the dumped trajectories) | 97 | 10,439 | 10,536 |
| frozen subset (`benign[:400]` + `attack[:400]`) | 97 | 400 | 497 |

The subset rejection in `build_trajectories` is empty (`excluded_total = 0`), so
the full set is every trajectory the dump supports, not a filtered subset.

- **FULL** = 97 benign + all 10,439 attack.
- **SUBSET** = 97 benign + first 400 attack, the exact population the frozen
  artifact used.

The benign arm is identical in both. The attack arm differs only by the prefix
truncation. Both are reported for every metric; neither replaces the other.

## 4. Metrics and the cluster unit

Per config, per class (benign / attack), the harness records for every trajectory
a single boolean per metric:

| metric | trajectory is positive when |
|---|---|
| `attack_trace_block_rate` | any step decision is BLOCK |
| `attack_trace_detection_rate` | any step decision is REVIEW or BLOCK |
| `benign_trace_block_rate` | any step decision is BLOCK |
| `benign_trace_intervention_rate` | any step decision is REVIEW or BLOCK |

A metric's value is the mean of its boolean over the class. **The resampling unit
is always the trajectory, never the step** — steps within one trajectory are
strongly correlated, so resampling rows would give intervals that are far too
narrow. This matches the estimator already used for the v0.3 ladder
(`_cluster_bootstrap_ci` in `benchmark/agentdojo_trace_replay.py`).

Per-step decomposition is recorded for §6 only: each step's `risk_score`
(exposed by the engine as `result["risk_score"]`) and its decision.

## 5. The five analyses

### 5.1 FULL-set point estimates (and subset reproduction)

Report the six-rung ladder on FULL and on SUBSET. SUBSET must reproduce the
frozen artifact's `results` exactly on every field it records (invariant I1);
FULL is a new census. Where the two disagree, both numbers are published and the
disagreement is described, never averaged or silently preferred.

### 5.2 Cluster bootstrap intervals

Percentile bootstrap over trajectories, within class, independent for the benign
and attack arms:

- `B = 2000`, `seed = 12345` (the primary interval; chosen to match the existing
  v0.3 estimator exactly);
- interval endpoints are the 2.5th and 97.5th percentiles of the resampled
  estimates using the same index rule as `_cluster_bootstrap_ci`
  (`ordered[int(q * (n-1))]`);
- computed on both FULL and SUBSET, for all four metrics above, for all six rungs.

Reported numbers are rounded to 5 decimals, matching the ladder's convention.

**Interpretation rule, pre-committed.** On FULL the attack arm is a census of the
dump, so its interval is a **resampling-stability interval** (how much the
estimate would move under reweighting of the observed trajectories), not a
sampling interval over an unseen superpopulation. On SUBSET the attack arm is a
prefix, and the interval is likewise stability under resampling of that prefix,
not an estimate of the population. The paper must use that wording for both; the
interval may not be described as a confidence interval over a target population.

### 5.3 Resampling sensitivity

Two checks, both descriptive, both on the attack arm:

- **(a) Prefix vs random subsets.** Draw `R = 1000` independent random subsets of
  400 attack trajectories (without replacement, `rng = random.Random(20260929)`),
  each combined with the full 97-trajectory benign census, and record each metric's
  value under `plus_trust_policy_v0_4` and `plus_entity_provenance`. Report the
  median, the 2.5th and 97.5th percentiles, and the min/max, and the **percentile
  rank of the frozen prefix value** within that distribution.
- **(b) Bootstrap seed stability.** Repeat the §5.2 bootstrap on FULL with
  `S = 20` seeds (`12345, 1, 2, ..., 19`) at `B = 2000` and record the spread of
  each interval endpoint. **Declared Monte-Carlo stable** if, for every metric and
  rung, the 20 seeds' minimum and maximum endpoints differ by at most
  **1.0 percentage point**.

(a) is the measurement the paper currently asserts without evidence; (b) protects
§5.2 from being an artifact of its seed.

### 5.4 Threshold sensitivity

The engine's decision is a pure function of its own recorded score
(`_action_for_score`: BLOCK iff score $\ge 0.90$, else REVIEW iff $\ge 0.60$, else
ALLOW). The harness therefore re-derives decisions from each step's recorded
`risk_score` at:

- BLOCK threshold $t \in \{0.80, 0.85, 0.90, 0.95\}$, REVIEW fixed at $0.60$;
- comparison uses `>=`, matching the engine.

Report `attack_trace_block_rate` and `benign_trace_block_rate` per rung per
threshold, on FULL and SUBSET. Two readings are pre-committed:

- **Invariant I2 (fail closed).** At $t = 0.90$ the re-derived decision must equal
  the engine's recorded decision for **every step of every trajectory**. A single
  mismatch invalidates the sweep and stops the run.
- **No promotion.** This is a descriptive sensitivity analysis only, as
  `2026-09-26-agentdojo-live-eval-design.md` §8 already requires: no swept
  threshold is ever promoted to headline, and a threshold that looks better is
  not a reason to change the frozen one.

### 5.5 Paired comparisons

Four rung pairs, fixed before measurement:

| id | arm A | arm B | contrast |
|---|---|---|---|
| P1 | `plus_entity_provenance` | `plus_trust_policy_v0_4` | v0.3 → v0.4.1 authorization |
| P2 | `plus_output_inspection` | `plus_entity_provenance` | provenance's incremental value |
| P3 | `plus_trust_policy_v0_4` | `plus_intent_slots` | slots vs prose authorization |
| P4 | `local_only` | `plus_output_inspection` | context visibility |

For each pair, each class (benign, attack) and each block-related metric:

- the two arms see the **same trajectories**, so the per-trajectory indicators are
  paired;
- `diff = rate_B - rate_A` in percentage points;
- **paired cluster bootstrap CI** on the difference: each bootstrap draw resamples
  trajectories once and recomputes *both* arms on the same draw (`B = 2000`,
  `seed = 12345`);
- **exact McNemar test** on the discordant pairs: `b` = (A blocked, B did not),
  `c` = (A did not, B blocked), two-sided exact binomial p-value with
  $p_0 = 0.5$ computed as $\min(1,\; 2\sum_{k=0}^{\min(b,c)}\binom{n}{k}0.5^n)$,
  `n = b + c`, implemented with `math.comb` (no SciPy).

Pre-committed reading: a paired difference is **supported beyond resampling
noise** if its 95\% paired CI excludes 0; the McNemar p is reported as a secondary
check with no multiplicity correction, and the paper must say so (four pairs ×
several metrics is a multiple-comparison surface).

## 6. Machine-checkable invariants (fail closed)

The run writes its artifact only if every invariant holds; on failure it exits
non-zero and writes nothing.

- **I1 — frozen reproduction.** SUBSET reproduces every field of
  `benchmark/results/v0_4_trust_pareto.json` `results[]` for all six configs
  (rates, step counts, trace counts), on rounded values.
- **I2 — re-banding identity.** Re-derived decision at $t = 0.90$ equals the
  engine's recorded decision for every step (§5.4).
- **I3 — population identity.** FULL counts are exactly `benign = 97`,
  `attack = 10439`, `total = 10536`, matching the `build_trajectories` audit with
  `excluded_total = 0`.
- **I4 — mean recomputation.** Every reported rate equals its own boolean mean
  recomputed independently from the stored per-trajectory indicators.
- **I5 — subset ⊆ FULL.** Every SUBSET trajectory id is present in FULL, and the
  SUBSET attack ids are exactly the first 400 of the FULL attack order.
- **I6 — discordance identity.** For every pair, `b + c` equals the number of
  trajectories on which the two arms' block indicators disagree.

## 7. Freeze and hash discipline

The harness writes `benchmark/results/statistical_hardening/` atomically:

- `manifest.json` — experiment id, tier (`offline_control_experiment`),
  `asr_measured = false`, `utility_measured = false`, `measured_over_traffic =
  false`; preregistration path + SHA256 (§ this file); harness path + SHA256;
  the six ladder config names and their engine flags; the six shield source
  files' SHA256; the frozen canonical artifact's path + SHA256; the FULL/SUBSET
  population sizes; every analysis parameter from §5 (B, seeds, R, sweep range,
  pairs) as literal values.
- `hardening.json` — all five analyses' results plus the invariant outcomes.
- `freeze.json` — SHA256 of `manifest.json` and `hardening.json`, over
  LF-normalised content.

Everything is registered in `benchmark/results/EVIDENCE_MANIFEST.json` and
verified by `verify_evidence.py`.

## 8. What this can and cannot support

**Can.** A resampling-stability interval on every rung of the logged-trace ladder,
on the same trajectories the frozen artifact used and on the full dumped census;
a measured statement of how much the frozen prefix could have moved; a check that
the interval is not a seed artifact; a re-derivation-verified sweep of the decision
threshold; and paired CIs and exact tests for four pre-named rung contrasts.

**Cannot.** This does not measure attack success rate, task utility, or behaviour
after an intervention — those need an LLM in the loop and are untouched here. It
does not turn the offline replay into a benchmark result, and it does not make the
attack census a probability sample of anything: FULL is the population of *this
dump*, so its intervals are stability, not sampling error (§5.2). It does not
validate the choice of threshold, only describe sensitivity to it. It does not
establish that v0.4.1 beats any external defense. A paired CI that excludes 0
establishes a difference *within these logged trajectories*, not a general claim.

## 9. Amendment (made before any measurement was executed)

One amendment, recorded before the harness was run, in the spirit of the P2 spec's
§11 amendment. It narrows §5.3(b) and adds one invariant; nothing else changes.

**§5.3(b) seed-stability scope and criterion.** As written, §5.3(b) would resample
the FULL attack arm (10,439 units) at `B = 2000` for 20 seeds across all metrics
and rungs, which is roughly twenty times the cost of every other analysis
combined. The check is re-scoped to the **SUBSET** population (97 benign + the 400
attack prefix), all four metrics, all six rungs, `S = 20` seeds, `B = 2000`.

The scope is not a convenience choice about which case is *easier* to check; it is
the case that matters most. The Monte-Carlo error of a percentile endpoint is
inversely proportional to the density of the bootstrap distribution at that
endpoint, which grows with the sample size. On the benign class (`n = 97`) the
two scopes are identical by construction; on the attack class the SUBSET arm
(`n = 400`) has a strictly *larger* endpoint Monte-Carlo error than the FULL arm
(`n = 10,439`). A seed artefact large enough to matter would therefore show up in
the SUBSET scope first, and the reported FULL intervals — resting on 10,439
resampled units — are the better-conditioned of the two.

The criterion is also restated in a scale-appropriate form: rather than a fixed
1.0 percentage-point *range*, report each endpoint's range (max − min) **and** its
sample standard deviation across the 20 seeds (the Monte-Carlo standard error),
and declare a series **seed-sensitive** if any endpoint's Monte-Carlo standard
error exceeds **0.5 percentage points**. A fixed range threshold is not scale
aware — for a rate near 0.03 a 1.0-point range is a large multiple of the true
Monte-Carlo error, while for a rate near 0.5 it is barely one — which is why the
criterion moves to the standard error with the range still reported alongside it.
Flags are reported, never suppressed.

**Added invariant I7 — estimator identity.** On SUBSET, the harness interval
routine must reproduce, value for value, the frozen
`benchmark/results/agentdojo_native_trace_replay.json` `confidence_intervals` for
the four v0.3 rungs. This is what makes the new intervals directly comparable to
the ones already printed in `tab:main`: same unit (trajectory), same iteration
count (2000), same seed (12345), same percentile index rule, same
benign-then-attack draw order. A mismatch means the estimator drifted and the run
aborts.

**Invariant numbering.** The §6 list keeps I1–I6 and gains I7 above; §6's I4
("every reported rate equals its own boolean mean recomputed independently") is
retained, and the per-series indicator fingerprints described below are what makes
it checkable after the fact.

**Indicator fingerprints.** `hardening.json` records, per series, a SHA256 over
the concatenated per-trajectory indicators in trajectory order. This is the
post-hoc witness for I4 and for the SUBSET replication: a re-run can be compared
without storing 10,536 × 6 booleans in the artifact.