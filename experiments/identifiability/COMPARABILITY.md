# T01 — Claim-specific comparability

A comparison is not a property of two numbers; it is a property of two reports
and a question. This note defines the comparison types the paper uses, states
the necessary conditions for each, and gives a counterexample from the frozen
evidence for every condition that can fail.

A report is `r = (M, δ, μ, P, E)`: mechanism, design vector, metric definition,
protocol, and evidence block. The design vector is `δ = (F, σ, ρ, α)`: sampling
frame, enforcement semantics, aggregation rule, attribution source. The metric
definition `μ` (numerator, denominator, unit, grader) and the protocol `P`
(common task grid, graders, and admission rule) are preconditions, not
coordinates of `δ`.

## 1. Definition

Two reports `r1 = (M1, δ1, μ1, P1, E1)` and `r2 = (M2, δ2, μ2, P2, E2)` are
**comparable for a question Q** if the quantity Q names is identified by both
reports and the difference between the reports is attributable to the
coordinate that Q varies.

The questions correspond to allowed variations:

| Type | Question | May vary | Must hold fixed |
|---|---|---|---|
| Population | Does the result hold on another population? | `F` | `M, σ, ρ, α, μ, P`; a common super-population |
| Mechanism | Which mechanism performs better on the same units? | `M` | `F, σ, ρ, α, μ, P`; identical units/decision points |
| Design sensitivity | Does one rule or semantics change the result? | `σ` or `ρ`, one only | `M, F, α, μ, P`; identical decisions |
| Attribution | Did the gate cause the observed outcome difference? | `α` | `M, F, σ, ρ, μ, P`; gate-side coverage of the flips |
| Descriptive | Are two reported numbers different? | one coordinate or coverage | `μ, P`; no causal or ranking reading |

This is not circular: the type is fixed by the question before the estimator is
chosen, and the design vector says which coordinate the question is allowed to
move. A comparison that varies more than one coordinate answers no single
question.

## 2. Necessary conditions

### 2.1 Common preconditions (all types)

1. **Same report schema.** Both reports must pass `validate_report` before any
   comparison is attempted. A missing design field is not a sensitivity result.
2. **Same metric definition.** Numerator, denominator, unit, and grader must be
   the same. `attack_trace_block_rate` and `end_to_end_asr` are different
   quantities even when both are percentages.
3. **Same admission rule and protocol.** The units must satisfy the same
   inclusion rule, and `P` must be equal: a common benchmark, task grid, grader
   version, and protocol identifier. A denominator that adds 27
   `injection_task_k/none/none.json` cells is a different denominator, not a
   robustness check.
4. **Reported uncertainty at the unit that is resampled.** A cell-level
   interval is not evidence about a population of user tasks.

### 2.2 Population comparison

Necessary conditions, in addition to 2.1:

- `F` is the only coordinate that differs.
- Both frames are subsets of a declared common population, or both are
  probability samples from it with reported sampling scheme.
- The frame composition is reported, not only the frame size.

Counterexample (Study 2). The 400-cell prefix and the 629-cell census share a
super-population, but the prefix is a deterministic block: it contains 11 of
240 workspace cells. The census order is tool_filter < pi_detector; the prefix
order is the reverse. The two reports are comparable as a *frame-sensitivity*
statement, not as two estimates of one population parameter, because the prefix
is an extreme order statistic, not a draw.

Counterexample (incompatible run). The `Meta-SecAlign-70B` run has 14 injection
tasks in workspace instead of 6, so its 949-cell grid does not share units with
the 629-cell grid. No population comparison is licensed, even though both runs
report the same metric names.

### 2.3 Mechanism comparison

Necessary conditions, in addition to 2.1:

- `F` is identical: the same traces and the same decision points.
- Exactly one of `σ` or `ρ` differs; the enforcement semantics is stated for
  both reports. A design-sensitivity comparison moves one coordinate, not two.
- The actions are recomputed on the recorded components, and reconstruction is
  checked against the engine's own action.

Counterexample (band split vs hard first). On attack traces the two rules block
the same 784 traces under `block` and the same 322 under `log_and_allow`; their
attack rates are equal by set identity, not by coincidence. A report that
describes the 0.0308 vs 0.0308 tie as "no difference in interception" is
correct; a report that describes the same numbers as evidence for a mechanism
difference is not, because the only difference is review load (5.90 vs 5.02
percent of steps) and, under blocking, three benign traces.

Counterexample (mixed semantics). Comparing rule A under `log_and_allow` with
rule B under `block` varies `ρ` and `σ` together. The observed difference
cannot be assigned to either coordinate; the REVIEW bound of T02 shows that
`σ` alone moves the attack rate by 4.43 points.

Counterexample (different units). Comparing the prefix gap with the census gap
while calling both "the effect of the defense" varies `F` and `ρ` (the ranking
changes) and is therefore a population comparison at best.

### 2.4 Attribution comparison

Necessary conditions, in addition to 2.1:

- `F`, `σ`, `ρ` are fixed; `α = gate_side`.
- Every flip has a gate-side record, or the missing records are bounded and the
  bound is reported.
- The record direction agrees with the outcome flip; a record of zero
  interventions is not evidence of a gate effect.

Counterexample (Study 2 paired run). Fifteen cells flip from attack success to
failure. Six have a concordant gate-side record, three have a record of zero
blocked calls, and six have no record; all six missing flips are in one user
task. The defensible statement is "at most twelve and at least six of the
fifteen flips are gate-consistent" (6/15–12/15), not "the gate prevented
fifteen attacks." The interval is a bound on records with a concordant
gate-side entry; it is not a causal contribution rate and does not license a
ratio between the two readings.

Counterexample (post-hoc fusion). The frozen sidecar is truncated at each
invocation and a cached cell writes no rows. The records are derived coverage
of a fusion, not a fresh measurement; calling them a measurement would violate
the provenance rule even if every record agreed.

## 3. Decision procedure

Given two reports and a question, apply four stages in order and stop at the
first failure:

1. **Schema.** Validate both reports. A missing design field, a malformed
   interval, or an invalid protocol is a schema failure, not a comparison.
2. **Question-conditioned comparability.** Check `μ`, `P`, the admission rule,
   the benchmark, and the allowed coordinate. If the mechanism and a design
   coordinate both move, or more than one coordinate moves, stop: the comparison
   answers no single question.
3. **Identifiability.** Decide whether the metric is point- or
   partially identified. Under unknown REVIEW semantics, a point block rate is
   not identified; only a bounded comparison is licensed.
4. **Inference and ranking.** Only after stages 1–3 pass may a difference
   interval be used. A strict ranking is licensed only when the difference
   interval excludes zero; overlapping partial-identification intervals leave
   the sign undetermined.

If a condition fails, downgrade the claim to a descriptive comparison and name
the coordinate that moved. The procedure is a filter, not an estimator. It says
what a report may claim, not how large the claim is.

## 4. Relation to the paper

- Population: Section 6.3 and Appendix C (frame effects, composition, reversal
  distance).
- Mechanism: Section 5.2 and Appendix B (rules, identical blocked sets, REVIEW
  bound).
- Attribution: Section 5.4 and Appendix E (15 flips, 6/15–12/15).

These types do not exhaust every question one could ask. They exhaust the
questions this paper answers, and each has a coordinate that is allowed to move
and a condition that the frozen evidence can check.
