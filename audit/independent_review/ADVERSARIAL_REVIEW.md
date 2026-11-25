# V01 — Adversarial review checklist

Seven critique types, each with the strongest version of the objection, the
evidence that bears on it, the response the paper can defend, and the residual
risk. This is an internal adversarial pass, not an external human review.

## 1. Construct validity

**Objection.** The paper measures trace blocking, not attack success; a gate
can block a trace without preventing the attack.

**Evidence.** The contract separates `attack_trace_block_rate` from
`end_to_end_asr` (Appendix A). Study 1 reports only the former and says so in
Section 5.1. The live paired run reports outcome flips, but only 6 of 15 have a
concordant gate record (Appendix E).

**Response.** The paper never substitutes the offline block rate for ASR. The
claim is about interception on recorded behaviour, and the limitation is stated
where the number is introduced.

**Residual risk.** A reader who wants an ASR ranking will not find one in
Study 1; the paper says this explicitly.

## 2. Internal validity

**Objection.** The four rules are applied after the fact, and two of 13,913
steps reconstruct a different score (0.27 versus 0.49).

**Evidence.** The two exceptions are benign ALLOW calls and change no count
(Appendix B). The other 13,911 steps match the engine's action exactly.

**Response.** The reconstruction check is reported, not hidden; the exceptions
are characterised and bounded.

**Residual risk.** Post-hoc replay cannot capture a rule that would have changed
the agent's later behaviour; the paper calls this a counterfactual, not an
end-to-end result.

## 3. External validity

**Objection.** One corpus, one live system, one public artifact.

**Evidence.** Study 2 reproduces the published table on 629 cells and finds the
frame effect; E05 found no second benchmark with paired defense outcomes (see
`experiments/external_artifacts/SURVEY.md`).

**Response.** The paper claims the frame effect on an artifact it did not build
and limits the semantics and attribution findings to one system. It does not
claim cross-benchmark reproduction.

**Residual risk.** The review may ask for a second benchmark; the honest answer
is that none passed admission within the triage cap.

## 4. Statistical conclusion validity

**Objection.** Two marginal intervals that overlap do not imply no difference;
the benign contrast has three discordant traces.

**Evidence.** All Study 1 contrasts are paired (Section 4.5). E01 reports cell,
user-task, injection-task and two-way intervals. E03 shows that with three
discordant pairs the exact McNemar test has no rejection region at 0.05 (minimum
p = 0.25) and 8 percent power at the observed effect.

**Response.** The paper reports the interval and the power floor, not a
significant/not-significant dichotomy; the E04 joint analysis licenses no
uniform-dominance claim.

**Residual risk.** A reader may still read "not significant" as "no effect";
the paper says the difference is below the design's resolution, not evidence of
equivalence.

## 5. Attribution

**Objection.** Fifteen flips, six with a gate record, three with zero
intervention, six with no record; the six missing flips are in one user task.

**Evidence.** Appendix E lists all fifteen rows and the [6, 12] bound. The
source is a post-hoc fusion (`derived: true`, not a measurement).

**Response.** The paper reports the bound and refuses the fifteen-to-zero
reading. The missingness is shown to cluster by user task, so it is not treated
as random.

**Residual risk.** Even the six "attributed" flips are provenance, not a
controlled intervention; the paper says so.

## 6. Reproducibility

**Objection.** The analysis is only reproducible if the frozen files and the
environment match.

**Evidence.** `research/route_b/DATA_MANIFEST.json` records SHA-256 for the
frozen assets; every experiment writes a script, a result JSON and a
reproduction command. V01's `recompute.py` reproduces the headline numbers
without importing the analysis modules; all eighteen checks match (offline mode
reports the external layer as blocked rather than failing).

**Response.** The release includes the scripts, the frozen outcome file (4.8
MB, no message text), and the tests that pin the values.

**Residual risk.** The raw live trajectories and the AgentDojo payloads are not
released; the paper explains why and what is released instead.

## 7. Novelty and generalization

**Objection.** The four-parameter contract is a checklist; the empirical
findings may be specific to this gate.

**Evidence.** The contract produces a set-identity result (band split and hard
first block the same 784 attack traces), a sharp REVIEW bound (4.43 points on
attacks), a composition effect that reproduces on an independent artifact, and
a minimum reversal distance of 0.107.

**Response.** The contribution is the measurement framework and the negative
result, not a new defense. The paper does not claim that the band split is
generally ineffective; it claims that this evaluation cannot identify an attack
advantage, and it shows how the design choice moves the verdict.

**Residual risk.** A reviewer may want a second mechanism; the paper's scope
statement addresses this directly.
