# Dataset — AgentDojo-derived logged-trace dump

This document is the data contract for the two external data sources the paper
uses: the logged-trace dump behind Study 1 and the public AgentDojo run tree
behind Study 2. Neither is redistributed inside this artifact. The dump is
represented by its fingerprint; the run tree is public upstream and is cloned by
the reviewer at the commit printed in the paper.

## 1. Source

| Item | Value |
|---|---|
| Upstream dataset | `ffuuugor/agentdojo-dump` (Hugging Face dataset of AgentDojo logged tool-call traces) |
| Used by | `benchmark/agentdojo_trace_replay.py::load_rows` |
| Glob read by the harness | `benchmark/external_datasets/ffuuugor___agentdojo-dump/**/*.arrow` |
| Arrow file | `.../ffuuugor___agentdojo-dump/default/0.0.0/<revision>/agentdojo-dump-train.arrow` |
| Licence | the upstream dataset's own terms; redistribution is not assumed |

`<revision>` is whatever revision directory the Hugging Face `datasets` loader
created on your machine. **Do not hand-match that directory name.** The harness
and the fingerprint both glob `*.arrow`, so the experiment is insensitive to it;
only the bytes are pinned.

## 2. How to obtain it

Obtain the dump from the upstream source above and place it so the glob in §1
resolves, for example by letting the loader populate
`benchmark/external_datasets/ffuuugor___agentdojo-dump/`. No network access is
performed by this artifact: the replay reads local files only.

If you already hold a copy, use it as-is and let §3 decide whether it is the
right one. Where a copy came from is not part of the identity of the experiment;
the manifest digest is.

## 3. Expected fingerprint

```bash
python scripts/fingerprint_agentdojo_dump.py
```

Canonical run — every line must match:

```text
dataset:          ffuugor/agentdojo-dump
files:            1
total_bytes:      50898680
rows:             13913
trajectories:     10536
excluded_total:   0
manifest_sha256:  948b94325ae1c8cfbe41bd205fee46b0f500215559ef5cd97a25c27fcf580049
```

`--json` additionally lists every file's relative path, size and SHA-256.

What the digest covers: each `*.arrow` file under the dump directory, hashed with
SHA-256, combined as `SHA-256(relative_path + "\0" + file_sha256)` over files in
sorted relative-path order. The NUL separator prevents two different
`(path, hash)` pairs from producing the same concatenation, and relative paths
make the digest independent of where this artifact was unpacked.

Exit codes: `0` with a fingerprint, `2` when no Arrow file is present. The script
is read-only with respect to the data — it hashes, it never modifies, moves or
regenerates anything, and nothing it returns is fed back into the engine, the
detector or the replay.

> A different dump version is **not** a reproduction. Compare the manifest digest
> first; if it differs, stop and acquire the matching dump before comparing any
> numbers.

## 4. What the dump yields

```text
rows parsed                 13913
trajectories constructed    10536
benign trajectories         97      (all of them; the study takes a census)
attack-labelled             10439   (the census; the prefix is the first 400)
```

The 400 attack-labelled trajectories are a deterministic prefix of the census,
taken in the order `build_trajectories` constructs. There is no shuffle and no
seed, so there is no sampling parameter to pin: the prefix is a property of the
load order. The per-trajectory outcomes that the offline analyses read are
shipped as `benchmark/results/e2b_trajectory_outcomes.jsonl` (4.8 MB of scores
and actions, no message text), so a reviewer can run those analyses without
staging the dump.

## 4b. The public AgentDojo run tree (Study 2)

Study 2 reads the run directory published by the AgentDojo authors, not the
logged-trace dump. Stage it at the pinned upstream commit:

```bash
git clone <agentdojo-repo> .tmp/agentdojo
cd .tmp/agentdojo
git checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
cd -
```

| Item | Value |
|---|---|
| Upstream repository | the public AgentDojo repository (URL printed in the paper) |
| Audited commit | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` |
| Comparable arms | `gpt-4o-2024-05-13` plus `tool_filter`, `spotlighting_with_delimiting`, `transformers_pi_detector`, and `repeat_user_prompt` |
| Files at that commit | 12,890 JSON files, 135,758,439 bytes |
| Licence | the upstream repository's own licence |

The tree is not shipped: it is public upstream, and the artifact host refuses
binaries and caps a file at 8 MB. `benchmark/external_validity_agentdojo.py`
reads only scalar and provenance fields; the result file it writes contains no
message text.

### 4c. Second model run

The same public run tree contains a `Meta-SecAlign-70B` run (version v1.2.1).
It uses the same user tasks and injection tasks except in the workspace suite,
where it has 14 injection tasks instead of 6. That difference yields 949
security cells per attack instead of 629 and 2,847 security cells in 2,979
files. The second model is therefore **excluded from every cross-model and
cross-defense comparison**; it is reported only as an inventory row and as
evidence that the published grids are not joinable. No number in Study 2
depends on it.

## 5. Why the dump is not in this artifact

Three reasons, all deliberate:

1. **Size.** The file is 50,898,680 bytes, far above the anonymous mirror's
   per-file limit of 8 MB. It could not be uploaded as part of the artifact.
2. **Anonymity.** The mirror anonymizes text content only; binary payloads are
   passed through unchanged and can carry upstream metadata. Shipping raw dump
   bytes would put unreviewable content into a double-blind submission.
3. **Terms.** The dump is distributed under the upstream dataset's own licence,
   which does not grant redistribution by a third party.

The manifest digest is therefore the identifier that binds a reproduction to the
evaluated data: a reviewer stages the dump locally, the fingerprint either
matches the digest above or refuses to proceed.
