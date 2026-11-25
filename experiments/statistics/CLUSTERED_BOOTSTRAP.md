# EXP-01 — Clustered uncertainty for Study 1

- redacted：2026-11-24
- redacted：`benchmark/results/e2b_trajectory_outcomes.jsonl`（redacted SHA-256 redacted `results/clustered_bootstrap.json`）
- redacted：`experiments/statistics/clustered_bootstrap.py`
- redacted：`experiments/statistics/results/clustered_bootstrap.json`
- redacted：2,000 redacted；cell seed 20261123，user seed 20261124，injection seed 20261125

## 1. redacted

redacted：

| redacted | redacted | redacted |
|---|---|---|
| cell | redacted | redacted（redacted） |
| user | `suite|user_task` | redacted |
| injection | `suite|injection_task` | redacted（redacted） |
| two-way | CGM redacted：user + injection − redacted | redacted |

redacted injection redacted `none`，redacted user redacted。redacted（redacted REVIEW redacted，redacted）。

## 2. redacted（redacted）

| redacted | redacted | redacted | cell 95% | user 95% | injection 95% | two-way 95% |
|---|---|---|---|---|---|---|
| band − hard, block | attack | 0.000 | [0, 0] | [0, 0] | [0, 0] | [0, 0] |
| band − hard, block | benign | +3.093 | [0, 7.22] | [0, 7.22] | — | — |
| band − global, block | attack | +0.134 | [0.07, 0.21] | [0.00, 0.42] | [0.09, 0.17] | [−0.12, 0.39] |
| band − global, block | benign | +3.093 | [0, 7.22] | [0, 7.22] | — | — |
| band − hard, log | attack | 0.000 | [0, 0] | [0, 0] | [0, 0] | [0, 0] |
| review step rate, block | benign | +0.885 | [0, 2.05] | [0, 1.97] | — | — |

redacted：redacted 97 redacted user cluster、35 redacted injection cluster；redacted 97 redacted user cluster。

## 3. redacted

1. **Band split redacted hard first redacted**，redacted `[0,0]`；redacted 784 redacted（block）redacted 322 redacted（log）。redacted“same traces”，redacted“same rate”。
2. **redacted +3.09 pp redacted user redacted cell redacted**（`[0, 7.22]`），redacted 3 redacted 3 redacted user cluster；redacted 0。redacted“redacted”。
3. **Band split redacted global cap redacted +0.134 pp redacted cell redacted 0，redacted user redacted two-way redacted 0**（`[0.00, 0.42]`、`[−0.12, 0.39]`）。redacted**redacted**；redacted“redacted”。
4. **redacted +0.885 pp** redacted user redacted `[0, 1.97]`，redacted 0；redacted。

## 4. redacted

- §5.2：redacted“small advantage”，redacted“point estimate +0.13；cell interval [0.07,0.21]；user-cluster [0.00,0.42]；two-way [−0.12,0.39]；redacted advantage”。
- §5.6：redacted“buys 0.13 points”redacted“point estimate 0.13, not distinguishable from zero under task clustering”。
- §1 C2：redacted。
- §8：redacted“redacted bootstrap”，redacted“redacted B redacted；+0.13 redacted user redacted two-way redacted 0”。
- redacted B：redacted。

## 5. redacted

- 629 redacted（redacted，redacted）；redacted cell-level。
- redacted 97 redacted、97 redacted user cluster redacted；redacted cell redacted，redacted。
- CGM redacted；redacted，redacted bootstrap redacted。
- 231 redacted/redacted `suite|user_task` redacted ID；redacted，redacted。

## 6. redacted

```bash
python experiments/statistics/clustered_bootstrap.py
python -m pytest -q tests/statistics/test_clustered_bootstrap.py
```

redacted JSON redacted `DATA_MANIFEST.json` redacted。
