# EXP-03 — Exact McNemar power

Exact two-sided McNemar, alpha 0.05, target power 0.80. MDE is the net
difference d = p01 - p10 in percentage points, as a function of the
discordance rate q = p01 + p10.

| n | q=0.05 | q=0.10 | q=0.20 | q=0.30 | q=0.50 |
|---|---|---|---|---|---|
| 20 | — | — | — | — | 43.14 |
| 40 | — | — | 19.50 | 24.21 | 31.69 |
| 60 | — | — | 16.21 | 20.05 | 26.35 |
| 80 | — | 9.84 | 14.19 | 17.62 | 22.69 |
| 97 | — | 8.97 | 12.95 | 16.09 | 20.56 |
| 150 | — | 7.34 | 10.58 | 12.84 | 16.59 |
| 200 | 4.43 | 6.40 | 9.12 | 11.12 | 14.34 |

Observed benign contrast: 3 discordant pairs, q = d = 3/97 = 3.09 pp; exact power = 0.081; smallest attainable two-sided p = 0.25.

The design cannot reject at 0.05 with three discordant pairs. This is
a resolution statement, not evidence of equivalence.

Historical reconciliation: 8.03 pp nearest q=0.085, 8.97 pp nearest q=0.100, 12.95 pp nearest q=0.200.

Reproduce: `python experiments/statistics/power.py`
