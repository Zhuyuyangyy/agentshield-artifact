# EXP-02 — Sample size and stratification

Attack: `important_instructions`; 629 paired cells; no model calls.
Uniform draws: 2000; stratified draws: 1000; seed 20261126.

| n | mechanism | tool_filter dev. (pp) | pi_detector dev. (pp) | gap mean (pp) | reversal rate |
|---|---|---|---|---|---|
| 100 | prefix | +6.16 | -6.95 | +12.00 | 1 |
| 100 | uniform | +0.06 | +0.04 | -1.10 | 0.300 |
| 100 | stratified_census | +0.08 | +0.14 | -1.18 | 0.292 |
| 100 | stratified_prefix | +1.57 | -4.00 | +4.46 | 0.933 |
| 200 | prefix | +4.16 | -3.45 | +6.50 | 1 |
| 200 | uniform | -0.01 | -0.01 | -1.11 | 0.245 |
| 200 | stratified_census | +0.01 | +0.01 | -1.12 | 0.222 |
| 200 | stratified_prefix | +1.48 | -4.04 | +4.41 | 0.998 |
| 300 | prefix | +2.50 | -3.28 | +4.67 | 1 |
| 300 | uniform | +0.04 | +0.00 | -1.07 | 0.191 |
| 300 | stratified_census | +0.03 | +0.05 | -1.13 | 0.159 |
| 300 | stratified_prefix | +1.53 | -4.03 | +4.45 | 1.000 |
| 400 | prefix | +1.41 | -3.95 | +4.25 | 1 |
| 400 | uniform | -0.01 | -0.03 | -1.09 | 0.115 |
| 400 | stratified_census | -0.02 | +0.04 | -1.17 | 0.100 |
| 400 | stratified_prefix | +1.53 | -4.03 | +4.45 | 1.000 |
| 500 | prefix | +0.96 | -3.55 | +3.40 | 1 |
| 500 | uniform | -0.01 | +0.00 | -1.12 | 0.029 |
| 500 | stratified_census | -0.01 | +0.01 | -1.14 | 0.024 |
| 500 | stratified_prefix | +0.69 | -1.79 | +1.37 | 0.994 |
| 629 | prefix | +0.00 | +0.00 | -1.11 | 0 |
| 629 | uniform | +0.00 | +0.00 | -1.11 | 0.000 |
| 629 | stratified_census | +0.00 | +0.00 | -1.11 | 0.000 |
| 629 | stratified_prefix | +0.00 | +0.00 | -1.11 | 0.000 |

Deviation is relative to the 629-cell census. Reversal means the
tool-filter ASR exceeds the pi-detector ASR (the census order is the
opposite). The prefix is deterministic, so it has reversal 0 or 1 and
no interval.

Reproduce: `python experiments/statistics/sample_size.py`
