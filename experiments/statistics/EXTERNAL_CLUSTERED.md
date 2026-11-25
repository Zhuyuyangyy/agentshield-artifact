# E01b — External clustered uncertainty

Contrast: tool\_filter minus pi\_detector; attack `important_instructions`; 2,000 draws; no model calls.

| frame | n | point (pp) | cell | user | injection | two-way |
|---|---|---|---|---|---|---|
| census | 629 | -1.113 | [-3.4976, 1.4308] | [-4.7005, 2.3963] | [-7.3383, 4.8215] | [-7.7496, 5.5238] |
| prefix_400 | 400 | +4.250 | [1.2438, 7.25] | [0.2544, 8.4746] | [-1.134, 9.5009] | [-1.6154, 10.1154] |
| banking | 144 | +10.417 | [5.5556, 15.9722] | [2.7778, 18.75] | [2.7778, 18.0729] | [-0.1239, 20.9573] |

On the census the point estimate is -1.113 points. Every 95 percent interval includes zero: cell [-3.4976, 1.4308], user [-4.7005, 2.3963], injection [-7.3383, 4.8215], two-way [-7.7496, 5.5238]. The top-two ranking is therefore unresolved at every level, independently of the frame effect.

Reproduce: `python experiments/statistics/external_clustered_bootstrap.py`
