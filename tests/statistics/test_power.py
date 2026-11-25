"""Pin the exact McNemar power values used in the paper and appendix."""

import json
from pathlib import Path

from experiments.statistics import power

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "statistics" / "results" / "power.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_mde_at_ninety_seven_matches_the_historical_values():
    data = _load()
    assert data["grid"]["97"]["0.10"] == 8.97
    assert data["grid"]["97"]["0.20"] == 12.95
    assert data["grid"]["97"]["0.30"] == 16.09
    assert data["grid"]["97"]["0.50"] == 20.56


def test_observed_benign_contrast_is_underpowered():
    data = _load()
    observed = data["observed_benign"]
    assert observed["discordant"] == 3
    assert observed["power_at_observed_effect"] == 0.081
    assert observed["minimum_two_sided_p"] == 0.25


def test_exact_rejection_region_needs_six_discordant_pairs():
    assert power._rejection_region(3) == (-1, 4)
    assert power._rejection_region(5) == (-1, 6)
    assert power._rejection_region(6) == (0, 6)
