"""Pin the Study 2 clustered intervals."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "statistics" / "results"
          / "external_clustered_bootstrap.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_census_gap_is_unresolved_at_every_level():
    data = _load()
    census = data["frames"]["census"]
    assert census["n"] == 629
    assert census["user_clusters"] == 97
    assert census["point_pp"] == -1.1129
    assert census["cell_ci95"] == [-3.4976, 1.4308]
    assert census["user_ci95"] == [-4.7005, 2.3963]
    assert census["twoway_ci95"] == [-7.7496, 5.5238]
    assert census["cell_excludes_zero"] is False
    assert census["user_excludes_zero"] is False
    assert census["twoway_excludes_zero"] is False


def test_prefix_reversal_does_not_survive_two_way_clustering():
    data = _load()
    prefix = data["frames"]["prefix_400"]
    assert prefix["point_pp"] == 4.25
    assert prefix["cell_ci95"] == [1.2438, 7.25]
    assert prefix["user_ci95"] == [0.2544, 8.4746]
    assert prefix["twoway_ci95"] == [-1.6154, 10.1154]
    assert prefix["cell_excludes_zero"] is True
    assert prefix["twoway_excludes_zero"] is False


def test_banking_gap():
    data = _load()
    banking = data["frames"]["banking"]
    assert banking["n"] == 144
    assert banking["point_pp"] == 10.4167
    assert banking["twoway_excludes_zero"] is False
