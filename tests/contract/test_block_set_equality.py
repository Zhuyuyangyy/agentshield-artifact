"""Pin the block-set equality that the paper's 'same traces' wording relies on."""

from experiments.contract import block_set_equality as audit


def test_attack_sets_are_identical_between_band_and_hard_first():
    rows = audit.load_rows()
    attack = audit.blocked_sets(rows, "attack")
    band = attack["band_split|block"]
    hard = attack["hard_first|block"]
    assert len(band) == 784
    assert len(hard) == 784
    assert band == hard
    log_band = attack["band_split|log_and_allow"]
    log_hard = attack["hard_first|log_and_allow"]
    assert len(log_band) == 322
    assert log_band == log_hard


def test_benign_difference_is_exactly_three_traces():
    rows = audit.load_rows()
    benign = audit.blocked_sets(rows, "benign")
    band = benign["band_split|block"]
    hard = benign["hard_first|block"]
    assert len(band) == 40
    assert len(hard) == 37
    assert len(band - hard) == 3
    assert not (hard - band)
    assert benign["band_split|log_and_allow"] == benign["hard_first|log_and_allow"]
    assert len(benign["band_split|log_and_allow"]) == 28


def test_global_cap_differs_from_band_on_fourteen_attack_traces():
    rows = audit.load_rows()
    attack = audit.blocked_sets(rows, "attack")
    band = attack["band_split|block"]
    cap = attack["global_cap|block"]
    assert len(cap) == 770
    assert len(band - cap) == 14
    assert not (cap - band)


def test_written_result_matches_the_file():
    import json
    from pathlib import Path

    path = (Path(__file__).resolve().parents[2]
            / "experiments" / "contract" / "results" / "block_set_equality.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["counts"] == {"attack": 10439, "benign": 97}
    by_key = {(item["label"], item["left"], item["right"]): item
              for item in data["comparisons"]}
    assert by_key[("attack", "band_split|block", "hard_first|block")]["only_left"] == 0
    assert by_key[("benign", "band_split|block", "hard_first|block")]["only_left"] == 3
    assert by_key[("attack", "band_split|block", "global_cap|block")]["only_left"] == 14
