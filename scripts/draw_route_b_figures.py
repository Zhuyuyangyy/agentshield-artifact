"""Draw the two data figures for the Route B manuscript.

Figure 2: where a fixed evaluation subset sits in the distribution of random
subsets of the same size, for the frozen corpus (left) and the independent
public artifact (right).

Figure 3: paired contrasts in percentage points, with 95 percent intervals, for
the two studies.

Presentation only. The numbers are read from the frozen result files; a light
assertion block fails the build if a value the manuscript quotes changes. The
script writes vector PDFs with anonymous metadata into paper/figures/, where
the manuscript's \\graphicspath finds them.

    python scripts/draw_route_b_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "benchmark" / "results" / "measurement_reanalysis.json"
EXTERNAL = ROOT / "benchmark" / "results" / "external_validity_agentdojo.json"
OUT_DIR = ROOT / "paper" / "figures"

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8.5,
    "axes.edgecolor": "black",
    "axes.linewidth": 0.7,
    "pdf.fonttype": 42,
    "savefig.dpi": 300,
})

_PDF_METADATA = {"Creator": None, "Producer": None, "CreationDate": None}

_RULE_LABELS = {
    "no_relaxation": "no relaxation",
    "global_cap": "global cap",
    "band_split": "band split",
    "hard_first": "hard first",
}
_POLICY_LABELS = {"log_and_allow": "log", "block": "block"}
_ARM_LABELS = {
    "none": "no defense",
    "tool_filter": "tool filter",
    "pi_detector": "pi detector",
    "repeat_user_prompt": "repeat prompt",
    "spotlighting": "spotlighting",
}


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _save(fig, stem: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{stem}.pdf"
    fig.savefig(out, bbox_inches="tight", facecolor="white",
                metadata=_PDF_METADATA)
    plt.close(fig)
    return out


def _check(frozen: dict, external: dict) -> None:
    """Fail loudly if a number the caption or the text quotes has moved."""
    assert frozen["parameters"]["random_subsets"] == 1000
    assert frozen["parameters"]["seed"] == 20261123
    assert frozen["random_400"]["no_relaxation|log_and_allow"][
        "prefix_percentile_rank"] == 0.996
    assert frozen["random_400"]["band_split|block"][
        "prefix_percentile_rank"] == 0.381
    assert external["parameters"]["random_draws"] == 2000
    arms = external["frames"]["random_400"]["arms"]
    assert arms["none"]["prefix_percentile_rank"] == 1.0
    assert arms["pi_detector"]["prefix_percentile_rank"] == 0.0
    contrasts = external["contrasts"]
    assert contrasts["tool_filter_minus_pi_detector"]["delta_pp"] == -1.113
    assert contrasts["tool_filter_minus_pi_detector"]["ci95_pp"] == [-3.498, 1.431]


def figure_prefix_percentiles() -> Path:
    frozen = _load(FROZEN)
    external = _load(EXTERNAL)
    _check(frozen, external)

    fig, (left, right) = plt.subplots(
        1, 2, figsize=(7.0, 2.75),
        gridspec_kw={"width_ratios": [1.25, 1.0], "wspace": 0.42})

    order = [(rule, policy) for rule in _RULE_LABELS
             for policy in ("log_and_allow", "block")]
    labels = [f"{_RULE_LABELS[r]} / {_POLICY_LABELS[p]}" for r, p in order]
    values = [frozen["random_400"][f"{r}|{p}"]["prefix_percentile_rank"]
              for r, p in order]
    ys = list(range(len(order)))[::-1]
    left.hlines(ys, 0, 1, color="0.85", linewidth=0.8, zorder=1)
    left.axvline(0.5, color="0.35", linewidth=0.8, linestyle=(0, (3, 2)), zorder=1)
    left.scatter(values, ys, marker="o", s=22, color="black", zorder=3)
    left.set_yticks(ys)
    left.set_yticklabels(labels, fontsize=7.5)
    left.set_xlim(-0.02, 1.02)
    left.set_ylim(-0.7, len(order) - 0.3)
    left.set_xlabel("percentile of the 400-trace prefix")
    left.set_title("(a) frozen corpus: 8 rule $\\times$ semantics cells",
                   fontsize=8.2, pad=4)
    left.tick_params(axis="x", labelsize=7.5)

    arms = ["none", "tool_filter", "pi_detector",
            "repeat_user_prompt", "spotlighting"]
    ys = list(range(len(arms)))[::-1]
    values = [external["frames"]["random_400"]["arms"][a]["prefix_percentile_rank"]
              for a in arms]
    right.hlines(ys, 0, 1, color="0.85", linewidth=0.8, zorder=1)
    right.axvline(0.5, color="0.35", linewidth=0.8, linestyle=(0, (3, 2)), zorder=1)
    right.scatter(values, ys, marker="o", s=22, color="black", zorder=3)
    right.set_yticks(ys)
    right.set_yticklabels([_ARM_LABELS[a] for a in arms], fontsize=7.5)
    right.set_xlim(-0.02, 1.02)
    right.set_ylim(-0.7, len(arms) - 0.3)
    right.set_xlabel("percentile of the 400-cell prefix")
    right.set_title("(b) public artifact: 5 defenses", fontsize=8.2, pad=4)
    right.tick_params(axis="x", labelsize=7.5)

    return _save(fig, "route_b_prefix_percentiles")


def _annotate_delta(ax, delta: float, y: float) -> None:
    """Place the value label on the side away from the zero line."""
    offset, ha = ((6, 0), "left") if delta >= 0 else ((-6, 0), "right")
    ax.annotate(f"{delta:+.2f}", (delta, y), xytext=offset,
                textcoords="offset points", ha=ha, va="center", fontsize=7,
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.6})


def figure_contrasts() -> Path:
    frozen = _load(FROZEN)
    external = _load(EXTERNAL)
    _check(frozen, external)

    fig, (top, bottom) = plt.subplots(
        2, 1, figsize=(7.0, 4.1), gridspec_kw={"hspace": 0.55})

    full = frozen["contrasts"]["full"]
    prefix = frozen["contrasts"]["published_prefix"]
    rows = [
        ("band split $-$ hard first (attack)",
         full["band_split_minus_hard_first|block"],
         "attack_trace_block_rate"),
        ("band split $-$ hard first (benign)",
         full["band_split_minus_hard_first|block"],
         "benign_trace_block_rate"),
        ("band split $-$ global cap (attack, census)",
         full["band_split_minus_global_cap|block"],
         "attack_trace_block_rate"),
        ("band split $-$ global cap (attack, prefix)",
         prefix["band_split_minus_global_cap|block"],
         "attack_trace_block_rate"),
    ]
    ys = list(range(len(rows)))[::-1]
    for y, (label, entry, field) in zip(ys, rows):
        delta = 100 * entry[f"{field}_delta"]
        low, high = (100 * v for v in entry[f"{field}_delta_ci95"])
        if high - low < 1e-9:
            top.scatter([delta], [y], marker="D", s=18, color="black", zorder=3)
        else:
            top.errorbar([delta], [y], xerr=[[delta - low], [high - delta]],
                         fmt="o", markersize=3.5, color="black",
                         capsize=2.5, linewidth=0.9, zorder=3)
        _annotate_delta(top, delta, y)
    top.axvline(0, color="0.35", linewidth=0.8, linestyle=(0, (3, 2)))
    top.set_yticks(ys)
    top.set_yticklabels([r[0] for r in rows], fontsize=7.4)
    top.set_xlim(-1.2, 8.6)
    top.set_ylim(-0.7, len(rows) - 0.3)
    top.set_xlabel("paired difference (percentage points)")
    top.set_title("(a) frozen corpus: same 13,913 decisions",
                  fontsize=8.2, pad=4)
    top.tick_params(axis="x", labelsize=7.5)

    order = [
        ("tool filter $-$ pi detector", "tool_filter_minus_pi_detector"),
        ("tool filter $-$ no defense", "tool_filter_minus_none"),
        ("pi detector $-$ no defense", "pi_detector_minus_none"),
        ("repeat prompt $-$ no defense", "repeat_user_prompt_minus_none"),
        ("spotlighting $-$ no defense", "spotlighting_minus_none"),
    ]
    ys = list(range(len(order)))[::-1]
    for y, (label, key) in zip(ys, order):
        entry = external["contrasts"][key]
        delta = entry["delta_pp"]
        low, high = entry["ci95_pp"]
        bottom.errorbar([delta], [y], xerr=[[delta - low], [high - delta]],
                        fmt="o", markersize=3.5, color="black",
                        capsize=2.5, linewidth=0.9, zorder=3)
        _annotate_delta(bottom, delta, y)
    bottom.axvline(0, color="0.35", linewidth=0.8, linestyle=(0, (3, 2)))
    bottom.set_yticks(ys)
    bottom.set_yticklabels([r[0] for r in order], fontsize=7.4)
    bottom.set_xlim(-48, 9)
    bottom.set_ylim(-0.7, len(order) - 0.3)
    bottom.set_xlabel("paired difference (percentage points)")
    bottom.set_title("(b) public artifact: 629 paired cells",
                     fontsize=8.2, pad=4)
    bottom.tick_params(axis="x", labelsize=7.5)

    return _save(fig, "route_b_contrasts")


def main() -> int:
    written = [figure_prefix_percentiles(), figure_contrasts()]
    for path in written:
        print(f"wrote {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
