# tests/test_corpus_eval.py

import pathlib
from dataclasses import dataclass
from typing import Literal, List, Dict, Tuple

import pytest

import scanner.core as core
import scanner.config as cfg
from scanner.config import SafePushConfig


Label = Literal["SECRET", "SAFE"]
Source = Literal["entropy", "pattern"]


@dataclass
class LabeledLine:
    file: str
    line_no: int
    text: str
    label: Label
    source: Source


@pytest.fixture(autouse=True)
def reset_config():
    """
    For corpus evaluation we DON'T want .safepush.yml ignores (like tests/**).
    So we temporarily replace cfg._CONFIG with an empty SafePushConfig.
    """
    original = cfg._CONFIG
    cfg._CONFIG = SafePushConfig()
    yield
    cfg._CONFIG = original


def _parse_label_from_comment(line: str) -> Tuple[Label | None, Source | None]:
    """
    Parse labels from trailing comment of the form:

        # safepush: EXPECT_SECRET entropy HIGH
        # safepush: EXPECT_SAFE pattern

    Returns (label, source) or (None, None) if the line is unlabeled.
    """
    marker = "# safepush:"
    if marker not in line:
        return None, None

    comment = line.split(marker, 1)[1].strip()
    parts = comment.split()

    if not parts:
        return None, None

    tag = parts[0].upper()
    label: Label | None = None
    if tag == "EXPECT_SECRET":
        label = "SECRET"
    elif tag == "EXPECT_SAFE":
        label = "SAFE"
    else:
        return None, None

    src: Source | None = None
    if len(parts) >= 2:
        if parts[1] in ("entropy", "pattern"):
            src = parts[1]  # type: ignore[assignment]

    return label, src


def _load_corpus() -> List[LabeledLine]:
    root = pathlib.Path(__file__).parent / "corpus"
    labeled: List[LabeledLine] = []

    for path in sorted(root.glob("*.py")):
        with path.open("r", encoding="utf-8") as f:
            for i, raw_line in enumerate(f, start=1):
                label, source = _parse_label_from_comment(raw_line)
                if not label or not source:
                    continue

                labeled.append(
                    LabeledLine(
                        file=str(path),
                        line_no=i,
                        text=raw_line.rstrip("\n"),
                        label=label,
                        source=source,
                    )
                )
    return labeled


def _predict_has_finding(sample: LabeledLine) -> bool:
    """
    Treat a line as 'SECRET' only if there is a MEDIUM or HIGH
    severity finding. LOW is considered non-blocking noise here.
    """
    findings = core.scan_line(sample.file, sample.line_no, sample.text)
    return any(f.severity in ("MEDIUM", "HIGH") for f in findings)



def _predict_source(sample: LabeledLine) -> str | None:
    """
    Very rough classification of what triggered us:

    - If any Finding.reason starts with "Matches", we count it as provider pattern.
    - If reason mentions entropy/suspicious, we count it as entropy.
    """
    findings = core.scan_line(sample.file, sample.line_no, sample.text)
    if not findings:
        return None

    reasons = [f.reason for f in findings]
    if any(r.startswith("Matches ") for r in reasons):
        return "pattern"
    if any("entropy" in r.lower() or "suspicious" in r.lower() for r in reasons):
        return "entropy"
    return None


def test_labeled_corpus_precision_recall():
    samples = _load_corpus()
    assert samples, "No labeled corpus samples found"

    # Overall confusion counts
    tp = fp = fn = tn = 0

    # Per-source confusion counts
    per_source: Dict[Source, Dict[str, int]] = {
        "entropy": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "pattern": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
    }

    false_positives: list[LabeledLine] = []
    false_negatives: list[LabeledLine] = []

    for s in samples:
        y_true = 1 if s.label == "SECRET" else 0
        y_pred = 1 if _predict_has_finding(s) else 0

        if y_true == 1 and y_pred == 1:
            tp += 1
        elif y_true == 0 and y_pred == 1:
            fp += 1
            false_positives.append(s)
        elif y_true == 1 and y_pred == 0:
            fn += 1
            false_negatives.append(s)
        else:
            tn += 1

        # per source (based on EXPECT_* source label)
        bucket = per_source[s.source]
        if y_true == 1 and y_pred == 1:
            bucket["tp"] += 1
        elif y_true == 0 and y_pred == 1:
            bucket["fp"] += 1
        elif y_true == 1 and y_pred == 0:
            bucket["fn"] += 1
        else:
            bucket["tn"] += 1

    def _metrics(tp: int, fp: int, fn: int) -> tuple[float, float]:
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        return prec, rec

    overall_prec, overall_rec = _metrics(tp, fp, fn)
    entropy_prec, entropy_rec = _metrics(
        per_source["entropy"]["tp"],
        per_source["entropy"]["fp"],
        per_source["entropy"]["fn"],
    )
    pattern_prec, pattern_rec = _metrics(
        per_source["pattern"]["tp"],
        per_source["pattern"]["fp"],
        per_source["pattern"]["fn"],
    )

    # Print metrics for manual inspection (shown with `pytest -s`)
    print("\n--- Labeled corpus metrics ---")
    print(f"Overall:  precision={overall_prec:.3f}, recall={overall_rec:.3f}")
    print(f"Entropy:  precision={entropy_prec:.3f}, recall={entropy_rec:.3f}")
    print(f"Patterns: precision={pattern_prec:.3f}, recall={pattern_rec:.3f}")

    if false_positives:
        print("\nFalse positives:")
        for s in false_positives:
            print(f"  FP {s.source} {s.file}:{s.line_no}: {s.text}")

    if false_negatives:
        print("\nFalse negatives:")
        for s in false_negatives:
            print(f"  FN {s.source} {s.file}:{s.line_no}: {s.text}")

    # For now, just assert we don't have any false negatives in this tiny corpus.
    assert fn == 0, f"Found {fn} false negatives in labeled corpus"
