"""
scorer.py
─────────
Computes the forensic intent score and summary statistics
from a list of BlockResults and Regions.

Intent score (0–100):
    Weighted combination of:
    - % of disk covered by wipe artefacts
    - number and size of distinct wipe regions
    - presence of high-confidence RANDOM_WIPE (hardest to explain innocently)
    - presence of MULTI_PASS (deliberate tool usage)

Verdict:
    HIGH   >= 70  -- Strong evidence of deliberate anti-forensic wiping
    MEDIUM 35-69  -- Moderate evidence; further correlation recommended
    LOW    <  35  -- Low probability of intentional wiping

Usage:
    from engine.scorer import compute_score, ScanStats
"""

from dataclasses import dataclass
from typing import List

from engine.classifier import BlockResult
from engine.aggregator import Region


@dataclass
class ScanStats:
    total_blocks:        int
    suspicious_blocks:   int
    suspicious_pct:      float
    regions_count:       int
    avg_entropy_flagged: float
    intent_score:        int      # 0-100
    verdict:             str      # HIGH | MEDIUM | LOW
    wipe_type_counts:    dict     # { "ZERO_WIPE": N, ... }

    def to_dict(self) -> dict:
        return {
            "total_blocks":        self.total_blocks,
            "suspicious_blocks":   self.suspicious_blocks,
            "suspicious_pct":      round(self.suspicious_pct, 2),
            "regions_count":       self.regions_count,
            "avg_entropy_flagged": round(self.avg_entropy_flagged, 3),
            "intent_score":        self.intent_score,
            "verdict":             self.verdict,
            "wipe_type_counts":    self.wipe_type_counts,
        }


def compute_score(
    blocks:  List[BlockResult],
    regions: List[Region],
) -> ScanStats:
    """
    Derive intent score and summary statistics from scan results.

    Parameters
    ----------
    blocks  : flat list of all BlockResult objects
    regions : aggregated Region objects

    Returns
    -------
    ScanStats
    """
    total = len(blocks)
    if total == 0:
        return _empty_stats()

    # ── Basic counts ──────────────────────────────────────────────────────────
    suspicious      = [b for b in blocks if b.is_suspicious]
    n_susp          = len(suspicious)
    susp_pct        = (n_susp / total) * 100

    avg_entropy_flagged = (
        sum(b.entropy for b in suspicious) / n_susp
        if n_susp > 0 else 0.0
    )

    # ── Wipe type counts ──────────────────────────────────────────────────────
    type_counts = {
        "ZERO_WIPE":   0,
        "FF_WIPE":     0,
        "RANDOM_WIPE": 0,
        "MULTI_PASS":  0,
    }
    for b in suspicious:
        if b.wipe_type in type_counts:
            type_counts[b.wipe_type] += 1

    # ── Intent score components ───────────────────────────────────────────────
    #
    # Component 1: coverage (0-40 pts)
    #   0% coverage -> 0 pts, 10%+ coverage -> 40 pts
    coverage_score = min(susp_pct / 10.0, 1.0) * 40

    # Component 2: region count (0-20 pts)
    #   More distinct regions = more deliberate targeting
    region_score = min(len(regions) / 10.0, 1.0) * 20

    # Component 3: RANDOM_WIPE presence (0-25 pts)
    #   Pseudorandom overwrites are the strongest indicator of a wipe tool
    rand_regions = [r for r in regions if r.wipe_type == "RANDOM_WIPE"]
    rand_score   = min(len(rand_regions) / 3.0, 1.0) * 25

    # Component 4: MULTI_PASS presence (0-15 pts)
    #   Multi-pass = deliberate tool (CCleaner, shred, sdelete etc.)
    multi_regions = [r for r in regions if r.wipe_type == "MULTI_PASS"]
    multi_score   = min(len(multi_regions) / 2.0, 1.0) * 15

    raw_score    = coverage_score + region_score + rand_score + multi_score
    intent_score = min(int(round(raw_score)), 100)

    # ── Verdict ───────────────────────────────────────────────────────────────
    if intent_score >= 70:
        verdict = "HIGH"
    elif intent_score >= 35:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return ScanStats(
        total_blocks        = total,
        suspicious_blocks   = n_susp,
        suspicious_pct      = susp_pct,
        regions_count       = len(regions),
        avg_entropy_flagged = avg_entropy_flagged,
        intent_score        = intent_score,
        verdict             = verdict,
        wipe_type_counts    = type_counts,
    )


def _empty_stats() -> ScanStats:
    return ScanStats(
        total_blocks=0, suspicious_blocks=0, suspicious_pct=0.0,
        regions_count=0, avg_entropy_flagged=0.0,
        intent_score=0, verdict="LOW",
        wipe_type_counts={
            "ZERO_WIPE": 0, "FF_WIPE": 0,
            "RANDOM_WIPE": 0, "MULTI_PASS": 0,
        },
    )
