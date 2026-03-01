"""
scorer.py
─────────
Computes the forensic intent score and summary statistics.

Intent model — hybrid approach combining team's density thresholds
with our weighted evidence scoring:

    Stage 1: Wipe density fast-path (from team's analysis_engine.py)
        If wipe_density > 0.30 -> strong coverage signal -> HIGH floor
        If wipe_density > 0.10 -> moderate coverage     -> MEDIUM floor
        If wipe_density > 0.02 -> low coverage          -> LOW floor

    Stage 2: Evidence quality scoring (0-100 pts)
        Coverage score   (0-40 pts): % of disk with wipe artefacts
        Region score     (0-20 pts): distinct targeted regions
        RANDOM_WIPE score(0-25 pts): strongest tool indicator
        MULTI_PASS score (0-15 pts): deliberate tool usage confirmed

    Stage 3: Penalty adjustments
        High LIKELY_* ratio without STRONG evidence: -10 pts
            (partial wipes alone are weak evidence)
        Low confidence average across regions: -5 pts

    Stage 4: Verdict
        Density fast-path can RAISE but not lower the score verdict.
        Final verdict = max(density_verdict, score_verdict)

Verdict thresholds:
    HIGH       >= 70   Strong evidence of deliberate anti-forensic wiping
    MEDIUM     35-69   Moderate evidence — correlate with other artefacts
    LOW        10-34   Weak signal — likely benign or insufficient data
    NEGLIGIBLE  < 10   No meaningful wipe evidence detected
"""

from dataclasses import dataclass
from typing import List

from engine.classifier import BlockResult
from engine.aggregator import Region, STRONG_WIPE_TYPES, PARTIAL_WIPE_TYPES


@dataclass
class ScanStats:
    total_blocks:        int
    suspicious_blocks:   int
    suspicious_pct:      float
    wipe_density:        float   # suspicious / total (from team's model)
    regions_count:       int
    avg_entropy_flagged: float
    intent_score:        int     # 0-100
    verdict:             str     # HIGH | MEDIUM | LOW | NEGLIGIBLE
    wipe_type_counts:    dict

    def to_dict(self) -> dict:
        return {
            "total_blocks":        self.total_blocks,
            "suspicious_blocks":   self.suspicious_blocks,
            "suspicious_pct":      round(self.suspicious_pct, 2),
            "wipe_density":        round(self.wipe_density, 4),
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
    Compute forensic intent score from block-level and region-level evidence.
    """
    total = len(blocks)
    if total == 0:
        return _empty_stats()

    # ── Block-level counts ────────────────────────────────────────────────────
    suspicious   = [b for b in blocks if b.is_suspicious]
    n_susp       = len(suspicious)
    susp_pct     = (n_susp / total) * 100
    wipe_density = n_susp / total   # from team's model

    avg_entropy_flagged = (
        sum(b.entropy for b in suspicious) / n_susp if n_susp > 0 else 0.0
    )

    # ── Wipe type counts ──────────────────────────────────────────────────────
    type_counts = {
        "ZERO_WIPE":           0,
        "FF_WIPE":             0,
        "RANDOM_WIPE":         0,
        "MULTI_PASS":          0,
        "LIKELY_ZERO_WIPE":    0,
        "LIKELY_FF_WIPE":      0,
        "LOW_ENTROPY_SUSPECT": 0,
    }
    for b in suspicious:
        if b.wipe_type in type_counts:
            type_counts[b.wipe_type] += 1

    # ── Stage 1: density fast-path verdict floor ──────────────────────────────
    # Directly from team's analysis_engine.py intent model
    if wipe_density > 0.30:
        density_verdict = "HIGH"
    elif wipe_density > 0.10:
        density_verdict = "MEDIUM"
    elif wipe_density > 0.02:
        density_verdict = "LOW"
    elif n_susp >= 2:
        density_verdict = "LOW"
    else:
        density_verdict = "NEGLIGIBLE"

    # ── Stage 2: evidence quality score (0-100 pts) ───────────────────────────

    # Coverage (0-40 pts): scales 0% -> 0 pts, 10%+ -> 40 pts
    coverage_score = min(susp_pct / 10.0, 1.0) * 40

    # Region count (0-20 pts): more distinct regions = more deliberate targeting
    # Targeted wiping (few high-confidence regions) scores differently than
    # mass wiping (many regions) — both are weighted here
    region_score = min(len(regions) / 10.0, 1.0) * 20

    # RANDOM_WIPE (0-25 pts): strongest wipe tool indicator
    # Pseudorandom overwrites cannot appear naturally
    rand_regions = [r for r in regions if r.wipe_type == "RANDOM_WIPE"]
    rand_score   = min(len(rand_regions) / 3.0, 1.0) * 25

    # MULTI_PASS (0-15 pts): confirms deliberate tool (shred, Gutmann, DoD)
    multi_regions = [r for r in regions if r.wipe_type == "MULTI_PASS"]
    multi_score   = min(len(multi_regions) / 2.0, 1.0) * 15

    raw_score = coverage_score + region_score + rand_score + multi_score

    # ── Stage 3: penalty adjustments ─────────────────────────────────────────

    # Penalty 1: high proportion of LIKELY_* without strong corroboration
    strong_count  = sum(type_counts.get(t, 0) for t in STRONG_WIPE_TYPES)
    partial_count = sum(type_counts.get(t, 0) for t in PARTIAL_WIPE_TYPES)
    if n_susp > 0 and partial_count > strong_count and strong_count < 10:
        raw_score -= 10  # mostly partial evidence, not enough hard confirmation

    # Penalty 2: low average region confidence
    if regions:
        avg_conf = sum(r.confidence for r in regions) / len(regions)
        if avg_conf < 0.55:
            raw_score -= 5

    intent_score = min(max(int(round(raw_score)), 0), 100)

    # ── Stage 4: verdict — density floor + score ─────────────────────────────
    if intent_score >= 70:
        score_verdict = "HIGH"
    elif intent_score >= 35:
        score_verdict = "MEDIUM"
    elif intent_score >= 10:
        score_verdict = "LOW"
    else:
        score_verdict = "NEGLIGIBLE"

    # Density fast-path can raise the verdict but not lower it
    verdict_order = ["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH"]
    final_verdict = verdict_order[
        max(verdict_order.index(score_verdict),
            verdict_order.index(density_verdict))
    ]

    return ScanStats(
        total_blocks        = total,
        suspicious_blocks   = n_susp,
        suspicious_pct      = susp_pct,
        wipe_density        = wipe_density,
        regions_count       = len(regions),
        avg_entropy_flagged = avg_entropy_flagged,
        intent_score        = intent_score,
        verdict             = final_verdict,
        wipe_type_counts    = type_counts,
    )


def _empty_stats() -> ScanStats:
    return ScanStats(
        total_blocks=0, suspicious_blocks=0, suspicious_pct=0.0,
        wipe_density=0.0, regions_count=0, avg_entropy_flagged=0.0,
        intent_score=0, verdict="NEGLIGIBLE",
        wipe_type_counts={
            "ZERO_WIPE": 0, "FF_WIPE": 0, "RANDOM_WIPE": 0,
            "MULTI_PASS": 0, "LIKELY_ZERO_WIPE": 0,
            "LIKELY_FF_WIPE": 0, "LOW_ENTROPY_SUSPECT": 0,
        },
    )