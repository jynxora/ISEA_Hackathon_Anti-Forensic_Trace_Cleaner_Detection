"""
writer.py
─────────
Serialises the full scan result to:

    uploads/analysis_<SESSION_ID>.json

Schema is the single source of truth consumed by analysis_dashboard.html.
Updated to handle new wipe types (LIKELY_ZERO_WIPE, LIKELY_FF_WIPE,
LOW_ENTROPY_SUSPECT) and the wipe_density field added to ScanStats.

Usage:
    from engine.writer import write_results

    path = write_results(
        session_id = "SID-A3F8C21E",
        filename   = "suspect.dd",
        sha256     = "e3b0c44...",
        size_bytes = 4294967296,
        blocks     = block_results,
        regions    = regions,
        stats      = scan_stats,
        output_dir = Path("uploads"),
    )
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from engine.classifier import BlockResult
from engine.aggregator import Region
from engine.scorer import ScanStats


def write_results(
    session_id: str,
    filename:   str,
    sha256:     str,
    size_bytes: int,
    blocks:     List[BlockResult],
    regions:    List[Region],
    stats:      ScanStats,
    output_dir: Path = Path("uploads"),
) -> Path:
    """
    Write analysis results to JSON and return the output path.
    """
    output_dir  = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"analysis_{session_id}.json"

    payload = {
        "session_id":  session_id,
        "filename":    filename,
        "sha256":      sha256,
        "size_bytes":  size_bytes,
        "size_human":  _fmt(size_bytes),
        "scanned_at":  datetime.now(timezone.utc).isoformat(),

        # Summary stats (feeds dashboard stat cards + intent score)
        "stats": stats.to_dict(),

        # Regions (feeds dashboard regions table + pie chart)
        "regions": [r.to_dict() for r in regions],

        # Per-block data (feeds entropy chart + hex viewer)
        # Full block list — dashboard samples for chart rendering.
        "blocks": [
            {
                "id":      b.block_id,
                "type":    b.wipe_type,
                "entropy": round(b.entropy, 3),
            }
            for b in blocks
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return output_path


def _fmt(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.2f} {unit}"
        b //= 1024
    return f"{b:.2f} PB"