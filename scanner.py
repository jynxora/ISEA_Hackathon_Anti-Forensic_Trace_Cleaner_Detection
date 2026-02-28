"""
scanner.py
──────────
Top-level orchestrator. Wires together:

    reader.py      → stream blocks from disk image
    classifier.py  → classify each block
    aggregator.py  → merge into regions, detect multi-pass
    scorer.py      → compute intent score + stats
    writer.py      → write analysis_<SID>.json

This is the single function FastAPI calls after a successful upload.

Usage:
    from scanner import run_scan

    json_path = run_scan(
        image_path = "uploads/SID-A3F8C21E_suspect.dd",
        session_id = "SID-A3F8C21E",
        sha256     = "e3b0c44...",
    )
"""

import sys
from pathlib import Path
from typing import Callable

from engine.reader     import BlockReader
from engine.classifier import classify_block, BlockResult
from engine.aggregator import aggregate
from engine.scorer     import compute_score
from engine.writer     import write_results


def run_scan(
    image_path:   str | Path,
    session_id:   str,
    sha256:       str,
    output_dir:   str | Path = Path("uploads"),
    progress_cb:  Callable[[int, int], None] | None = None,
) -> Path:
    """
    Run the full wipe detection pipeline on a raw disk image.

    Parameters
    ----------
    image_path  : path to the uploaded disk image
    session_id  : session ID string (e.g. "SID-A3F8C21E")
    sha256      : pre-computed SHA-256 of the image (from hashing.py)
    output_dir  : directory to write the JSON result into
    progress_cb : optional callback(blocks_done, total_blocks) for
                  progress reporting (used by FastAPI to push SSE updates)

    Returns
    -------
    Path to the written analysis_<SID>.json file
    """

    image_path = Path(image_path)
    reader     = BlockReader(image_path)
    total      = reader.total_blocks

    print(f"[scanner] Starting scan: {image_path.name}")
    print(f"[scanner] Total blocks : {total:,}  ({reader.image_size / (1024**3):.2f} GB)")

    # ── Phase 1: Classify every block ─────────────────────────────────────────
    block_results: list[BlockResult] = []

    for block in reader:
        result = classify_block(block.id, block.offset, block.data)
        block_results.append(result)

        # Progress callback every 10 000 blocks
        if progress_cb and block.id % 10_000 == 0:
            progress_cb(block.id, total)

    print(f"[scanner] Classification done. Suspicious blocks: "
          f"{sum(1 for b in block_results if b.is_suspicious):,}")

    # ── Phase 2: Aggregate into regions ───────────────────────────────────────
    regions = aggregate(block_results)
    print(f"[scanner] Regions detected: {len(regions)}")

    # ── Phase 3: Compute intent score ─────────────────────────────────────────
    stats = compute_score(block_results, regions)
    print(f"[scanner] Intent score: {stats.intent_score}  Verdict: {stats.verdict}")

    # ── Phase 4: Write JSON ────────────────────────────────────────────────────
    json_path = write_results(
        session_id = session_id,
        filename   = image_path.name,
        sha256     = sha256,
        size_bytes = reader.image_size,
        blocks     = block_results,
        regions    = regions,
        stats      = stats,
        output_dir = Path(output_dir),
    )

    print(f"[scanner] Results written to: {json_path}")
    return json_path


# ── CLI convenience ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scanner.py <image_path> <session_id> [sha256]")
        sys.exit(1)

    img   = sys.argv[1]
    sid   = sys.argv[2]
    sha   = sys.argv[3] if len(sys.argv) > 3 else "unknown"

    out   = run_scan(img, sid, sha)
    print(f"\nDone. JSON at: {out}")
