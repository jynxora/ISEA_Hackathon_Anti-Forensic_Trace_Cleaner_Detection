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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from engine.reader     import BlockReader
from engine.classifier import classify_block, BlockResult
from engine.aggregator import aggregate
from engine.scorer     import compute_score
from engine.writer     import write_results


# ── Fallback region dataclass (mirrors whatever aggregator.py produces) ────────
@dataclass
class FallbackRegion:
    """
    Mirrors engine.aggregator.Region exactly so scorer.py and writer.py
    can consume it without any special-casing.
    """
    id:           int
    start_offset: int
    end_offset:   int
    size:         int
    wipe_type:    str
    avg_entropy:  float
    confidence:   float
    block_count:  int
    blocks:       list = None

    def __post_init__(self):
        if self.blocks is None:
            self.blocks = []

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "start":       self.start_offset,
            "end":         self.end_offset,
            "size":        self.size,
            "type":        self.wipe_type,
            "entropy":     round(self.avg_entropy, 3),
            "confidence":  round(self.confidence, 3),
            "block_count": self.block_count,
        }


def _fallback_aggregate(block_results: list[BlockResult]) -> list:
    """
    Pure-Python fallback region builder.

    Groups consecutive suspicious blocks into contiguous regions.
    Runs when the primary aggregate() returns an empty list despite
    suspicious blocks being present (e.g. aggregator API mismatch).

    Assumes BlockResult has (tries common field name variants):
        .id / .block_id / .block_index : int   block index
        .offset / .byte_offset         : int   byte offset
        .is_suspicious                 : bool
        .type / .block_type            : str   e.g. "ZERO_WIPE", "FF_WIPE", "NORMAL" …
        .entropy                       : float
        .confidence                    : float (optional, defaults to 1.0 if absent)

    Block size is inferred from two consecutive blocks' offsets.
    Falls back to 512 bytes if only one block exists.
    """
    BLOCK_SIZE = 512  # default fallback

    # Infer block size from first two blocks
    if len(block_results) >= 2:
        BLOCK_SIZE = block_results[1].offset - block_results[0].offset
        if BLOCK_SIZE <= 0:
            BLOCK_SIZE = 512

    regions = []
    region_id = 0

    run_blocks: list[BlockResult] = []

    def _flush(run: list[BlockResult]) -> None:
        nonlocal region_id
        if not run:
            return

        # Dominant type = most frequent type in the run
        type_counts: dict[str, int] = {}
        for b in run:
            type_counts[b.wipe_type] = type_counts.get(b.wipe_type, 0) + 1
        dominant_type = max(type_counts, key=type_counts.__getitem__)

        avg_entropy    = sum(b.entropy for b in run) / len(run)
        avg_confidence = sum(
            getattr(b, "confidence", 1.0) for b in run
        ) / len(run)

        start_offset = run[0].offset
        end_offset   = run[-1].offset + BLOCK_SIZE

        regions.append(FallbackRegion(
            id           = region_id,
            start_offset = start_offset,
            end_offset   = end_offset,
            size         = end_offset - start_offset,
            wipe_type    = dominant_type,
            avg_entropy  = round(avg_entropy, 4),
            confidence   = round(avg_confidence, 4),
            block_count  = len(run),
        ))
        region_id += 1

    for blk in block_results:
        if blk.is_suspicious:
            run_blocks.append(blk)
        else:
            _flush(run_blocks)
            run_blocks = []

    _flush(run_blocks)  # flush any trailing run

    return regions


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
        if progress_cb and block.id % 1_000 == 0:
            progress_cb(block.id, total)

    n_suspicious = sum(1 for b in block_results if b.is_suspicious)
    print(f"[scanner] Classification done. Suspicious blocks: {n_suspicious:,}")

    # ── Debug: log first few suspicious block types so we can verify field names
    suspicious_sample = [b for b in block_results if b.is_suspicious][:5]
    for s in suspicious_sample:
        print(f"[scanner]   sample suspicious block → id={s.block_id} type={s.wipe_type} entropy={s.entropy:.3f}")

    # ── Phase 2: Aggregate into regions ───────────────────────────────────────
    regions = aggregate(block_results)
    print(f"[scanner] aggregate() returned {len(regions)} regions")

    # ── Fallback: if aggregator returned nothing but we have suspicious blocks,
    #    build regions ourselves by merging contiguous suspicious block runs.
    if len(regions) == 0 and n_suspicious > 0:
        print(f"[scanner] WARNING: aggregate() returned 0 regions despite "
              f"{n_suspicious} suspicious blocks — activating fallback aggregation.")
        regions = _fallback_aggregate(block_results)
        print(f"[scanner] Fallback aggregation produced {len(regions)} region(s).")

        # Log first few fallback regions for verification
        for r in regions[:3]:
            print(f"[scanner]   region id={r.id} type={r.wipe_type} blocks={r.block_count} start=0x{r.start_offset:08X}")

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
