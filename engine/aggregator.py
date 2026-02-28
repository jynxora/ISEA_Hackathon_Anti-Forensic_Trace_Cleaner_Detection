"""
aggregator.py
─────────────
Takes the flat list of BlockResult objects from classifier.py and:

    1.  Merges consecutive suspicious blocks of the same type into Regions.
    2.  Applies a minimum size filter (removes noise from isolated blocks).
    3.  Runs a second-pass multi-pass detector: looks for alternating
        ZERO_WIPE / FF_WIPE / RANDOM_WIPE bands — the signature of
        Gutmann / DoD 5220 multi-pass wipes.
    4.  Computes per-region statistics (avg entropy, confidence, size).

Usage:
    from engine.aggregator import aggregate

    regions = aggregate(block_results)
"""

from dataclasses import dataclass, field
from typing import List

from engine.classifier import BlockResult


# ── Tuning ────────────────────────────────────────────────────────────────────

MIN_REGION_BLOCKS  = 16       # minimum consecutive blocks to form a region
                               # 16 × 4096 = 65 536 bytes (64 KB)
                               # single isolated blocks are noise — skip them

MULTI_PASS_MIN_BANDS = 3      # minimum alternating sub-bands to call MULTI_PASS
BLOCK_SIZE           = 4096


# ── Region dataclass ──────────────────────────────────────────────────────────

@dataclass
class Region:
    id:           int
    start_offset: int
    end_offset:   int
    size:         int
    wipe_type:    str
    block_count:  int
    avg_entropy:  float
    confidence:   float
    blocks:       List[int] = field(default_factory=list, repr=False)
    # blocks: list of block IDs included in this region

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "start":        self.start_offset,
            "end":          self.end_offset,
            "size":         self.size,
            "type":         self.wipe_type,
            "entropy":      round(self.avg_entropy, 3),
            "confidence":   round(self.confidence, 3),
            "block_count":  self.block_count,
        }


# ── Main aggregator ───────────────────────────────────────────────────────────

def aggregate(results: List[BlockResult]) -> List[Region]:
    """
    Convert flat block results into merged, filtered, scored regions.

    Parameters
    ----------
    results : list[BlockResult]
        Ordered list of all block classification results.

    Returns
    -------
    list[Region]
        Detected wipe regions, sorted by start offset.
    """
    if not results:
        return []

    raw_regions  = _merge_consecutive(results)
    sized        = _filter_by_size(raw_regions)
    with_multi   = _detect_multi_pass(sized, results)
    finalised    = _compute_confidence(with_multi, results)

    # Assign final sequential IDs
    for i, r in enumerate(finalised, 1):
        r.id = i

    return finalised


# ── Step 1: merge consecutive same-type blocks ────────────────────────────────

def _merge_consecutive(results: List[BlockResult]) -> List[Region]:
    regions = []
    region_id = 0

    i = 0
    while i < len(results):
        block = results[i]

        if not block.is_suspicious:
            i += 1
            continue

        # Start of a new suspicious run
        wipe_type   = block.wipe_type
        start_block = block.block_id
        run_blocks  = [block]

        j = i + 1
        while j < len(results):
            nxt = results[j]
            if nxt.is_suspicious and nxt.wipe_type == wipe_type:
                run_blocks.append(nxt)
                j += 1
            else:
                break

        start_offset = start_block * BLOCK_SIZE
        end_offset   = run_blocks[-1].block_id * BLOCK_SIZE + BLOCK_SIZE - 1
        size         = end_offset - start_offset + 1
        avg_entropy  = sum(b.entropy for b in run_blocks) / len(run_blocks)

        regions.append(Region(
            id           = region_id,
            start_offset = start_offset,
            end_offset   = end_offset,
            size         = size,
            wipe_type    = wipe_type,
            block_count  = len(run_blocks),
            avg_entropy  = avg_entropy,
            confidence   = 0.0,   # computed later
            blocks       = [b.block_id for b in run_blocks],
        ))
        region_id += 1
        i = j

    return regions


# ── Step 2: remove regions smaller than MIN_REGION_BLOCKS ────────────────────

def _filter_by_size(regions: List[Region]) -> List[Region]:
    return [r for r in regions if r.block_count >= MIN_REGION_BLOCKS]


# ── Step 3: detect multi-pass by looking for alternating adjacent bands ───────

def _detect_multi_pass(
    regions: List[Region],
    all_blocks: List[BlockResult],
) -> List[Region]:
    """
    Scan pairs of adjacent regions for alternating wipe types.
    e.g. ZERO_WIPE → FF_WIPE → ZERO_WIPE → FF_WIPE
    or   ZERO_WIPE → RANDOM_WIPE → ZERO_WIPE

    If MULTI_PASS_MIN_BANDS adjacent alternating regions are found,
    merge them into a single MULTI_PASS region.
    """
    if len(regions) < MULTI_PASS_MIN_BANDS:
        return regions

    merged = []
    i = 0

    while i < len(regions):
        # Try to build a band sequence starting here
        band_group = [regions[i]]
        j = i + 1

        while j < len(regions):
            prev = band_group[-1]
            curr = regions[j]

            # Adjacent? (end of prev immediately before start of curr)
            gap = curr.start_offset - prev.end_offset - 1
            is_adjacent = gap <= BLOCK_SIZE * 4   # allow up to 4 normal blocks gap

            # Alternating type?
            is_alternating = (
                curr.wipe_type != prev.wipe_type
                and curr.wipe_type in ("ZERO_WIPE", "FF_WIPE", "RANDOM_WIPE")
                and prev.wipe_type in ("ZERO_WIPE", "FF_WIPE", "RANDOM_WIPE")
            )

            if is_adjacent and is_alternating:
                band_group.append(curr)
                j += 1
            else:
                break

        if len(band_group) >= MULTI_PASS_MIN_BANDS:
            # Merge into one MULTI_PASS region
            all_block_ids = []
            for r in band_group:
                all_block_ids.extend(r.blocks)

            block_entropies = [
                all_blocks[bid].entropy
                for bid in all_block_ids
                if bid < len(all_blocks)
            ]
            avg_entropy = sum(block_entropies) / len(block_entropies) if block_entropies else 0.0

            merged.append(Region(
                id           = 0,
                start_offset = band_group[0].start_offset,
                end_offset   = band_group[-1].end_offset,
                size         = band_group[-1].end_offset - band_group[0].start_offset + 1,
                wipe_type    = "MULTI_PASS",
                block_count  = sum(r.block_count for r in band_group),
                avg_entropy  = avg_entropy,
                confidence   = 0.0,
                blocks       = all_block_ids,
            ))
            i = j
        else:
            merged.append(regions[i])
            i += 1

    return merged


# ── Step 4: compute final confidence per region ───────────────────────────────

def _compute_confidence(
    regions: List[Region],
    all_blocks: List[BlockResult],
) -> List[Region]:
    """
    Refine confidence scores using region-level context:
    - Larger regions = higher confidence (isolated blocks are noise)
    - Average block-level confidence from classifier
    - Type-specific adjustments
    """
    for r in regions:
        block_confs = [
            all_blocks[bid].confidence
            for bid in r.blocks
            if bid < len(all_blocks)
        ]
        avg_block_conf = sum(block_confs) / len(block_confs) if block_confs else 0.5

        # Size bonus: 0.0 at 16 blocks, +0.10 at 1000+ blocks
        size_bonus = min(r.block_count / 1000, 1.0) * 0.10

        # Type adjustments
        type_base = {
            "ZERO_WIPE":   0.0,
            "FF_WIPE":     0.0,
            "RANDOM_WIPE": -0.05,   # slightly penalised — compressed data false-positive risk
            "MULTI_PASS":  -0.10,   # hardest to confirm without pass-count data
        }.get(r.wipe_type, 0.0)

        r.confidence = round(
            min(avg_block_conf + size_bonus + type_base, 1.0), 3
        )

    return regions
