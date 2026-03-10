"""
aggregator.py
─────────────
Converts the flat list of per-block BlockResult objects into meaningful
forensic Regions, with multi-pass detection and false-positive suppression.

Pipeline:
    1. _merge_consecutive     — group adjacent same-type suspicious blocks
    2. _absorb_noise          — allow small NORMAL gaps within a wipe region
                                (real wipers skip filesystem metadata blocks)
    3. _filter_by_size        — discard regions too small to be deliberate
    4. _detect_multi_pass     — identify alternating band sequences
    5. _suppress_false_pos    — remove isolated regions that look like legit data
    6. _compute_confidence    — region-level confidence using block evidence

Key insight on noise absorption:
    Real wipe tools do NOT wipe 100% consecutively. They skip:
    - Active MFT entries (NTFS)
    - Partition tables and boot sectors
    - Bad sector markers
    - Filesystem journal blocks
    This means a genuine wipe region may have small gaps of NORMAL blocks
    interspersed. We allow gaps up to MAX_NORMAL_GAP blocks before breaking
    a region into two.

Key insight on false-positive suppression:
    A single isolated region of LIKELY_ZERO_WIPE with low confidence in
    the middle of otherwise clean data is more likely to be a sparse file
    or filesystem structure than a deliberate wipe. We apply contextual
    suppression: isolated low-confidence regions of LIKELY_* types that
    are not corroborated by neighbouring evidence are downgraded to NORMAL.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from engine.classifier import BlockResult


# ─────────────────────────────────────────────────────────────────────────────
# TUNING
# ─────────────────────────────────────────────────────────────────────────────

BLOCK_SIZE            = 512
MIN_REGION_BLOCKS     = 16      # 64 KB minimum — single blocks are noise
MAX_NORMAL_GAP        = 8       # allow up to 8 NORMAL blocks within a wipe region
                                 # before splitting into two regions
MULTI_PASS_MIN_BANDS  = 3       # minimum alternating bands to confirm MULTI_PASS
MULTI_PASS_GAP_BLOCKS = 4       # max gap between bands to still count as adjacent
ISOLATION_WINDOW      = 50      # blocks to look left/right when checking isolation

# Confidence penalty applied to wipe regions beyond every partition boundary.
# These sectors were likely never written; the fill pattern is factory default,
# not deliberate wiping.  We penalise rather than eliminate entirely because
# some legitimate wipers do overwrite beyond the last partition.
BEYOND_BOUNDARY_PENALTY = 0.28   # subtract from confidence when region is beyond boundary

# LIKELY_* types: require corroboration to avoid false positives
PARTIAL_WIPE_TYPES    = {"LIKELY_ZERO_WIPE", "LIKELY_FF_WIPE", "LOW_ENTROPY_SUSPECT"}
STRONG_WIPE_TYPES     = {"ZERO_WIPE", "FF_WIPE", "RANDOM_WIPE", "MULTI_PASS"}


# ─────────────────────────────────────────────────────────────────────────────
# REGION DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Region:
    id:               int
    start_offset:     int
    end_offset:       int
    size:             int
    wipe_type:        str
    block_count:      int
    avg_entropy:      float
    confidence:       float
    blocks:           List[int] = field(default_factory=list, repr=False)
    boundary_context: str = "UNKNOWN"   # INSIDE_PARTITION | BEYOND_BOUNDARY | UNKNOWN

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "start":            self.start_offset,
            "end":              self.end_offset,
            "size":             self.size,
            "type":             self.wipe_type,
            "entropy":          round(self.avg_entropy, 3),
            "confidence":       round(self.confidence, 3),
            "block_count":      self.block_count,
            "boundary_context": self.boundary_context,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def aggregate(results: List[BlockResult], partition_map=None) -> List[Region]:
    """
    Convert flat BlockResult list into confirmed wipe Regions.

    Parameters
    ----------
    results        : ordered list of all BlockResult objects from classifier.py
    partition_map  : optional PartitionMap from partition_map.py; when supplied
                     each region is annotated with its boundary context and
                     regions beyond every partition boundary receive a
                     confidence penalty (they are likely unwritten sectors,
                     not deliberate wipes).

    Returns
    -------
    list[Region] sorted by start offset, IDs assigned sequentially
    """
    if not results:
        return []
    id_to_idx = {b.block_id: i for i, b in enumerate(results)}
    
    raw = _merge_consecutive(results)
    print(f"[aggregator] after _merge_consecutive: {len(raw)} regions")
    
    absorbed = _absorb_noise(raw, results, id_to_idx)
    print(f"[aggregator] after _absorb_noise: {len(absorbed)} regions")
    
    sized = _filter_by_size(absorbed)
    print(f"[aggregator] after _filter_by_size: {len(sized)} regions")
    
    with_multi = _detect_multi_pass(sized, results, id_to_idx)
    print(f"[aggregator] after _detect_multi_pass: {len(with_multi)} regions")
    
    clean = _suppress_false_positives(with_multi, results, id_to_idx)
    print(f"[aggregator] after _suppress_false_positives: {len(clean)} regions")
    
    scored = _compute_confidence(clean, results, id_to_idx)

    # Step 7: apply partition boundary context (if partition map available)
    if partition_map is not None and partition_map.scheme != "UNKNOWN":
        scored = _apply_boundary_context(scored, partition_map)
        beyond = sum(1 for r in scored if r.boundary_context == "BEYOND_BOUNDARY")
        print(f"[aggregator] after _apply_boundary_context: "
              f"{beyond}/{len(scored)} regions beyond partition boundary")

    for i, r in enumerate(scored, 1):
        r.id = i
    return scored


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: merge consecutive same-type suspicious blocks
# ─────────────────────────────────────────────────────────────────────────────

def _dominant_type(blocks):
    counts = {}
    for b in blocks:
        counts[b.wipe_type] = counts.get(b.wipe_type, 0) + 1
    return max(counts, key=counts.__getitem__)


def _merge_consecutive(results):
    regions   = []
    i         = 0
    region_id = 0

    while i < len(results):
        block = results[i]
        if not block.is_suspicious:
            i += 1
            continue

        # FIX: collect ANY consecutive suspicious blocks, regardless of type
        run_blocks = [block]
        j = i + 1
        while j < len(results) and results[j].is_suspicious:
            run_blocks.append(results[j])
            j += 1

        dominant    = _dominant_type(run_blocks)
        avg_entropy = sum(b.entropy for b in run_blocks) / len(run_blocks)
        start_off   = run_blocks[0].block_id * BLOCK_SIZE
        end_off     = run_blocks[-1].block_id * BLOCK_SIZE + BLOCK_SIZE - 1

        regions.append(Region(
            id=region_id, start_offset=start_off, end_offset=end_off,
            size=end_off - start_off + 1, wipe_type=dominant,
            block_count=len(run_blocks), avg_entropy=avg_entropy,
            confidence=0.0, blocks=[b.block_id for b in run_blocks],
        ))
        region_id += 1
        i = j
        
    return regions

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: absorb small NORMAL gaps within a wipe region
# ─────────────────────────────────────────────────────────────────────────────

def _absorb_noise(
    regions: List[Region],
    all_blocks: List[BlockResult],
    id_to_idx: dict,
) -> List[Region]:
    """
    Merge two adjacent same-type regions if the gap between them is
    <= MAX_NORMAL_GAP blocks of NORMAL/UNALLOCATED.

    Rationale: wipe tools skip metadata blocks. A gap of 8 NORMAL blocks
    between two ZERO_WIPE runs is almost certainly one wipe region, not two.
    """
    if len(regions) < 2:
        return regions

    merged = [regions[0]]

    for curr in regions[1:]:
        prev = merged[-1]

        if prev.wipe_type != curr.wipe_type:
            merged.append(curr)
            continue

        # Calculate gap in blocks
        prev_last_block = prev.blocks[-1] if prev.blocks else -999
        curr_first_block = curr.blocks[0] if curr.blocks else 9999
        gap_blocks = curr_first_block - prev_last_block - 1

        if gap_blocks <= MAX_NORMAL_GAP:
            # Absorb the gap and merge into prev
            gap_block_ids = list(range(prev_last_block + 1, curr_first_block))
            merged_blocks = prev.blocks + gap_block_ids + curr.blocks

            all_ids = prev.blocks + curr.blocks
            entropies = [all_blocks[id_to_idx[bid]].entropy for bid in all_ids if bid in id_to_idx]
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

            merged[-1] = Region(
                id           = prev.id,
                start_offset = prev.start_offset,
                end_offset   = curr.end_offset,
                size         = curr.end_offset - prev.start_offset + 1,
                wipe_type    = prev.wipe_type,
                block_count  = len(merged_blocks),
                avg_entropy  = avg_entropy,
                confidence   = 0.0,
                blocks       = merged_blocks,
            )
        else:
            merged.append(curr)

    return merged


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: discard regions below minimum size
# ─────────────────────────────────────────────────────────────────────────────

def _filter_by_size(regions: List[Region]) -> List[Region]:
    """
    Remove regions smaller than MIN_REGION_BLOCKS (64 KB).
    Single isolated blocks and tiny clusters are noise —
    legitimate sparse blocks and filesystem metadata commonly
    appear in small quantities.
    """
    return [r for r in regions if r.block_count >= MIN_REGION_BLOCKS]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: detect multi-pass wipe by alternating band analysis
# ─────────────────────────────────────────────────────────────────────────────

def _detect_multi_pass(
    regions: List[Region],
    all_blocks: List[BlockResult],
    id_to_idx: dict,
) -> List[Region]:
    """
    Detect Gutmann / DoD multi-pass wipes by finding sequences of
    adjacent regions with alternating wipe types.

    e.g. ZERO_WIPE -> FF_WIPE -> ZERO_WIPE -> FF_WIPE -> RANDOM_WIPE
    or   ZERO_WIPE -> RANDOM_WIPE -> ZERO_WIPE

    These patterns are the signature of multi-pass overwrite tools that
    deliberately alternate patterns to defeat magnetic remanence recovery.
    No legitimate use case produces this pattern.

    Requires MULTI_PASS_MIN_BANDS (3) alternating bands to confirm.
    """
    if len(regions) < MULTI_PASS_MIN_BANDS:
        return regions

    result = []
    i      = 0

    while i < len(regions):
        band_group = [regions[i]]
        j          = i + 1

        while j < len(regions):
            prev = band_group[-1]
            curr = regions[j]

            gap_blocks = (curr.start_offset - prev.end_offset - 1) // BLOCK_SIZE
            is_adjacent    = gap_blocks <= MULTI_PASS_GAP_BLOCKS
            is_alternating = (
                curr.wipe_type != prev.wipe_type
                and curr.wipe_type    in STRONG_WIPE_TYPES
                and prev.wipe_type    in STRONG_WIPE_TYPES
            )

            if is_adjacent and is_alternating:
                band_group.append(curr)
                j += 1
            else:
                break

        if len(band_group) >= MULTI_PASS_MIN_BANDS:
            all_block_ids = []
            for r in band_group:
                all_block_ids.extend(r.blocks)

            entropies = [all_blocks[id_to_idx[bid]].entropy for bid in all_block_ids if bid in id_to_idx]
            avg_e = sum(entropies) / len(entropies) if entropies else 0.0

            result.append(Region(
                id           = 0,
                start_offset = band_group[0].start_offset,
                end_offset   = band_group[-1].end_offset,
                size         = band_group[-1].end_offset - band_group[0].start_offset + 1,
                wipe_type    = "MULTI_PASS",
                block_count  = sum(r.block_count for r in band_group),
                avg_entropy  = avg_e,
                confidence   = 0.0,
                blocks       = all_block_ids,
            ))
            i = j
        else:
            result.append(regions[i])
            i += 1

    return result


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: suppress false positives in LIKELY_* and LOW_ENTROPY_SUSPECT regions
# ─────────────────────────────────────────────────────────────────────────────

def _suppress_false_positives(
    regions: List[Region],
    all_blocks: List[BlockResult],
    id_to_idx: dict,
) -> List[Region]:
    """
    Remove isolated LIKELY_* regions with no strong-wipe corroboration
    AND small block count. Large LIKELY_* regions are self-corroborating —
    no legitimate sparse file or filesystem artefact spans thousands of blocks.
    """
    if not regions:
        return regions

    # Self-corroboration threshold: regions this large cannot be filesystem noise
    SELF_CORROBORATE_BLOCKS = 64  # 32 KB — anything larger keeps itself

    strong_block_ids = set()
    for r in regions:
        if r.wipe_type in STRONG_WIPE_TYPES:
            strong_block_ids.update(r.blocks)

    confirmed = []
    for r in regions:
        # Strong wipe types always kept
        if r.wipe_type not in PARTIAL_WIPE_TYPES:
            confirmed.append(r)
            continue

        # Large partial-wipe regions are self-corroborating
        if r.block_count >= SELF_CORROBORATE_BLOCKS:
            confirmed.append(r)
            continue

        # Small partial-wipe regions: require strong-wipe neighbour
        first_block  = r.blocks[0]  if r.blocks else 0
        last_block   = r.blocks[-1] if r.blocks else 0
        window_start = max(0, first_block - ISOLATION_WINDOW)
        window_end   = last_block + ISOLATION_WINDOW

        corroborated = any(
            window_start <= bid <= window_end
            for bid in strong_block_ids
        )
        if corroborated:
            confirmed.append(r)

    return confirmed

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: compute final per-region confidence
# ─────────────────────────────────────────────────────────────────────────────

def _compute_confidence(
    regions: List[Region],
    all_blocks: List[BlockResult],
    id_to_idx: dict,
) -> List[Region]:
    """
    Assign final confidence to each region using:
    - Average block-level confidence from classifier
    - Size bonus (larger regions = more deliberate)
    - Type-specific adjustment
    - Density bonus: high ratio of suspicious to total blocks in region
    """
    for r in regions:
        valid_idxs = [id_to_idx[bid] for bid in r.blocks if bid in id_to_idx]
        block_confs = [all_blocks[idx].confidence for idx in valid_idxs]

        if not block_confs:
            r.confidence = 0.50
            continue

        avg_conf    = sum(block_confs) / len(block_confs)

        # Size bonus: 0.0 at 16 blocks, +0.10 at 512+ blocks
        size_bonus  = min(r.block_count / 512, 1.0) * 0.10

        # Density: what fraction of the block IDs are actually suspicious?
        susp_in_region = sum(1 for idx in valid_idxs if all_blocks[idx].is_suspicious)
        density_ratio  = susp_in_region / len(valid_idxs)
        density_bonus  = (density_ratio - 0.5) * 0.10  # +0.05 at 100% density

        # Type-specific adjustment
        type_adj = {
            "ZERO_WIPE":          +0.00,
            "FF_WIPE":            -0.02,  # slight penalty — legit in hardware images
            "RANDOM_WIPE":        -0.04,  # compressed data risk
            "MULTI_PASS":         -0.08,  # requires band confirmation
            "LIKELY_ZERO_WIPE":   -0.12,  # partial evidence
            "LIKELY_FF_WIPE":     -0.12,
            "LOW_ENTROPY_SUSPECT":-0.15,  # weakest signal
        }.get(r.wipe_type, 0.0)

        r.confidence = round(
            min(max(avg_conf + size_bonus + density_bonus + type_adj, 0.0), 1.0), 3
        )

    return regions

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7: apply partition boundary context
# ─────────────────────────────────────────────────────────────────────────────

def _apply_boundary_context(regions: List[Region], partition_map) -> List[Region]:
    """
    Annotate each region with its boundary context and penalise regions
    that lie entirely beyond every partition's end LBA.

    Why this matters
    ────────────────
    A disk that was only 40% full when wiped will have its trailing 60%
    filled with factory-default zeros (or 0xFF on flash).  Without this
    step the classifier correctly labels those sectors as ZERO_WIPE, but
    the forensic conclusion is wrong — they were never written, not
    deliberately overwritten.

    The penalty is applied only to ZERO_WIPE and FF_WIPE (the two types
    whose natural unwritten state is indistinguishable from a deliberate
    single-pass fill).  RANDOM_WIPE and MULTI_PASS beyond the boundary
    still receive a moderate penalty but are not dismissed — a random
    pattern genuinely cannot appear naturally in unwritten space and
    therefore carries forensic weight regardless of partition position.

    Confidence after penalty is floored at 0.10 (never fully dismissed)
    because: (a) the partition table could itself be damaged or misleading;
    (b) some enterprise wipers deliberately overwrite beyond partition
    boundaries as part of a thorough sanitisation procedure.
    """
    for r in regions:
        ctx = partition_map.classify_region(r.start_offset, r.end_offset)
        r.boundary_context = ctx.value   # store the string form

        if ctx.value == "BEYOND_BOUNDARY":
            if r.wipe_type in ("ZERO_WIPE", "FF_WIPE"):
                # These look identical to unwritten sectors — strong penalty
                r.confidence = round(max(r.confidence - BEYOND_BOUNDARY_PENALTY, 0.10), 3)
            elif r.wipe_type in ("LIKELY_ZERO_WIPE", "LIKELY_FF_WIPE",
                                  "LOW_ENTROPY_SUSPECT"):
                # Partial / suspect types beyond boundary — very likely noise
                r.confidence = round(max(r.confidence - BEYOND_BOUNDARY_PENALTY * 1.3, 0.10), 3)
            else:
                # RANDOM_WIPE / MULTI_PASS beyond boundary — still suspicious,
                # but moderate penalty for location
                r.confidence = round(max(r.confidence - BEYOND_BOUNDARY_PENALTY * 0.5, 0.10), 3)

        elif ctx.value == "INSIDE_PARTITION":
            # Small confidence boost for being inside a known partition —
            # this was formatted space, so a wipe pattern here is meaningful.
            boost = 0.04
            r.confidence = round(min(r.confidence + boost, 1.0), 3)

    return regions
