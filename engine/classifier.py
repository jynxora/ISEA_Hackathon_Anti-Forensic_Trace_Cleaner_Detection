"""
classifier.py
─────────────
Per-block wipe pattern classifier.

Classification labels:
    ZERO_WIPE            clean 0x00 fill, >90% dominance (deliberate single-pass)
    LIKELY_ZERO_WIPE     partial 0x00 overwrite, 60-90% dominance
    FF_WIPE              clean 0xFF fill, >90% dominance
    LIKELY_FF_WIPE       partial 0xFF overwrite, 60-90% dominance
    RANDOM_WIPE          pseudorandom overwrite, entropy >= 7.60, flat byte distribution
    MULTI_PASS           structured mid-entropy block, candidate for band detection
    LOW_ENTROPY_SUSPECT  structured low entropy, not zero/FF — pattern wipe candidate
    UNALLOCATED          genuine uninitialised space (never written, not wiped)
    NORMAL               legitimate data: text, binary, compressed, encrypted, FS structures

False-positive suppression rationale:
    HIGH ENTROPY != RANDOM WIPE
        ZIP, PNG, MP4, encrypted volumes all produce entropy >= 7.5.
        Distinguishing signal: DISTRIBUTION FLATNESS.
        Wipe tools (shred, dd, sdelete) use CSPRNG -> flat distribution.
        Compressed/encrypted data has structural byte-range bias -> non-flat.

    LOW ENTROPY != ZERO WIPE
        NTFS MFT entries, FAT tables, sparse file tails, null-padded strings
        all produce low-entropy 0x00-dominant blocks.
        Distinguishing signal: dominance threshold + non-zero byte entropy.
        Sparse/structural blocks have patterned non-zero bytes; wiped blocks
        have random scatter in their non-zero portion.

    MID ENTROPY != MULTI-PASS
        Executable code, DB records, log files sit in 3.5-6.5 entropy range.
        Multi-pass is only a candidate here; aggregator.py confirms by
        detecting alternating entropy bands across consecutive blocks.

Architecture contract:
    This module classifies ONE block at a time.
    No cross-block context. No region logic. No scoring.
    All of that lives in aggregator.py and scorer.py.
"""

import math
from collections import Counter
from dataclasses import dataclass

try:
    import numpy as np
    _NUMPY = True
except ImportError:
    _NUMPY = False


# ─────────────────────────────────────────────────────────────────────────────
# THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────

# Fill detection (zero / FF)
ZERO_FF_STRONG_MIN     = 0.90   # >90% single byte = strong wipe
ZERO_FF_PARTIAL_MIN    = 0.60   # 60-90% = partial / interrupted wipe
ENTROPY_FILL_MAX       = 0.20   # max entropy for a clean fill block

# Random wipe detection
ENTROPY_RANDOM_MIN     = 7.60   # from team's entropy_calc + empirical testing
UNIFORMITY_WIPE_MAX    = 0.0140 # std-dev ceiling for genuine CSPRNG output
                                 # legitimate compressed data: 0.018 - 0.060+

# Low entropy suspect (pattern wipe)
ENTROPY_LOW_MIN        = 0.21   # above fill threshold
ENTROPY_LOW_MAX        = 1.50   # from team's classifier.py
SUSPECT_DOMINANT_MAX   = 0.85   # if >85% one byte -> unallocated, not pattern wipe

# Multi-pass candidate range
MULTI_PASS_LO          = 3.5
MULTI_PASS_HI          = 6.5
MULTI_PASS_UNIF_MAX    = 0.0080  # anomalously flat for this entropy range

# Known compressed/encrypted format magic bytes
# Presence in a block's first 16 bytes = strong legit-data signal
COMPRESSED_MAGIC = frozenset([
    0x50, 0x4B,              # ZIP (PK)
    0x1F, 0x8B,              # GZIP
    0xFF, 0xD8,              # JPEG
    0x89, 0x50, 0x4E, 0x47, # PNG
    0x25, 0x50, 0x44, 0x46, # PDF
    0x7F, 0x45, 0x4C, 0x46, # ELF
    0x4D, 0x5A,              # PE/MZ executable
    0x52, 0x61, 0x72, 0x21, # RAR
    0xFD, 0x37, 0x7A, 0x58, # XZ
    0x42, 0x5A, 0x68,        # BZ2
])


# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BlockResult:
    block_id:      int
    offset:        int
    wipe_type:     str    # label from list above
    entropy:       float
    confidence:    float  # 0.0 - 1.0
    dominant_byte: int    # most frequent byte value (0-255)
    dominant_pct:  float  # fraction of block occupied by dominant_byte
    is_suspicious: bool   # True = warrants forensic attention
    zero_ratio:    float  # fraction of 0x00 bytes (for aggregator use)
    ff_ratio:      float  # fraction of 0xFF bytes (for aggregator use)


# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL FUNCTIONS  (from team's files, extended)
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy. 0.0 = uniform fill. 8.0 = perfect random."""
    if not data:
        return 0.0
    if _NUMPY:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        freq = counts[counts > 0] / len(data)
        return round(float(-np.sum(freq * np.log2(freq))), 6)
    counts = Counter(data)
    length = len(data)
    h = 0.0
    for count in counts.values():
        p = count / length
        h -= p * math.log2(p)
    return round(h, 6)


def byte_frequency(data: bytes) -> list:
    """256-element list: index = byte value, value = fraction of total bytes."""
    length = len(data)
    if _NUMPY:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        return (counts / length).tolist()
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return [c / length for c in counts]


def distribution_uniformity(freq: list) -> float:
    """
    Std-dev of byte frequency distribution.
    Lower = flatter = more consistent with CSPRNG output.
    Genuine random wipe:  ~0.002 - 0.006
    Compressed/encrypted: ~0.018 - 0.060
    """
    mean = 1.0 / 256
    if _NUMPY:
        arr = np.asarray(freq)
        return float(np.sqrt(np.mean((arr - mean) ** 2)))
    variance = sum((f - mean) ** 2 for f in freq) / 256
    return math.sqrt(variance)


def detect_patterns(data: bytes) -> tuple:
    """
    Returns (zero_ratio, ff_ratio).
    Direct equivalent of team's pattern_detector.detect_patterns().
    """
    if _NUMPY:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        n = len(data)
        return round(float(counts[0] / n), 4), round(float(counts[255] / n), 4)
    freq   = Counter(data)
    length = len(data)
    return (
        round(freq.get(0x00, 0) / length, 4),
        round(freq.get(0xFF, 0) / length, 4),
    )


def _stats_from_data(data: bytes):
    """
    Single-pass computation of all stats needed by classify_block.
    Returns (entropy, freq_list, zero_ratio, ff_ratio, dom_byte, dom_pct)
    Avoids the 3 separate Counter/loop passes in the original.
    """
    if _NUMPY:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        n = len(data)
        freq = counts / n
        nz = freq[freq > 0]
        entropy = float(-np.sum(nz * np.log2(nz))) if len(nz) else 0.0
        zero_ratio = float(counts[0] / n)
        ff_ratio   = float(counts[255] / n)
        dom_byte   = int(np.argmax(counts))
        dom_pct    = float(freq[dom_byte])
        return entropy, freq.tolist(), zero_ratio, ff_ratio, dom_byte, dom_pct
    # Pure-Python fallback
    length = len(data)
    raw_counts = [0] * 256
    for b in data:
        raw_counts[b] += 1
    freq = [c / length for c in raw_counts]
    dom_byte = max(range(256), key=lambda i: freq[i])
    dom_pct  = freq[dom_byte]
    h = 0.0
    for c in raw_counts:
        if c:
            p = c / length
            h -= p * math.log2(p)
    entropy    = round(h, 6)
    zero_ratio = round(raw_counts[0] / length, 4)
    ff_ratio   = round(raw_counts[255] / length, 4)
    return entropy, freq, zero_ratio, ff_ratio, dom_byte, dom_pct


def has_legitimate_structure(data: bytes, freq: list) -> bool:
    """
    Heuristic checks for known legitimate high-entropy data.
    Returns True if the block looks like real compressed/encrypted content
    rather than a wipe pattern. Used as second-stage guard for RANDOM_WIPE.

    Three checks (any one being True = treat as legitimate):

    1. Format magic bytes in first 16 bytes of block
    2. Byte-range clustering: legit compressed data over-represents certain
       32-byte value buckets; pure random doesn't
    3. Printable ASCII run >= 64 bytes: text/log data embedded in binary
    """
    # 1. Magic bytes
    if set(data[:16]) & COMPRESSED_MAGIC:
        return True

    # 2. Byte-range clustering
    # Divide 0x00-0xFF into 8 buckets of 32 values each.
    # If any bucket contains >2.8x the expected uniform share -> clustered.
    expected_per_bucket = 32.0 / 256  # = 0.125
    for i in range(8):
        bucket_sum = sum(freq[i * 32:(i + 1) * 32])
        if bucket_sum > expected_per_bucket * 2.8:
            return True

    # 3. Printable ASCII run
    run = 0
    for b in data:
        if 0x20 <= b <= 0x7E:
            run += 1
            if run >= 64:
                return True
        else:
            run = 0

    return False
    # 4. Compressed container stream detection
    # Pure CSPRNG wipe tools produce TRULY flat distributions.
    # Real compressed data (E01, zip streams, encrypted volumes) has
    # subtle byte-range bias even when entropy is near-maximal.
    # Check: if the top-8 most frequent bytes account for >12% of data
    # (vs the expected 8/256 = 3.1% for pure random), it's structured.
    
    sorted_freq = sorted(freq, reverse=True)
    top8_sum = sum(sorted_freq[:8])
    if top8_sum > 0.055:   # pure random ≈ 0.031, compressed ≈ 0.060–0.120
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

def classify_block(block_id: int, offset: int, data: bytes) -> BlockResult:
    """
    Classify a single raw block.

    Decision tree (evaluated in strict priority order):
        1.  Empty block                  -> NORMAL
        2.  Strong zero fill (>90%)      -> ZERO_WIPE
        3.  Strong FF fill (>90%)        -> FF_WIPE
        4.  Partial zero (60-90%)        -> LIKELY_ZERO_WIPE  or NORMAL
        5.  Partial FF (60-90%)          -> LIKELY_FF_WIPE    or NORMAL
        6.  High entropy + flat dist     -> RANDOM_WIPE       (+ legit guard)
        7.  High entropy + non-flat      -> NORMAL            (compressed data)
        8.  Suspicious low entropy       -> LOW_ENTROPY_SUSPECT or NORMAL
        9.  Mid entropy + flat dist      -> MULTI_PASS candidate
       10.  Ambiguous zero dominance     -> UNALLOCATED
       11.  Everything else              -> NORMAL
    """

    if not data:
        return _result(block_id, offset, "NORMAL", 0.0, 1.0, 0, 1.0, False, 0.0, 0.0)

    # Single-pass: compute entropy, freq, zero/ff ratios, dominant byte all at once
    entropy, freq, zero_ratio, ff_ratio, dominant_byte, dominant_pct = _stats_from_data(data)

    # ── 1. STRONG ZERO WIPE ───────────────────────────────────────────────────
    # >90% 0x00, near-zero entropy.
    # Legit exceptions: sparse file tails, unwritten MFT extensions.
    # These appear as isolated blocks; aggregator filters by region length.
    if zero_ratio >= ZERO_FF_STRONG_MIN and entropy <= ENTROPY_FILL_MAX:
        conf = _fill_conf(zero_ratio, entropy)
        return _result(block_id, offset, "ZERO_WIPE", entropy, conf,
                       dominant_byte, dominant_pct, True, zero_ratio, ff_ratio)

    # ── 2. STRONG FF WIPE ────────────────────────────────────────────────────
    # >90% 0xFF, near-zero entropy.
    # Legit exceptions: flash memory erase state, some BIOS/firmware regions.
    # Confidence slightly penalised: FF blocks appear in legit hardware images.
    if ff_ratio >= ZERO_FF_STRONG_MIN and entropy <= ENTROPY_FILL_MAX:
        conf = _fill_conf(ff_ratio, entropy) * 0.96
        return _result(block_id, offset, "FF_WIPE", entropy, conf,
                       dominant_byte, dominant_pct, True, zero_ratio, ff_ratio)

    # ── 3. PARTIAL ZERO WIPE ─────────────────────────────────────────────────
    # 60-90% 0x00. Forensically important: real wipers leave partial overwrites
    # at boundaries, or are interrupted. Also: wiped blocks on partially-used
    # clusters where some data remains.
    #
    # Key legit-data guard: null-padded strings and NTFS allocation units
    # have structured (low-entropy) non-zero bytes. Partial wipes have
    # random scatter in their non-zero portion (higher non-zero entropy).
    if ZERO_FF_PARTIAL_MIN <= zero_ratio < ZERO_FF_STRONG_MIN:
        non_zero = bytes(b for b in data if b != 0x00)
        if non_zero and shannon_entropy(non_zero) > 3.5:
            # Varied non-zero bytes = looks like partial overwrite, not padding
            conf = _partial_conf(zero_ratio)
            return _result(block_id, offset, "LIKELY_ZERO_WIPE", entropy, conf,
                           dominant_byte, dominant_pct, True, zero_ratio, ff_ratio)
        # Low-entropy non-zero bytes = structured padding / filesystem metadata
        return _result(block_id, offset, "NORMAL", entropy, 0.82,
                       dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)

    # ── 4. PARTIAL FF WIPE ───────────────────────────────────────────────────
    if ZERO_FF_PARTIAL_MIN <= ff_ratio < ZERO_FF_STRONG_MIN:
        non_ff = bytes(b for b in data if b != 0xFF)
        if non_ff and shannon_entropy(non_ff) > 3.5:
            conf = _partial_conf(ff_ratio)
            return _result(block_id, offset, "LIKELY_FF_WIPE", entropy, conf,
                           dominant_byte, dominant_pct, True, zero_ratio, ff_ratio)
        return _result(block_id, offset, "NORMAL", entropy, 0.82,
                       dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)

    # ── 5. RANDOM WIPE (high entropy) ────────────────────────────────────────
    # The hardest classification. Two-stage guard:
    #   Stage 1: uniformity threshold (fast)
    #   Stage 2: structural signature scan (catches edge cases)
    if entropy >= ENTROPY_RANDOM_MIN:
        uniformity = distribution_uniformity(freq)

        if uniformity <= UNIFORMITY_WIPE_MAX:
            # Flat distribution — run structural check for edge cases
            if has_legitimate_structure(data, freq):
                return _result(block_id, offset, "NORMAL", entropy, 0.72,
                               dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)
            conf = _random_conf(entropy, uniformity)
            return _result(block_id, offset, "RANDOM_WIPE", entropy, conf,
                           dominant_byte, dominant_pct, True, zero_ratio, ff_ratio)
        else:
            # Non-flat high entropy = compressed / encrypted legitimate data
            return _result(block_id, offset, "NORMAL", entropy, 0.87,
                           dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)

    # ── 6. LOW ENTROPY SUSPECT ────────────────────────────────────────────────
    # Entropy 0.21-1.50, no single-byte dominance.
    # Pattern-based wipe tools (Gutmann passes: 0xAA/0x55/0x92 etc.) leave
    # structured low-entropy blocks that aren't simple fills.
    # Legit guard: if one byte dominates >85%, it's sparse data, not a pattern.
    if ENTROPY_LOW_MIN < entropy <= ENTROPY_LOW_MAX:
        if dominant_pct <= SUSPECT_DOMINANT_MAX:
            uniformity = distribution_uniformity(freq)
            if uniformity < 0.020:
                # Anomalously structured for this entropy range
                return _result(block_id, offset, "LOW_ENTROPY_SUSPECT", entropy,
                               0.52, dominant_byte, dominant_pct, True,
                               zero_ratio, ff_ratio)
        # Single byte dominates or distribution is normal — legit data
        return _result(block_id, offset, "NORMAL", entropy, 0.82,
                       dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)

    # ── 7. MULTI-PASS CANDIDATE ───────────────────────────────────────────────
    # Mid-range entropy + anomalously flat distribution.
    # Single block cannot confirm multi-pass — aggregator.py does band analysis.
    # Legit guard: executables and DB pages have clustered distributions;
    # multi-pass patterns are anomalously uniform for this entropy range.
    if MULTI_PASS_LO <= entropy <= MULTI_PASS_HI:
        uniformity = distribution_uniformity(freq)
        if uniformity < MULTI_PASS_UNIF_MAX:
            return _result(block_id, offset, "MULTI_PASS", entropy, 0.52,
                           dominant_byte, dominant_pct, True, zero_ratio, ff_ratio)

    # ── 8. GENUINE UNALLOCATED ────────────────────────────────────────────────
    # Zero-dominant (70-90%) but not clean enough for ZERO_WIPE.
    # Typical of uninitialised sectors on freshly formatted drives.
    # NOT a wipe indicator — marked non-suspicious.
    if dominant_byte == 0x00 and 0.70 <= dominant_pct < ZERO_FF_STRONG_MIN:
        return _result(block_id, offset, "UNALLOCATED", entropy, 0.48,
                       dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)

    # ── 9. NORMAL ─────────────────────────────────────────────────────────────
    return _result(block_id, offset, "NORMAL", entropy, 0.90,
                   dominant_byte, dominant_pct, False, zero_ratio, ff_ratio)


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE CALCULATORS
# ─────────────────────────────────────────────────────────────────────────────

def _fill_conf(dominant_ratio: float, entropy: float) -> float:
    """Strong fill confidence: higher dominance + lower entropy = more certain."""
    dom_score = (dominant_ratio - ZERO_FF_STRONG_MIN) / (1.0 - ZERO_FF_STRONG_MIN)
    ent_score = 1.0 - min(entropy / 0.5, 1.0)
    return round(min(0.55 + dom_score * 0.28 + ent_score * 0.17, 1.0), 3)


def _partial_conf(dominant_ratio: float) -> float:
    """Partial fill confidence: scales 0.40 -> 0.72 across 60-90% dominance."""
    scaled = (dominant_ratio - ZERO_FF_PARTIAL_MIN) / (ZERO_FF_STRONG_MIN - ZERO_FF_PARTIAL_MIN)
    return round(0.40 + scaled * 0.32, 3)


def _random_conf(entropy: float, uniformity: float) -> float:
    """Random wipe confidence: higher entropy + flatter = more certain. Cap at 0.92."""
    ent_score  = (entropy - ENTROPY_RANDOM_MIN) / (8.0 - ENTROPY_RANDOM_MIN)
    unif_score = 1.0 - min(uniformity / UNIFORMITY_WIPE_MAX, 1.0)
    return round(min(0.58 + ent_score * 0.22 + unif_score * 0.12, 0.92), 3)


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def _result(
    block_id: int, offset: int, wipe_type: str,
    entropy: float, confidence: float,
    dominant_byte: int, dominant_pct: float,
    is_suspicious: bool,
    zero_ratio: float, ff_ratio: float,
) -> BlockResult:
    return BlockResult(
        block_id      = block_id,
        offset        = offset,
        wipe_type     = wipe_type,
        entropy       = entropy,
        confidence    = confidence,
        dominant_byte = dominant_byte,
        dominant_pct  = dominant_pct,
        is_suspicious = is_suspicious,
        zero_ratio    = zero_ratio,
        ff_ratio      = ff_ratio,
    )
