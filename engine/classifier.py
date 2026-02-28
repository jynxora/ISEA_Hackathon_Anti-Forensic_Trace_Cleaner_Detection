"""
classifier.py
─────────────
Analyses a single raw 4 KB block and classifies it as one of:

    ZERO_WIPE     — 0x00 fill (single-pass zero wipe)
    FF_WIPE       — 0xFF fill (single-pass FF wipe)
    RANDOM_WIPE   — pseudorandom overwrite (entropy ≈ 8.0, flat distribution)
    MULTI_PASS    — alternating structured wipe (Gutmann / DoD style)
    NORMAL        — legitimate data (text, binary, structured)
    UNALLOCATED   — genuine unallocated / uninitialised space (ambiguous zeros)

Detection logic:
    1.  Shannon entropy          — quantifies byte randomness
    2.  Byte frequency histogram — identifies dominant byte values
    3.  Byte variance            — distinguishes wipe patterns from structured data
    4.  Uniformity score         — flat distribution = random wipe
    5.  False-positive guard     — compressed/encrypted legit data also has high
                                   entropy; we use distribution flatness +
                                   context flags to reduce misclassification

Usage:
    from engine.classifier import classify_block, BlockResult
"""

import math
from collections import Counter
from dataclasses import dataclass


# ── Thresholds (tunable) ──────────────────────────────────────────────────────

ENTROPY_ZERO_MAX    = 0.20   # entropy of a zero-filled block
ENTROPY_FF_MAX      = 0.20   # entropy of an FF-filled block
ENTROPY_RANDOM_MIN  = 7.60   # random wipe starts here
ENTROPY_NORMAL_MAX  = 7.50   # legitimate data rarely exceeds this

DOMINANCE_MIN       = 0.90   # ≥90% of block must be one byte for ZERO/FF
UNIFORMITY_THRESH   = 0.015  # max allowed std-dev of byte freq for RANDOM_WIPE
                              # (truly random → each byte ≈ 1/256 = 0.00390)
MULTI_PASS_ENTROPY_LO = 3.5  # multi-pass blocks oscillate across this range
MULTI_PASS_ENTROPY_HI = 6.5


# ── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class BlockResult:
    block_id:    int
    offset:      int
    wipe_type:   str    # ZERO_WIPE | FF_WIPE | RANDOM_WIPE | MULTI_PASS | NORMAL | UNALLOCATED
    entropy:     float
    confidence:  float  # 0.0 – 1.0
    dominant_byte: int  # most frequent byte value (0-255)
    dominant_pct:  float  # fraction of block occupied by dominant_byte
    is_suspicious: bool   # True for anything that is NOT NORMAL


# ── Core entropy function ─────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits per byte.
    Range: 0.0 (all identical bytes) → 8.0 (perfectly random bytes).
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 6)


def byte_frequency(data: bytes) -> list[float]:
    """
    Returns a 256-element list where index = byte value,
    value = fraction of total bytes. Sum = 1.0.
    """
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return [c / length for c in counts]


def distribution_uniformity(freq: list[float]) -> float:
    """
    Measure how flat the byte frequency distribution is.
    A truly random block → each byte ≈ 1/256 ≈ 0.00390.
    Returns the standard deviation; lower = more uniform = more random.
    """
    mean = 1.0 / 256
    variance = sum((f - mean) ** 2 for f in freq) / 256
    return math.sqrt(variance)


# ── Main classifier ───────────────────────────────────────────────────────────

def classify_block(block_id: int, offset: int, data: bytes) -> BlockResult:
    """
    Classify a single block of raw bytes.

    Returns a BlockResult with wipe_type and confidence.
    """

    # ── Empty / padding block ─────────────────────────────────────────────────
    if len(data) == 0:
        return BlockResult(
            block_id=block_id, offset=offset,
            wipe_type="NORMAL", entropy=0.0, confidence=1.0,
            dominant_byte=0, dominant_pct=1.0, is_suspicious=False,
        )

    entropy = shannon_entropy(data)
    freq    = byte_frequency(data)

    dominant_byte = int(max(range(256), key=lambda i: freq[i]))
    dominant_pct  = freq[dominant_byte]

    # ── 1. ZERO WIPE — 0x00 dominance + near-zero entropy ────────────────────
    if dominant_byte == 0x00 and dominant_pct >= DOMINANCE_MIN and entropy <= ENTROPY_ZERO_MAX:
        confidence = _zero_ff_confidence(dominant_pct, entropy)
        return BlockResult(
            block_id=block_id, offset=offset,
            wipe_type="ZERO_WIPE", entropy=entropy, confidence=confidence,
            dominant_byte=dominant_byte, dominant_pct=dominant_pct,
            is_suspicious=True,
        )

    # ── 2. FF WIPE — 0xFF dominance + near-zero entropy ──────────────────────
    if dominant_byte == 0xFF and dominant_pct >= DOMINANCE_MIN and entropy <= ENTROPY_FF_MAX:
        confidence = _zero_ff_confidence(dominant_pct, entropy)
        return BlockResult(
            block_id=block_id, offset=offset,
            wipe_type="FF_WIPE", entropy=entropy, confidence=confidence,
            dominant_byte=dominant_byte, dominant_pct=dominant_pct,
            is_suspicious=True,
        )

    # ── 3. RANDOM WIPE — high entropy + flat distribution ────────────────────
    #    False-positive guard: compressed data also has high entropy BUT
    #    has non-uniform distribution (certain byte ranges dominate).
    if entropy >= ENTROPY_RANDOM_MIN:
        uniformity = distribution_uniformity(freq)
        if uniformity <= UNIFORMITY_THRESH:
            # Truly flat distribution → pseudorandom overwrite
            confidence = _random_confidence(entropy, uniformity)
            return BlockResult(
                block_id=block_id, offset=offset,
                wipe_type="RANDOM_WIPE", entropy=entropy, confidence=confidence,
                dominant_byte=dominant_byte, dominant_pct=dominant_pct,
                is_suspicious=True,
            )
        else:
            # High entropy but non-flat → likely compressed/encrypted legit data
            # Flag as NORMAL — this is the false-positive guard
            return BlockResult(
                block_id=block_id, offset=offset,
                wipe_type="NORMAL", entropy=entropy, confidence=0.75,
                dominant_byte=dominant_byte, dominant_pct=dominant_pct,
                is_suspicious=False,
            )

    # ── 4. MULTI-PASS — moderate entropy in structured oscillating range ──────
    #    Gutmann / DoD wipes leave bands of alternating low/mid entropy.
    #    We flag mid-range entropy blocks with very low byte variance as
    #    potential multi-pass artefacts; final determination done by
    #    aggregator.py (consecutive band analysis).
    if MULTI_PASS_ENTROPY_LO <= entropy <= MULTI_PASS_ENTROPY_HI:
        uniformity = distribution_uniformity(freq)
        # Multi-pass shows structured regularity — not too random, not too uniform
        if uniformity < 0.008:
            return BlockResult(
                block_id=block_id, offset=offset,
                wipe_type="MULTI_PASS", entropy=entropy, confidence=0.65,
                dominant_byte=dominant_byte, dominant_pct=dominant_pct,
                is_suspicious=True,
            )

    # ── 5. UNALLOCATED — zero-dominant but not a clean wipe ──────────────────
    #    Genuine unallocated sectors on freshly formatted drives are also
    #    zero-filled, but with lower dominance and occasional random bytes.
    #    Differentiated from ZERO_WIPE by lower dominance threshold.
    if dominant_byte == 0x00 and 0.70 <= dominant_pct < DOMINANCE_MIN:
        return BlockResult(
            block_id=block_id, offset=offset,
            wipe_type="UNALLOCATED", entropy=entropy, confidence=0.55,
            dominant_byte=dominant_byte, dominant_pct=dominant_pct,
            is_suspicious=False,   # ambiguous — not conclusive evidence of wiping
        )

    # ── 6. NORMAL — legitimate data ───────────────────────────────────────────
    return BlockResult(
        block_id=block_id, offset=offset,
        wipe_type="NORMAL", entropy=entropy, confidence=0.90,
        dominant_byte=dominant_byte, dominant_pct=dominant_pct,
        is_suspicious=False,
    )


# ── Confidence helpers ────────────────────────────────────────────────────────

def _zero_ff_confidence(dominant_pct: float, entropy: float) -> float:
    """Higher dominance + lower entropy = higher confidence."""
    dom_score = (dominant_pct - 0.90) / 0.10        # 0.0 → 1.0 as pct goes 90→100%
    ent_score = 1.0 - min(entropy / 0.5, 1.0)       # 0.0 → 1.0 as entropy goes 0.5→0
    return round(min(0.50 + dom_score * 0.30 + ent_score * 0.20, 1.0), 3)


def _random_confidence(entropy: float, uniformity: float) -> float:
    """Higher entropy + flatter distribution = higher confidence."""
    ent_score  = (entropy - ENTROPY_RANDOM_MIN) / (8.0 - ENTROPY_RANDOM_MIN)
    unif_score = 1.0 - min(uniformity / UNIFORMITY_THRESH, 1.0)
    return round(min(0.60 + ent_score * 0.25 + unif_score * 0.15, 1.0), 3)
