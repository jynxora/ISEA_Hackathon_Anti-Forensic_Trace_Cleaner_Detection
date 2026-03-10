"""
scanner_v2.py
─────────────
Optimised scan orchestrator. Drop-in replacement for scanner.py.

FIXES vs v1:
  ① ML stall eliminated — vectorised batch_classify_raw() replaces
    serial seek+classify loop. All feature extraction in one pass,
    all predictions in single matrix operation.
  ② Real-time progress — phase names written to shared scan_state dict
    on every _emit() call, immediately visible to FastAPI poll endpoint.
  ③ Event loop unblocked — run_scan() is pure synchronous Python;
    backend_integrate.py runs it in asyncio.get_event_loop().run_in_executor()
    so the FastAPI event loop never blocks and /scan/status always responds.

PERFORMANCE TARGET:
  1.5 GB image, 8-core machine:
    Phase CLASSIFYING: ~30s  (7 parallel workers)
    Phase ML:          ~5s   (vectorised, 50k blocks max)
    Phase AGGREGATING: ~2s
    Total wall clock:  ~45s
"""

import multiprocessing
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

from engine.reader     import BlockReader, BLOCK_SIZE
from engine.classifier import classify_block, BlockResult
from engine.aggregator import aggregate
from engine.scorer     import compute_score
from engine.writer     import write_results
from engine.ml_classifier import get_classifier, MLResult
from engine.custody    import CustodyChain
from engine.report_generator import generate_report
from engine.partition_map import parse_partition_map


# ─────────────────────────────────────────────────────────────────────────────
# PHASE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

class ScanPhase:
    HASHING     = "hashing"
    CLASSIFYING = "classifying"
    ML          = "ml_analysis"
    AGGREGATING = "aggregating"
    SCORING     = "scoring"
    REPORTING   = "reporting"
    WRITING     = "writing"
    DONE        = "done"

# Maps phase → (lo%, hi%) of the overall 0-100 progress bar
PHASE_RANGES = {
    ScanPhase.HASHING:     (0,   5),
    ScanPhase.CLASSIFYING: (5,  70),
    ScanPhase.ML:          (70, 82),
    ScanPhase.AGGREGATING: (82, 90),
    ScanPhase.SCORING:     (90, 93),
    ScanPhase.REPORTING:   (93, 97),
    ScanPhase.WRITING:     (97, 100),
}

def _phase_pct(phase: str, within: float = 1.0) -> int:
    lo, hi = PHASE_RANGES.get(phase, (0, 100))
    return min(int(lo + (hi - lo) * within), 99)


# ─────────────────────────────────────────────────────────────────────────────
# PARALLEL WORKER (child process — must be picklable, no lambdas)
# ─────────────────────────────────────────────────────────────────────────────

def _classify_chunk(args):
    """
    Worker function for ProcessPoolExecutor.
    Returns list of plain tuples (not dataclasses) to minimise pickle cost.
    """
    image_path, start_block, end_block = args
    reader = BlockReader(image_path, start_block=start_block, end_block=end_block)
    out = []
    for block in reader:
        r = classify_block(block.id, block.offset, block.data)
        out.append((
            r.block_id, r.offset, r.wipe_type, r.entropy,
            r.confidence, r.dominant_byte, r.dominant_pct,
            r.is_suspicious, r.zero_ratio, r.ff_ratio,
        ))
    return out


def _tuple_to_br(t) -> BlockResult:
    return BlockResult(
        block_id=t[0], offset=t[1], wipe_type=t[2], entropy=t[3],
        confidence=t[4], dominant_byte=t[5], dominant_pct=t[6],
        is_suspicious=t[7], zero_ratio=t[8], ff_ratio=t[9],
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT  (synchronous — called from run_in_executor in backend)
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(
    image_path:  str | Path,
    session_id:  str,
    sha256:      str,
    output_dir:  str | Path = Path("uploads"),
    progress_cb: Optional[Callable[[int, int], None]] = None,
    examiner:    str = "WipeTrace Analysis System",
    n_workers:   Optional[int] = None,
    # Extra: shared state dict reference for phase updates
    # If provided, _emit() also writes phase directly to this dict
    scan_state_ref: Optional[dict] = None,
) -> Path:
    """
    Full wipe detection pipeline.

    progress_cb(overall_pct: int, total: int=100) is called frequently.
    The backend reads overall_pct directly from scan_state["progress"].

    IMPORTANT: This function is SYNCHRONOUS. The FastAPI backend must run it
    via asyncio.get_event_loop().run_in_executor(None, ...) so the event loop
    is never blocked and /scan/status polls always get a response.
    """
    t0 = time.time()
    image_path = Path(image_path)
    output_dir = Path(output_dir)

    def _emit(phase: str, within: float = 1.0, note: str = ""):
        pct = _phase_pct(phase, within)
        # Update shared state if provided (for real-time backend visibility)
        if scan_state_ref is not None:
            scan_state_ref["progress"] = pct
            scan_state_ref["phase"] = phase
        if progress_cb:
            progress_cb(pct, 100)
        print(f"[scanner_v2] [{pct:3d}%] {phase.upper()}"
              + (f" {within*100:.0f}%" if within < 1.0 else "")
              + (f" — {note}" if note else ""))

    # ── Custody chain ─────────────────────────────────────────────────────────
    custody = CustodyChain(session_id=session_id, examiner=examiner,
                            output_dir=output_dir)

    # ── Reader ────────────────────────────────────────────────────────────────
    _emit(ScanPhase.HASHING, 0.5, "reading image header")
    reader = BlockReader(image_path)
    total  = reader.total_blocks

    print(f"[scanner_v2] Image: {image_path.name}")
    print(f"[scanner_v2] Size:  {reader.image_size / (1024**3):.2f} GB")
    print(f"[scanner_v2] Blocks: {total:,}")

    custody.record_acquisition(
        filename=image_path.name, sha256=sha256,
        size_bytes=reader.image_size,
    )
    custody.record_hash_initial(sha256=sha256, filename=image_path.name)
    custody.record_scan_start(image_path=str(image_path),
                               total_blocks=total, image_size=reader.image_size)
    _emit(ScanPhase.HASHING, 1.0, "hashing complete")

    # ── Partition map ─────────────────────────────────────────────────────────
    # Parse MBR/GPT partition table to establish partition boundaries.
    # This allows the aggregator and scorer to distinguish "never-written"
    # sectors beyond the last partition from genuinely wiped sectors inside
    # a formerly active partition.
    partition_map = parse_partition_map(image_path)
    if partition_map.scheme != "UNKNOWN":
        print(f"[scanner_v2] Partition scheme: {partition_map.scheme}, "
              f"{len(partition_map.partitions)} partition(s), "
              f"last used LBA: {partition_map.last_used_lba:,}")
        for p in partition_map.partitions:
            print(f"  [{p.index}] {p.type_name}  "
                  f"LBA {p.start_lba:,}–{p.end_lba:,}  "
                  f"({p.sector_count * 512 / (1024**3):.2f} GB)")
    else:
        print(f"[scanner_v2] Partition table: UNKNOWN "
              f"({'; '.join(partition_map.parse_errors[:2]) if partition_map.parse_errors else 'no errors'})")

    # ── Parallel classification ───────────────────────────────────────────────
    _emit(ScanPhase.CLASSIFYING, 0.0, "starting parallel scan")

    if n_workers is None:
        n_workers = max(1, (multiprocessing.cpu_count() or 2) - 1)

    block_results: list = []

    USE_PARALLEL = total > 10_000 and n_workers > 1

    if USE_PARALLEL:
        chunk_size = max(2000, total // (n_workers * 4))
        chunks = []
        s = 0
        while s < total:
            e = min(s + chunk_size - 1, total - 1)
            chunks.append((str(image_path), s, e))
            s = e + 1

        print(f"[scanner_v2] Parallel: {n_workers} workers, {len(chunks)} chunks")
        completed = 0
        chunk_results = [None] * len(chunks)

        with ProcessPoolExecutor(max_workers=n_workers) as pool:
            futures = {pool.submit(_classify_chunk, c): i for i, c in enumerate(chunks)}
            for future in as_completed(futures):
                idx = futures[future]
                tuples = future.result()
                chunk_results[idx] = tuples
                completed += len(tuples)
                _emit(ScanPhase.CLASSIFYING, completed / total,
                      f"{completed:,}/{total:,} blocks")

        for ct in chunk_results:
            if ct:
                block_results.extend(_tuple_to_br(t) for t in ct)
    else:
        for block in reader:
            r = classify_block(block.id, block.offset, block.data)
            block_results.append(r)
            if block.id % 2_000 == 0:
                _emit(ScanPhase.CLASSIFYING, block.id / total,
                      f"{block.id:,}/{total:,} blocks")

    block_results.sort(key=lambda b: b.block_id)
    n_susp_pre = sum(1 for b in block_results if b.is_suspicious)
    print(f"[scanner_v2] Rule-based: {n_susp_pre:,} suspicious blocks")
    _emit(ScanPhase.CLASSIFYING, 1.0, f"{n_susp_pre:,} suspicious")

    # ── ML vectorised batch analysis ─────────────────────────────────────────
    # CRITICAL FIX: We used to do serial seek+classify per block → 30 min stall
    # Now: batch read ALL suspicious blocks into memory, call batch_classify_raw
    # which does ONE feature matrix + ONE predict_proba call. ~2-5 seconds.
    _emit(ScanPhase.ML, 0.0, "loading ML model")
    ml_summary = {"available": False, "overrides": 0, "false_positive_reductions": 0,
                  "blocks_analyzed": 0, "model_version": "unavailable"}
    try:
        clf = get_classifier()

        if clf.is_available:
            _emit(ScanPhase.ML, 0.15, "collecting suspicious blocks")

            # Select blocks for ML: suspicious + small window around each
            suspicious_ids = {b.block_id for b in block_results if b.is_suspicious}

            # ONLY run ML on suspicious + 3-block window (much smaller than before)
            # This avoids the 1M+ block window explosion for large images
            window = set()
            for bid in suspicious_ids:
                for w in (-2, -1, 0, 1, 2):
                    nb = bid + w
                    if 0 <= nb < total:
                        window.add(nb)

            # Build index for fast lookup
            br_by_id = {b.block_id: b for b in block_results if b.block_id in window}
            ml_candidates = [br_by_id[bid] for bid in sorted(window) if bid in br_by_id]

            # Cap at 50k — prioritise suspicious blocks
            MAX_ML = 50_000
            if len(ml_candidates) > MAX_ML:
                susp_cands = [b for b in ml_candidates if b.block_id in suspicious_ids]
                ml_candidates = susp_cands[:MAX_ML]

            n_ml = len(ml_candidates)
            print(f"[scanner_v2] ML: batch-reading {n_ml:,} blocks…")
            _emit(ScanPhase.ML, 0.2, f"reading {n_ml:,} blocks into memory")

            # ── BATCH READ — one sequential pass through the file ─────────────
            # Sort by offset for sequential reads (no random seeks)
            ml_candidates.sort(key=lambda b: b.offset)

            block_ids_ml = []
            offsets_ml   = []
            data_ml      = []
            base_rs_ml   = []

            with open(image_path, "rb") as f:
                prev_offset = -1
                for br in ml_candidates:
                    # Sequential reads — seek only when offset is non-contiguous
                    if br.offset != prev_offset + BLOCK_SIZE:
                        f.seek(br.offset)
                    raw = f.read(BLOCK_SIZE)
                    if not raw:
                        continue
                    block_ids_ml.append(br.block_id)
                    offsets_ml.append(br.offset)
                    data_ml.append(raw)
                    base_rs_ml.append(br)
                    prev_offset = br.offset

            _emit(ScanPhase.ML, 0.35, f"{len(data_ml):,} blocks read, running ensemble…")

            # ── VECTORISED CLASSIFY — single matrix op ─────────────────────────
            def ml_progress(done, total):
                _emit(ScanPhase.ML, 0.35 + 0.55 * (done / total if total > 0 else 1.0),
                      f"ensemble {done}/{total}")

            ml_results = clf.batch_classify_raw(
                block_ids=block_ids_ml,
                offsets=offsets_ml,
                data_list=data_ml,
                base_results=base_rs_ml,
                progress_cb=ml_progress,
            )

            # ── Apply overrides back to block_results ─────────────────────────
            overrides = 0
            fp_reductions = 0
            # Build mutable index
            br_index = {b.block_id: b for b in block_results}

            for mlr in ml_results:
                if mlr.ml_override:
                    orig = br_index.get(mlr.block_id)
                    if orig:
                        was_suspicious = orig.is_suspicious
                        orig.wipe_type    = mlr.final_label
                        orig.is_suspicious = mlr.is_suspicious
                        orig.confidence   = mlr.ml_confidence
                        overrides += 1
                        if was_suspicious and not mlr.is_suspicious:
                            fp_reductions += 1

            n_susp_post = sum(1 for b in block_results if b.is_suspicious)
            ml_summary = {
                "available":               True,
                "model_version":           clf.model_version,
                "overrides":               overrides,
                "false_positive_reductions": fp_reductions,
                "blocks_analyzed":         len(data_ml),
                "cv_scores":               clf.cv_scores,
                "models":                  clf.summary().get("models", []),
            }
            custody.record_ml_analysis(
                model_version=clf.model_version, blocks_analyzed=len(data_ml),
                overrides=overrides, false_positive_reductions=fp_reductions,
            )
            print(f"[scanner_v2] ML done: {overrides} overrides, "
                  f"{fp_reductions} FP reductions. "
                  f"Suspicious: {n_susp_pre:,} → {n_susp_post:,}")

    except Exception as e:
        import traceback
        print(f"[scanner_v2] ML skipped: {e}")
        traceback.print_exc()

    _emit(ScanPhase.ML, 1.0)

    # ── Aggregation ───────────────────────────────────────────────────────────
    _emit(ScanPhase.AGGREGATING, 0.0)
    regions = aggregate(block_results, partition_map=partition_map)
    print(f"[scanner_v2] {len(regions)} regions")
    _emit(ScanPhase.AGGREGATING, 1.0, f"{len(regions)} regions")

    # ── Scoring ───────────────────────────────────────────────────────────────
    _emit(ScanPhase.SCORING, 0.0)
    stats = compute_score(block_results, regions, partition_map=partition_map)
    print(f"[scanner_v2] Score: {stats.intent_score}/100 ({stats.verdict})")
    custody.record_scan_complete(
        result_path=str(output_dir / f"analysis_{session_id}.json"),
        intent_score=stats.intent_score, verdict=stats.verdict,
        regions_found=len(regions), suspicious_blocks=stats.suspicious_blocks,
        total_blocks=stats.total_blocks,
        ml_overrides=ml_summary.get("overrides", 0),
        model_version=ml_summary.get("model_version", ""),
    )
    _emit(ScanPhase.SCORING, 1.0)

    # ── Forensic report ───────────────────────────────────────────────────────
    _emit(ScanPhase.REPORTING, 0.0)
    report = generate_report(
        session_id=session_id, filename=image_path.name, sha256=sha256,
        size_bytes=reader.image_size, stats=stats, regions=regions,
        blocks=block_results, custody=custody, ml_summary=ml_summary,
    )
    custody.record_report_generated(
        str(output_dir / f"analysis_{session_id}.json"), "JSON"
    )
    _emit(ScanPhase.REPORTING, 1.0)

    # ── Write results ─────────────────────────────────────────────────────────
    _emit(ScanPhase.WRITING, 0.0)
    custody_path = custody.save()
    print(f"[scanner_v2] Custody: {custody_path}")

    json_path = _write_enhanced(
        session_id=session_id, filename=image_path.name, sha256=sha256,
        size_bytes=reader.image_size, blocks=block_results, regions=regions,
        stats=stats, output_dir=output_dir, report=report,
        custody_summary=custody.to_summary_dict(), ml_summary=ml_summary,
        partition_map=partition_map,
    )

    elapsed = time.time() - t0
    speed   = (reader.image_size / (1024**2)) / elapsed if elapsed > 0 else 0
    print(f"[scanner_v2] ✓ Done in {elapsed:.1f}s ({speed:.1f} MB/s). JSON: {json_path}")

    _emit(ScanPhase.WRITING, 1.0)
    if scan_state_ref is not None:
        scan_state_ref["progress"] = 100
        scan_state_ref["phase"] = ScanPhase.DONE
    if progress_cb:
        progress_cb(100, 100)

    return json_path


# ─────────────────────────────────────────────────────────────────────────────
# ENHANCED JSON WRITER
# ─────────────────────────────────────────────────────────────────────────────

def _write_enhanced(session_id, filename, sha256, size_bytes,
                    blocks, regions, stats, output_dir, report,
                    custody_summary, ml_summary, partition_map=None) -> Path:
    import json
    from datetime import datetime, timezone

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"analysis_{session_id}.json"

    def _fmt(b):
        for u in ("B","KB","MB","GB","TB"):
            if b<1024: return f"{b:.2f} {u}"
            b /= 1024
        return f"{b:.2f} PB"

    payload = {
        # ── Backward-compatible core fields ───────────────────────────────────
        "session_id": session_id, "filename": filename,
        "sha256": sha256, "size_bytes": size_bytes,
        "size_human": _fmt(size_bytes),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats.to_dict(),
        "regions": [r.to_dict() for r in regions],
        "blocks": [{"id":b.block_id,"type":b.wipe_type,"entropy":round(b.entropy,3)}
                   for b in blocks],
        # ── New fields ────────────────────────────────────────────────────────
        "forensic_report":    report,
        "chain_of_custody":   custody_summary,
        "ml_analysis":        ml_summary,
        "partition_map":      partition_map.to_dict() if partition_map is not None else None,
        "analysis_metadata":  {
            "scanner_version":    "scanner_v2",
            "ml_enabled":         ml_summary.get("available", False),
            "custody_enabled":    True,
            "partition_map_scheme": partition_map.scheme if partition_map is not None else "UNKNOWN",
        },
    }

    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scanner_v2.py <image_path> <session_id> [sha256]")
        sys.exit(1)
    out = run_scan(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "unknown")
    print(f"\nDone. JSON: {out}")
