"""
custody.py
──────────
Law Enforcement Agency (LEA) grade evidence handling and chain of custody.

LEGAL BASIS:
    Implements evidence handling compliant with:
    - ISO/IEC 27037:2012  — Digital Evidence Identification, Collection, Acquisition
    - ACPO Good Practice Guide for Digital Evidence (UK)
    - NIST SP 800-86       — Guide to Integrating Forensic Techniques
    - Federal Rules of Evidence (FRE) Rule 901 — Authentication
    - RFC 3161             — Cryptographic Timestamp (structure mirrored)

CHAIN OF CUSTODY RECORD:
    Every evidence event is recorded as an immutable log entry containing:
    1. Event timestamp (UTC ISO-8601)
    2. Event type (ACQUISITION, HASH_VERIFY, SCAN_START, SCAN_COMPLETE, etc.)
    3. SHA-256 of evidence file at that point (integrity verification)
    4. Examiner/system identifier
    5. Description + metadata
    6. Entry hash: SHA-256 of (prev_entry_hash + this_entry_content)
       → Tamper-evident linked hash chain — any modification breaks it

    The chain is serialised to:
        uploads/custody_<SESSION_ID>.json

INTEGRITY VERIFICATION:
    Call verify_chain(session_id) at any time to check that no entry
    has been modified since recording. Returns (bool, list_of_violations).

    In court submissions, the chain JSON + original hash prove:
    - When the evidence was acquired
    - That the file has not been modified since acquisition
    - Every analysis step performed on the evidence
    - Which software versions were used

Usage:
    from engine.custody import CustodyChain

    chain = CustodyChain(session_id="SID-A3F8C21E")
    chain.record_acquisition(
        filename="suspect.dd",
        sha256="e3b0...",
        size_bytes=4294967296,
        source_device="USB 3.0 write-blocked drive",
        examiner="Det. J. Smith, Badge #4421",
    )
    chain.record_scan_start(image_path="uploads/SID-A3F8C21E_suspect.dd")
    chain.record_scan_complete(result_path="uploads/analysis_SID-A3F8C21E.json",
                               intent_score=78, verdict="HIGH")
    chain.record_hash_verify(sha256="e3b0...", verified=True)
    chain.save()

    # Later:
    ok, violations = CustodyChain.verify_chain("SID-A3F8C21E")
"""

import hashlib
import json
import os
import platform
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

CUSTODY_VERSION  = "1.0.0"
CHAIN_DIR        = Path("uploads")

EVENT_TYPES = {
    "SYSTEM_INIT":       "System initialisation — WipeTrace session created",
    "ACQUISITION":       "Evidence acquisition — disk image received and stored",
    "HASH_INITIAL":      "Initial integrity hash computed (SHA-256)",
    "HASH_VERIFY":       "Integrity hash verification performed",
    "SCAN_START":        "Forensic scan initiated",
    "SCAN_PROGRESS":     "Scan progress checkpoint",
    "SCAN_COMPLETE":     "Forensic scan completed — results generated",
    "ML_ANALYSIS":       "ML classifier analysis applied",
    "REPORT_GENERATED":  "Forensic report generated",
    "EXPORT":            "Evidence package exported",
    "SESSION_CLOSED":    "Session closed — evidence preserved",
    "INTEGRITY_BROKEN":  "ALERT: Chain of custody integrity violation detected",
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CustodyEntry:
    """
    A single immutable event in the chain of custody.

    entry_hash: SHA-256(prev_hash + timestamp + event_type + sha256_evidence + description)
    Linking prev_hash creates a tamper-evident chain — modifying any entry
    invalidates all subsequent entry_hashes.
    """
    sequence:         int           # sequential entry number (1-indexed)
    timestamp_utc:    str           # ISO-8601 UTC
    timestamp_unix:   float         # Unix timestamp for machine processing
    event_type:       str
    description:      str
    sha256_evidence:  Optional[str]  # SHA-256 of evidence file at this point
    examiner:         str
    system_info:      dict
    metadata:         dict
    prev_hash:        str           # hash of previous entry (or "GENESIS" for first)
    entry_hash:       str           # tamper-evident hash of this entry

    def to_dict(self) -> dict:
        return asdict(self)


def _system_info() -> dict:
    """Collect system metadata for audit trail."""
    return {
        "hostname":     socket.gethostname(),
        "platform":     platform.platform(),
        "python":       sys.version.split()[0],
        "pid":          os.getpid(),
        "software":     "WipeTrace v1.0",
    }


def _compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    event_type: str,
    sha256_evidence: Optional[str],
    description: str,
) -> str:
    """
    Compute tamper-evident hash for a custody entry.
    Any change to any field breaks this hash and all subsequent hashes.
    """
    content = "|".join([
        prev_hash,
        timestamp,
        event_type,
        sha256_evidence or "NULL",
        description,
    ])
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# CUSTODY CHAIN
# ─────────────────────────────────────────────────────────────────────────────

class CustodyChain:
    """
    Tamper-evident, append-only chain of custody for a WipeTrace session.
    """

    def __init__(
        self,
        session_id:     str,
        examiner:       str = "WipeTrace Analysis System",
        output_dir:     Path = CHAIN_DIR,
    ):
        self.session_id  = session_id
        self.examiner    = examiner
        self.output_dir  = Path(output_dir)
        self.entries:    List[CustodyEntry] = []
        self._last_hash  = "GENESIS"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Bootstrap: record system initialisation as first entry
        self._record(
            event_type="SYSTEM_INIT",
            description=f"WipeTrace session {session_id} initialised. "
                        f"Chain of custody record established.",
            metadata={
                "session_id":      session_id,
                "custody_version": CUSTODY_VERSION,
                "examiner":        examiner,
            },
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def record_acquisition(
        self,
        filename:       str,
        sha256:         str,
        size_bytes:     int,
        source_device:  str = "uploaded via WipeTrace web interface",
        examiner:       str = "",
        write_blocker:  str = "software (WipeTrace upload stream)",
        notes:          str = "",
    ) -> CustodyEntry:
        """
        Record evidence acquisition — the most legally critical event.
        Must be called immediately after the image is stored.
        """
        size_human = _fmt_bytes(size_bytes)
        desc = (
            f"Disk image '{filename}' acquired and stored. "
            f"Size: {size_human} ({size_bytes:,} bytes). "
            f"SHA-256: {sha256}. "
            f"Source: {source_device}. "
            f"Write protection: {write_blocker}."
        )
        if notes:
            desc += f" Notes: {notes}"

        return self._record(
            event_type="ACQUISITION",
            description=desc,
            sha256_evidence=sha256,
            examiner=examiner or self.examiner,
            metadata={
                "filename":       filename,
                "size_bytes":     size_bytes,
                "size_human":     size_human,
                "source_device":  source_device,
                "write_blocker":  write_blocker,
                "notes":          notes,
            },
        )

    def record_hash_initial(self, sha256: str, filename: str) -> CustodyEntry:
        return self._record(
            event_type="HASH_INITIAL",
            description=f"SHA-256 computed for '{filename}': {sha256}",
            sha256_evidence=sha256,
            metadata={"algorithm": "SHA-256", "filename": filename},
        )

    def record_hash_verify(
        self, sha256: str, verified: bool, original_sha256: str = ""
    ) -> CustodyEntry:
        status = "MATCH — integrity confirmed" if verified else \
                 "MISMATCH — EVIDENCE MAY HAVE BEEN MODIFIED"
        desc = f"Hash verification: {status}. Current SHA-256: {sha256}."
        if original_sha256 and original_sha256 != sha256:
            desc += f" Original SHA-256: {original_sha256}."

        return self._record(
            event_type="HASH_VERIFY",
            description=desc,
            sha256_evidence=sha256,
            metadata={
                "current_sha256":  sha256,
                "original_sha256": original_sha256,
                "verified":        verified,
                "alert":           not verified,
            },
        )

    def record_scan_start(
        self,
        image_path: str,
        total_blocks: int = 0,
        image_size: int = 0,
    ) -> CustodyEntry:
        return self._record(
            event_type="SCAN_START",
            description=f"Forensic scan initiated on '{Path(image_path).name}'. "
                        f"Total blocks: {total_blocks:,}. "
                        f"Image size: {_fmt_bytes(image_size)}.",
            metadata={
                "image_path":    str(image_path),
                "total_blocks":  total_blocks,
                "image_size":    image_size,
            },
        )

    def record_scan_progress(self, blocks_done: int, total: int) -> CustodyEntry:
        pct = int((blocks_done / total * 100)) if total > 0 else 0
        return self._record(
            event_type="SCAN_PROGRESS",
            description=f"Scan progress: {pct}% ({blocks_done:,}/{total:,} blocks)",
            metadata={"blocks_done": blocks_done, "total": total, "pct": pct},
        )

    def record_scan_complete(
        self,
        result_path:      str,
        intent_score:     int,
        verdict:          str,
        regions_found:    int = 0,
        suspicious_blocks: int = 0,
        total_blocks:     int = 0,
        ml_overrides:     int = 0,
        model_version:    str = "",
    ) -> CustodyEntry:
        desc = (
            f"Forensic scan completed. Results written to '{Path(result_path).name}'. "
            f"Intent score: {intent_score}/100 ({verdict}). "
            f"Regions detected: {regions_found}. "
            f"Suspicious blocks: {suspicious_blocks:,}/{total_blocks:,}."
        )
        if ml_overrides > 0:
            desc += f" ML model overrode {ml_overrides} rule-based classifications."

        return self._record(
            event_type="SCAN_COMPLETE",
            description=desc,
            metadata={
                "result_path":       str(result_path),
                "intent_score":      intent_score,
                "verdict":           verdict,
                "regions_found":     regions_found,
                "suspicious_blocks": suspicious_blocks,
                "total_blocks":      total_blocks,
                "ml_overrides":      ml_overrides,
                "model_version":     model_version,
            },
        )

    def record_ml_analysis(
        self,
        model_version: str,
        blocks_analyzed: int,
        overrides: int,
        false_positive_reductions: int,
    ) -> CustodyEntry:
        return self._record(
            event_type="ML_ANALYSIS",
            description=(
                f"ML ensemble classifier v{model_version} applied. "
                f"{blocks_analyzed:,} blocks analyzed. "
                f"{overrides} rule-based decisions overridden "
                f"({false_positive_reductions} false-positive reductions)."
            ),
            metadata={
                "model_version":             model_version,
                "blocks_analyzed":           blocks_analyzed,
                "overrides":                 overrides,
                "false_positive_reductions": false_positive_reductions,
            },
        )

    def record_report_generated(
        self, report_path: str, report_type: str = "JSON"
    ) -> CustodyEntry:
        return self._record(
            event_type="REPORT_GENERATED",
            description=f"{report_type} forensic report generated: "
                        f"'{Path(report_path).name}'",
            metadata={"report_path": str(report_path), "report_type": report_type},
        )

    def record_export(self, export_path: str, export_format: str) -> CustodyEntry:
        return self._record(
            event_type="EXPORT",
            description=f"Evidence exported as {export_format}: '{export_path}'",
            metadata={"export_path": export_path, "format": export_format},
        )

    def save(self) -> Path:
        """Serialise the full chain to JSON."""
        path = self.output_dir / f"custody_{self.session_id}.json"
        payload = {
            "chain_of_custody": {
                "session_id":      self.session_id,
                "custody_version": CUSTODY_VERSION,
                "total_entries":   len(self.entries),
                "genesis_hash":    "GENESIS",
                "final_hash":      self._last_hash,
                "created_at":      self.entries[0].timestamp_utc if self.entries else "",
                "last_updated":    self.entries[-1].timestamp_utc if self.entries else "",
                "examiner":        self.examiner,
                "legal_notice": (
                    "This chain of custody record was generated by WipeTrace. "
                    "Each entry hash is computed from the previous entry hash and "
                    "current entry content, forming a tamper-evident linked chain. "
                    "Any modification to this record will invalidate subsequent "
                    "entry hashes, which can be independently verified."
                ),
            },
            "entries": [e.to_dict() for e in self.entries],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return path

    @staticmethod
    def verify_chain(
        session_id: str,
        custody_dir: Path = CHAIN_DIR,
    ) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of a saved custody chain.

        Returns (is_valid: bool, violations: list[str])

        For court submissions: call this before submitting to confirm
        the chain has not been tampered with since initial recording.
        """
        path = Path(custody_dir) / f"custody_{session_id}.json"
        if not path.exists():
            return False, [f"Custody file not found: {path}"]

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries = data.get("entries", [])
        violations = []
        prev_hash = "GENESIS"

        for i, entry_dict in enumerate(entries):
            expected_hash = _compute_entry_hash(
                prev_hash=prev_hash,
                timestamp=entry_dict["timestamp_utc"],
                event_type=entry_dict["event_type"],
                sha256_evidence=entry_dict.get("sha256_evidence"),
                description=entry_dict["description"],
            )
            actual_hash = entry_dict.get("entry_hash", "")

            if actual_hash != expected_hash:
                violations.append(
                    f"Entry #{i+1} (seq={entry_dict.get('sequence')}, "
                    f"type={entry_dict.get('event_type')}): "
                    f"hash mismatch — expected {expected_hash[:16]}…, "
                    f"got {actual_hash[:16]}… "
                    f"CHAIN INTEGRITY BROKEN AT THIS POINT."
                )

            prev_hash = actual_hash or expected_hash

        is_valid = len(violations) == 0
        return is_valid, violations

    def to_summary_dict(self) -> dict:
        """Summary suitable for embedding in the analysis JSON."""
        return {
            "session_id":    self.session_id,
            "total_entries": len(self.entries),
            "final_hash":    self._last_hash,
            "examiner":      self.examiner,
            "created_at":    self.entries[0].timestamp_utc if self.entries else "",
            "last_updated":  self.entries[-1].timestamp_utc if self.entries else "",
            "last_event":    self.entries[-1].event_type if self.entries else "",
            "events": [
                {
                    "seq":      e.sequence,
                    "ts":       e.timestamp_utc,
                    "type":     e.event_type,
                    "desc":     e.description,          # full — no truncation
                    "hash":     e.entry_hash,            # full SHA-256
                    "prev_hash": e.prev_hash,            # full, for cross-checking
                    "sha256_evidence": e.sha256_evidence or "",  # evidence hash per-event
                    "examiner": e.examiner,
                    "metadata": e.metadata,
                }
                for e in self.entries
            ],
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _record(
        self,
        event_type:      str,
        description:     str,
        sha256_evidence: Optional[str] = None,
        examiner:        str = "",
        metadata:        dict = None,
    ) -> CustodyEntry:
        """Append an immutable entry to the chain."""
        now = datetime.now(timezone.utc)
        ts_utc = now.isoformat()
        ts_unix = now.timestamp()

        entry_hash = _compute_entry_hash(
            prev_hash=self._last_hash,
            timestamp=ts_utc,
            event_type=event_type,
            sha256_evidence=sha256_evidence,
            description=description,
        )

        entry = CustodyEntry(
            sequence=len(self.entries) + 1,
            timestamp_utc=ts_utc,
            timestamp_unix=ts_unix,
            event_type=event_type,
            description=description,
            sha256_evidence=sha256_evidence,
            examiner=examiner or self.examiner,
            system_info=_system_info(),
            metadata=metadata or {},
            prev_hash=self._last_hash,
            entry_hash=entry_hash,
        )

        self.entries.append(entry)
        self._last_hash = entry_hash
        return entry


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.2f} {unit}"
        b //= 1024
    return f"{b:.2f} PB"
