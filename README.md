# WipeTrace

**Forensic disk-wipe detection and analysis tool.**

WipeTrace scans raw disk images and identifies sectors that have been deliberately overwritten — zero fills, `0xFF` fills, pseudorandom overwrites, multi-pass Gutmann/DoD patterns, and partial wipe artefacts. It combines a rule-based block classifier, a 4-model ML ensemble, partition-boundary awareness, and a full chain-of-custody system into a single browser-accessible interface built for forensic investigators.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Running the Server](#running-the-server)
- [Usage Walkthrough](#usage-walkthrough)
- [Detection Engine](#detection-engine)
  - [Block Classification](#block-classification)
  - [Region Aggregation](#region-aggregation)
  - [Partition Boundary Analysis](#partition-boundary-analysis)
  - [ML Ensemble](#ml-ensemble)
  - [Intent Scoring](#intent-scoring)
- [API Reference](#api-reference)
- [Output JSON Schema](#output-json-schema)
- [Chain of Custody](#chain-of-custody)
- [Forensic Limitations](#forensic-limitations)
- [Contributing](#contributing)

---

## Overview

When a suspect drive is wiped before seizure, the goal is to detect *that a wipe occurred* and establish the *likely method* — even when the wiped data itself is unrecoverable. WipeTrace works on raw disk images (`.dd`, `.img`, `.raw`, `.E01` flat extraction) and produces a structured forensic report suitable for evidentiary use.

The core insight is that different wipe strategies leave distinct byte-level signatures:

| Wipe Method | Signature |
|---|---|
| Single-pass zero | >90% `0x00`, entropy ≈ 0 |
| Single-pass `0xFF` | >90% `0xFF`, entropy ≈ 0 |
| CSPRNG overwrite | Entropy ≥ 7.6 bits/byte, flat byte distribution |
| Gutmann / DoD multi-pass | Alternating bands of fill and random types |
| Partial / interrupted wipe | 60–90% fill byte with high-entropy scatter in non-fill portion |
| Low-entropy pattern wipe | Structured mid-entropy, anomalously uniform distribution |

Crucially, WipeTrace also distinguishes **deliberately wiped sectors** from **never-written sectors** — a half-empty drive's trailing zero-filled space is factory default, not evidence of wiping.

---

## Features

- **7-class block classifier** — `ZERO_WIPE`, `FF_WIPE`, `RANDOM_WIPE`, `MULTI_PASS`, `LIKELY_ZERO_WIPE`, `LIKELY_FF_WIPE`, `LOW_ENTROPY_SUSPECT`
- **ML ensemble** — RandomForest + ExtraTrees + GradientBoosting + IsolationForest, 30-dimensional feature space, trained on ~15,000 synthetic samples
- **Partition boundary analysis** — parses MBR and GPT tables; zero-fill regions beyond the last partition boundary are penalised rather than flagged as evidence
- **Multi-pass detection** — identifies alternating wipe-type bands (Gutmann, DoD 5220.22-M patterns)
- **Chain of custody** — cryptographically linked event log from acquisition through reporting; SHA-256 at every stage
- **Forensic intent score** — 0–100 composite score with `NEGLIGIBLE / LOW / MEDIUM / HIGH` verdict
- **Parallel scanning** — `ProcessPoolExecutor` splits the image across CPU cores; ~30 s for a 1.5 GB image on an 8-core machine
- **Browser UI** — single-page dashboard with disk map, entropy chart, regions table, hex viewer, forensic report, and chain-of-custody viewer
- **Light/dark mode** — full theme support
- **Multi-format export** — JSON, CSV, PDF (print), RTF/DOCX
- **Case management** — investigator name, badge/staff ID, case ID, agency, device description, notes

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser                                                        │
│  upload_module.html  →  analysis_dashboard.html                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP / REST
┌───────────────────────────▼─────────────────────────────────────┐
│  FastAPI  (backend_integrate.py)                                │
│  POST /upload   POST /scan   GET /scan/status   GET /results    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│  scanner_v2.py  (scan orchestrator)                             │
│                                                                 │
│  1. hash_file()          SHA-256 of full image                  │
│  2. parse_partition_map()  MBR / GPT boundary detection         │
│  3. BlockReader          stream image in 512-byte blocks        │
│  4. classify_block()     rule-based per-block classification    │
│     (parallel, N-1 cores)                                       │
│  5. MLClassifier.batch_classify_raw()  ensemble override        │
│  6. aggregate()          merge blocks → regions                 │
│     + _apply_boundary_context()  penalise beyond-boundary fills │
│  7. compute_score()      forensic intent score                  │
│  8. generate_report()    structured forensic narrative          │
│  9. CustodyChain.save()  write custody JSON                     │
│  10. write_results()     write analysis JSON                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
wipetrace/
│
├── backend_integrate.py        FastAPI server — upload, scan, results endpoints
├── scanner_v2.py               Scan orchestrator (parallel + ML + custody)
├── scanner.py                  Legacy single-threaded scanner (deprecated)
├── hashing.py                  SHA-256 file hashing (1 MB streaming chunks)
├── upload_module.html          Case intake form + file upload UI */front end/*
├── analysis_dashboard.html     Full analysis dashboard (SPA) */front end/*
├── engine/
│   ├── reader.py               BlockReader — streams image in 512-byte blocks
│   ├── classifier.py           Rule-based block classifier (7 wipe types)
│   ├── ml_classifier.py        4-model ML ensemble (30-feature extraction)
│   ├── aggregator.py           Merge blocks → regions; multi-pass detection
│   ├── partition_map.py        MBR/GPT parser; boundary context annotation
│   ├── scorer.py               Forensic intent score (0–100) + verdict
│   ├── report_generator.py     Structured forensic report narrative
│   ├── custody.py              Cryptographic chain-of-custody log
│   └── writer.py               JSON result serialiser
│
├── uploads/                    Created at runtime — stores images + results
│   ├── SID-XXXXXXXX_image.dd
│   └── analysis_SID-XXXXXXXX.json
│
├── requirements.txt
└── README.md
```

> **Note on module paths:** `engine/` modules are imported as `from engine.classifier import ...`. Place all `engine/*.py` files in an `engine/` subdirectory. The `engine/` directory does not need an `__init__.py` (Python 3.3+ namespace packages), but adding an empty one is fine.

---

## Installation

### Prerequisites

- Python **3.10 or later** (3.12 recommended)
- A modern browser (Chrome, Firefox, Edge, Safari)
- 2 GB free RAM minimum; 8 GB recommended for images > 4 GB

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/jynxora/wipetrace.git
cd wipetrace

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create the engine package directory (if it doesn't exist)
mkdir -p engine
mv classifier.py ml_classifier.py aggregator.py partition_map.py \
   scorer.py report_generator.py custody.py reader.py writer.py engine/

# 5. Verify
python3 -c "from engine.classifier import classify_block; print('OK')"
```

---

## Running the Server

```bash
uvicorn backend_integrate:app --host 0.0.0.0 --port 8000
```

Then open **`upload_module.html`** in your browser (you can open it as a local file — no web server needed for the frontend).

> **CORS:** The server is configured with `allow_origins=["*"]` for development. Tighten this to your specific origin in production by editing the `CORSMiddleware` block in `backend_integrate.py`.

---

## Usage Walkthrough

### 1. Upload a disk image

Open `upload_module.html`. Fill in the optional case details (investigator name, badge ID, case ID, agency, device description) — these are embedded in the chain-of-custody log and forensic report.

Click **Choose File** and select a raw disk image (`.dd`, `.img`, `.raw`). The file streams to the backend in 1 MB chunks; SHA-256 is computed on the server after the upload completes.

### 2. Run the scan

Click **Begin Analysis**. The dashboard opens and polls `/scan/status/{session_id}` every 2 seconds, showing phase progress (Hashing → Classifying → ML Analysis → Aggregating → Scoring → Reporting → Writing).

### 3. Review results

The **Overview** tab shows:
- **5 stat cards** — Blocks Scanned, Suspicious Blocks, Regions Detected, Intent Score, Avg Entropy. Large numbers are abbreviated (e.g. `1.75M`); hover for the full precise value.
- **Wipe Type Distribution** — doughnut chart with all 7 types; partial/suspect types shown at reduced opacity.
- **Disk Map** — proportional visual of the disk. Wipe regions are colour-coded; regions beyond the last partition boundary are desaturated and marked with a hatched "Unwritten" overlay. Hover any segment for offset, entropy, confidence, and boundary context.
- **Entropy vs Block Offset** — 1,200-point sample of Shannon entropy across the image.
- **Forensic Intent Score** — 0–100 composite score with verdict ring.

The **Regions** tab provides a sortable, filterable table with Start/End offsets, size, wipe type badge, entropy, confidence bar, block count, and a **Context** badge (`INSIDE PARTITION` / `BEYOND BOUNDARY`).

The **Raw Data** tab gives a hex viewer for any block, with a 256-bucket byte frequency histogram.

The **Forensic Report** tab contains the structured narrative with recommended investigative actions scaled to the intent score.

The **Chain of Custody** tab shows the full cryptographic event log with SHA-256 entry/previous/evidence hashes and an integrity verification check against the live `/verify` endpoint.

### 4. Export

Click **Export** → choose JSON (full analysis), CSV (regions table), PDF (print-formatted report), or DOCX/RTF (Word-compatible document).

---

## Detection Engine

### Block Classification

`engine/classifier.py` classifies each 512-byte block through a strict priority decision tree:

1. **Empty block** → `NORMAL`
2. **>90% `0x00`, entropy ≤ 0.20** → `ZERO_WIPE`
3. **>90% `0xFF`, entropy ≤ 0.20** → `FF_WIPE`
4. **60–90% `0x00`** with high-entropy non-zero scatter → `LIKELY_ZERO_WIPE`
5. **60–90% `0xFF`** with high-entropy non-zero scatter → `LIKELY_FF_WIPE`
6. **Entropy ≥ 7.60** + flat byte distribution → `RANDOM_WIPE` (with compressed/encrypted data guard)
7. **Entropy 0.21–1.50**, no single-byte dominance, anomalously uniform → `LOW_ENTROPY_SUSPECT`
8. **Mid entropy 3.5–6.5** + flat distribution + **≥35% fill bytes** → `MULTI_PASS` candidate
9. **70–90% `0x00`** dominant → `UNALLOCATED`
10. Everything else → `NORMAL`

The `MULTI_PASS` gate at step 8 requires at least 35% of the block's bytes to be `0x00` or `0xFF`. This prevents high-entropy encrypted/compressed blocks from being mislabelled as multi-pass candidates just because they happen to have a flat byte distribution.

### Region Aggregation

`engine/aggregator.py` runs a 7-step pipeline on the flat block list:

| Step | Function | Purpose |
|---|---|---|
| 1 | `_merge_consecutive` | Group adjacent suspicious blocks into raw regions |
| 2 | `_absorb_noise` | Merge regions separated by ≤8 NORMAL blocks (wipers skip metadata blocks) |
| 3 | `_filter_by_size` | Discard regions < 16 blocks (8 KB) — isolated blocks are noise |
| 4 | `_detect_multi_pass` | Find alternating-type band sequences (≥3 bands) → upgrade to `MULTI_PASS` |
| 5 | `_suppress_false_positives` | Remove isolated low-confidence `LIKELY_*` regions with no strong-wipe neighbours |
| 6 | `_compute_confidence` | Per-region confidence from block evidence + size bonus + type adjustment |
| 7 | `_apply_boundary_context` | Annotate with `INSIDE_PARTITION` / `BEYOND_BOUNDARY`; penalise fill-type regions beyond the partition boundary |

### Partition Boundary Analysis

`engine/partition_map.py` parses the disk's partition table directly from the raw image bytes using only the Python standard library (`struct`). It supports:

- **MBR** (sector 0, signature `0x55AA`) — 4 primary entries + extended partition EBR chain
- **GPT** (primary header at LBA 1, signature `EFI PART`) — up to 128 partition entries
- **Hybrid** (protective MBR + GPT) — automatically detected and parsed as GPT
- **Unknown** — graceful degradation when no recognisable partition table is found

The key output is `PartitionMap.last_used_lba` — the highest end LBA across all partitions. Any byte offset beyond this is "unwritten territory":

- `ZERO_WIPE` / `FF_WIPE` regions beyond the boundary receive a **−0.28 confidence penalty** — their fill pattern is identical to factory-default unwritten sectors.
- `LIKELY_*` / `LOW_ENTROPY_SUSPECT` beyond the boundary receive **−0.36**.
- `RANDOM_WIPE` / `MULTI_PASS` beyond the boundary receive **−0.14** — random patterns cannot appear naturally in unwritten space, so they remain forensically relevant regardless of position.
- `INSIDE_PARTITION` regions receive a small **+0.04 boost**.

No region is ever fully dismissed (minimum confidence 0.10) because partition tables can themselves be corrupted or falsified.

### ML Ensemble

`engine/ml_classifier.py` runs a 4-model ensemble on suspicious blocks to reduce false positives — primarily distinguishing legitimate high-entropy data (AES-256, ZLIB, JPEG, H.264) from CSPRNG-based wipe output.

**Feature extraction (30 dimensions):**

| Group | Features | What they capture |
|---|---|---|
| Distribution shape (F01–F09) | Chi-squared statistic, KL divergence from uniform, top-5 byte dominance, gini coefficient | Whether the byte distribution is genuinely flat or has structure |
| Serial structure (F10–F15) | Byte pair transition entropy, run-length statistics, bigram chi-squared | Sequential patterns that CSPRNG output lacks |
| Spectral (F16–F19) | FFT power spectrum shape, dominant frequency magnitude | Periodic structure from compression/encryption artefacts |
| Block structure (F20–F25) | Null byte ratio, printable ASCII ratio, magic byte presence, 16-byte alignment patterns | Compressed file headers and padding |
| Entropy sub-blocks (F26–F30) | Shannon entropy of 8 equal sub-blocks (min, max, variance) | Intra-block entropy uniformity — CSPRNG is flat; encrypted data has local structure |

**Models:**
- `RandomForestClassifier(n_estimators=200)`
- `ExtraTreesClassifier(n_estimators=200)`
- `GradientBoostingClassifier(n_estimators=150)`
- `IsolationForest(n_estimators=200)` — anomaly gate

Final label: `argmax(mean(RF_proba, ET_proba, GB_proba))`, with `IsolationForest` score as a veto gate. Override threshold: 0.70 ensemble confidence.

The model is trained on ~15,000 synthetic samples at first use and cached to `engine/wipetrace_ml_model.pkl`. Training takes approximately 60–90 seconds and is skipped on subsequent runs.

### Intent Scoring

`engine/scorer.py` computes a 0–100 forensic intent score in four stages:

1. **Density fast-path** — raw suspicious-block density establishes a verdict floor (`NEGLIGIBLE / LOW / MEDIUM / HIGH`). When a partition map is available, blocks beyond the boundary are excluded from this density calculation.
2. **Evidence quality score** — coverage % (0–40 pts) + distinct region count (0–20 pts) + RANDOM_WIPE regions (0–25 pts) + MULTI_PASS regions (0–15 pts).
3. **Penalty adjustments** — high `LIKELY_*` ratio without strong corroboration (−10 pts), low average confidence (−5 pts), majority of evidence beyond partition boundary (−7 to −15 pts).
4. **Verdict** — density floor can raise but not lower the score-derived verdict.

**Verdict thresholds:**

| Score | Verdict | Interpretation |
|---|---|---|
| ≥ 70 | `HIGH` | Strong evidence of deliberate anti-forensic wiping |
| 35–69 | `MEDIUM` | Moderate evidence — correlate with other artefacts |
| 10–34 | `LOW` | Weak signal — likely benign or insufficient data |
| < 10 | `NEGLIGIBLE` | No meaningful wipe evidence detected |

---

## API Reference

All endpoints accept and return JSON. The server runs at `http://localhost:8000` by default.

### `POST /upload`
Stream a disk image to the server.

**Request:** `multipart/form-data` with field `file`.

**Response:**
```json
{
  "session_id": "SID-A3F8C21E",
  "filename": "suspect.dd",
  "size_bytes": 4294967296,
  "size_human": "4.00 GB",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "status": "ready"
}
```

### `POST /scan`
Trigger a scan on a previously uploaded image.

**Request:**
```json
{
  "session_id": "SID-A3F8C21E",
  "examiner": "Det. J. Smith",
  "case_id": "2024-CR-00142",
  "agency": "Metropolitan Police",
  "device": "Seagate 2TB HDD",
  "notes": "Seized from suspect's vehicle"
}
```

**Response:** `{ "session_id": "...", "status": "running" }`

### `GET /scan/status/{session_id}`
Poll scan progress.

**Response:**
```json
{
  "session_id": "SID-A3F8C21E",
  "status": "running",
  "progress": 68,
  "phase": "classifying"
}
```

Phases: `hashing` → `classifying` → `ml_analysis` → `aggregating` → `scoring` → `reporting` → `writing` → `done`

### `GET /results/{session_id}`
Fetch the complete analysis JSON once `status == "done"`.

### `GET /verify/{session_id}`
Verify the integrity of the chain-of-custody log for a session.

### `DELETE /session/{session_id}`
Delete the uploaded image and results JSON. Call after exporting.

---

## Output JSON Schema

```jsonc
{
  "session_id": "SID-A3F8C21E",
  "filename": "suspect.dd",
  "sha256": "e3b0c44...",
  "size_bytes": 4294967296,
  "scanned_at": "2024-03-15T14:22:10.441Z",

  "stats": {
    "total_blocks": 8388608,
    "suspicious_blocks": 1782558,
    "suspicious_pct": 21.25,
    "wipe_density": 0.2125,
    "regions_count": 18,
    "avg_entropy_flagged": 0.47,
    "intent_score": 85,
    "verdict": "HIGH",
    "coverage_pct": 71.0,
    "dominant_type": "ZERO_WIPE",
    "wipe_type_counts": { "ZERO_WIPE": 1750000, "FF_WIPE": 0, ... }
  },

  "regions": [
    {
      "id": 1,
      "start": 1048576,
      "end": 214748160,
      "size": 213699584,
      "type": "ZERO_WIPE",
      "entropy": 0.003,
      "confidence": 0.912,
      "block_count": 417382,
      "boundary_context": "INSIDE_PARTITION"
    }
    // ...
  ],

  "blocks": [
    { "id": 0, "type": "NORMAL", "entropy": 4.821 }
    // one entry per 512-byte block
  ],

  "partition_map": {
    "scheme": "MBR",
    "partitions": [
      {
        "index": 0, "start_lba": 2048, "end_lba": 4192255,
        "size_bytes": 2147581952, "type_code": "0x07",
        "type_name": "NTFS / exFAT / HPFS",
        "is_bootable": true, "scheme": "MBR"
      }
    ],
    "last_used_lba": 4192255,
    "disk_size_lba": 8388608
  },

  "forensic_report": { /* structured narrative — see report_generator.py */ },
  "chain_of_custody": { /* custody log summary */ },
  "ml_analysis": { "available": true, "overrides": 142, ... }
}
```

---

## Chain of Custody

`engine/custody.py` maintains a tamper-evident event log. Each event is SHA-256 hashed and chained to the previous hash, forming a cryptographic linked list. Events recorded during a scan:

| Event | When |
|---|---|
| `ACQUISITION` | Image received by server |
| `HASH_INITIAL` | SHA-256 computed after upload |
| `SCAN_START` | Scan engine begins |
| `ML_ANALYSIS` | ML ensemble completes |
| `SCAN_COMPLETE` | All phases done |
| `REPORT_GENERATED` | Forensic report written |

The custody log is saved as `analysis_{session_id}_custody.json` alongside the results file. The dashboard's Chain of Custody tab verifies chain integrity live against the `/verify` endpoint.

---

## Forensic Limitations

**Unwritten vs. wiped sectors.** WipeTrace uses partition boundary analysis to separate unwritten factory-default sectors from deliberately wiped ones. This relies on the partition table being intact. A suspect who destroys or falsifies the partition table before wiping will cause WipeTrace to classify those boundary regions as `UNKNOWN` — the tool will not make an incorrect attribution, but it will lose confidence granularity.

**SSD / TRIM / wear-levelling.** When the OS issues TRIM commands on an SSD, the controller may zero or erase blocks autonomously — producing patterns identical to a deliberate wipe. WipeTrace cannot distinguish TRIM erasure from intentional wiping at the byte level. Treat `ZERO_WIPE` detections on SSD images with additional caution.

**Full-disk wipes.** A disk that was entirely wiped before any data was written cannot be distinguished from a disk that was never used. WipeTrace is most effective when a wipe was partial — covering only the formerly active area.

**Encrypted volumes.** A correctly implemented full-disk encryption (BitLocker, LUKS, FileVault) will produce byte patterns that may resemble `RANDOM_WIPE` to the rule-based classifier. The ML ensemble is trained to distinguish CSPRNG wipe output from AES-CBC output and will reduce false positives, but high-entropy `RANDOM_WIPE` detections on known-encrypted volumes should be corroborated with other evidence.

**Block size.** WipeTrace operates at a fixed 512-byte block size. 4Kn (Advanced Format) drives that use 4,096-byte native sectors may produce slightly degraded classification at block boundaries where two logical 512-byte blocks straddle a physical sector.

---

## Contributing

Pull requests are welcome. Before opening one:

1. Run the existing test suite: `python3 -m pytest tests/` (if tests are present)
2. Ensure `classifier.py` changes include updated docstrings for any modified decision-tree steps
3. If changing the output JSON schema, update the schema documentation in this README and ensure backward compatibility in `analysis_dashboard.html`'s `adaptApiResponse()` function
4. Partition map changes should be tested against MBR, GPT, hybrid, and raw (no partition table) images

To report a false positive or false negative with a specific image type, open an issue and include:
- The wipe tool / method used to create the test image (if known)
- The block range and classification WipeTrace produced
- The hex dump of a representative block (first 64 bytes sufficient)

---
