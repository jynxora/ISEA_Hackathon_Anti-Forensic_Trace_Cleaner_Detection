# ISEA Hackathon — Anti-Forensic Data Wiping Detection Engine

A high-performance disk image analysis engine designed to detect intentional data wiping patterns inside forensic images.

Built during a 24-hour ISEA Anti-Forensic Detection Hackathon.

We did not win the competition.  
We did build a robust, modular, working detection system.

---

## Problem Statement

When an attacker anticipates forensic acquisition (raids, internal investigations, incident response), they may attempt to destroy evidence using:

- Zero-fill wipes (`0x00`)
- FF-fill wipes (`0xFF`)
- Random overwrite
- Multi-pass overwrite strategies
- Low-and-slow wiping to evade threshold detection

Traditional forensic tools can detect absence of data — but often do not clearly quantify wipe intent or differentiate noise from deliberate destruction.

This project focuses on:

> Detecting structured, intentional wipe behavior inside raw disk images.

---

## System Architecture

```
project/
├── upload_module.html
├── analysis_dashboard.html
├── hashing.py
├── backend_main.py
├── scanner.py
│
├── engine/
│ ├── reader.py
│ ├── classifier.py
│ ├── aggregator.py
│ ├── scorer.py
│ └── writer.py
│
└── uploads/
└── analysis_<SID>.json
```
---

## Architecture Overview

### 1️ Reader (`engine/reader.py`)

- Streams raw disk images in 4KB blocks
- Memory-efficient
- Designed for large forensic images
- No full image loading into RAM

---

### 2️ Block Classifier (`engine/classifier.py`)

Per-block classification into:

- `ZERO` → all `0x00`
- `FF` → all `0xFF`
- `RANDOM` → high entropy overwrite
- `MULTI` → mixed structured overwrite patterns
- `NORMAL` → non-wipe content

Designed for deterministic behavior — no ML guesswork.

---

### 3️ Aggregator (`engine/aggregator.py`)

- Merges consecutive flagged blocks
- Converts block-level noise into region-level intelligence
- Eliminates fragmented false positives

---

### 4️ Intent Scorer (`engine/scorer.py`)

Core logic layer.

Calculates:

- Intent score
- Region confidence
- False-positive filtering
- Pattern coherence weighting

**Focus:**  
Distinguishing legitimate high-entropy content from deliberate wipe patterns.

---

### 5️ Writer (`engine/writer.py`)

- Outputs structured JSON
- Stored as:
  uploads/analysis_<SID>.json


- Designed for dashboard consumption
- API-consumable output format

---

## Backend

### `backend_main.py`

- Handles file upload
- Generates secure session ID
- Triggers hashing + scan pipeline
- Serves analysis output

### `hashing.py`

- Calculates cryptographic hashes
- Ensures evidence integrity tracking
- Prepares image fingerprint before analysis

---

## Dashboard

### `analysis_dashboard.html`

- Visualizes detected wipe regions
- Displays intent score
- Shows region offsets and classifications
- Designed for clarity over aesthetics

---

## Detection Philosophy

We avoided:

- Kernel drivers
- Memory forensics
- Unrealistic threat assumptions
- Overuse of entropy as a magic metric

We focused on:

- Host-acquired disk images
- Block-level deterministic classification
- Region-based reasoning
- Practical forensic signals

This is not a ransomware detector.  
This is not a full DFIR suite.

This is a specialized anti-forensic wipe detection engine.

---

## What It Detects

- Structured wipe attempts
- Multi-pass overwrites
- Large contiguous random regions
- Suspicious block homogeneity
- Coherent wipe segments inconsistent with normal file system behavior

---

## What It Does Not Do

- File carving
- File system reconstruction
- Attribution
- Network forensics
- Real-time monitoring

This is post-acquisition forensic analysis.

---

## Technical Design Principles

- Streaming architecture
- Modular engine separation
- Deterministic logic
- False-positive minimization
- JSON-first output design
- Scalable to large disk images

---

## Hackathon Context

Built in 24 hours during the ISEA Anti-Forensic Detection Tool Building Hackathon.

**Constraints:**

- Limited time
- No external forensic libraries, frameworks or tools
- Pure custom detection logic

**Result:**  
A working prototype capable of detecting wipe behavior with region-level granularity.

---

## Future Improvements

- Smarter entropy variance modeling
- File system-aware wipe anomaly detection
- Temporal wipe pattern inference
- Visualization enhancements
- Report export (PDF / forensic-ready format)
- Automated false-positive benchmarking suite

---

## Use Cases

- Post-raid forensic review
- Corporate insider investigations
- Incident response validation
- Academic research in anti-forensic detection
- Cyber forensic training environments

---

## License

MIT License

---

## Final Note

This project was built under time pressure.

It is not a polished product.  
It is a serious prototype.

The goal was not to build hype.  
The goal was to understand and detect anti-forensic intent.

And that is exactly what this system attempts to do.
