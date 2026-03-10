"""
partition_map.py
────────────────
Parses MBR and GPT partition tables from a raw disk image to establish
partition boundaries.  Used by the aggregator and scorer to distinguish
"never-written" sectors (beyond every partition's end LBA) from sectors
that were once inside an active partition and may have been deliberately
wiped.

Supports
--------
  MBR  — sector 0, signature 0x55AA at bytes 510-511
  GPT  — primary header at sector 1, signature "EFI PART"
  Hybrid (protective MBR + GPT) — detected and handled as GPT
  Extended partitions (MBR type 0x05 / 0x0F) — one level of nesting

Does NOT support
----------------
  BSD disklabels, Apple Partition Map, LVM/RAID metadata.
  These produce scheme="UNKNOWN" with an empty partition list.

Key output
----------
  PartitionMap.last_used_lba
      The highest end LBA across ALL partitions.  Any byte offset strictly
      beyond this is "beyond every partition boundary" — territory that
      was never formatted or written by the OS and therefore should NOT be
      interpreted as a deliberate wipe even if it contains 0x00 fill.

  PartitionMap.classify_offset(byte_offset) -> BoundaryContext
      Returns INSIDE, BEYOND, or UNKNOWN for any byte offset in the image.

Usage
-----
  pm = parse_partition_map(path_to_image)
  ctx = pm.classify_offset(region.start_offset)
"""

import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SECTOR_SIZE      = 512
MBR_SIGNATURE    = b"\x55\xAA"
GPT_SIGNATURE    = b"EFI PART"
GPT_HEADER_LBA   = 1                   # primary GPT header is always at LBA 1
MBR_PART_OFFSET  = 446                 # first partition entry in MBR
MBR_PART_SIZE    = 16
MBR_PART_COUNT   = 4
GPT_PART_ENTRY_SIZE_MIN = 128          # minimum; header field specifies actual size

# MBR partition type codes that indicate "this partition has real data"
# Type 0x00 = empty slot — skip
MBR_TYPE_EMPTY   = 0x00
MBR_TYPE_EXTENDED       = (0x05, 0x0F, 0x85)  # extended partition containers
MBR_PROTECTIVE_GPT      = 0xEE                 # protective MBR for GPT disks

# Well-known GPT type GUIDs (as raw 16-byte little-endian)
_GPT_TYPE_UNUSED = b"\x00" * 16


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

class BoundaryContext(str, Enum):
    INSIDE   = "INSIDE_PARTITION"    # offset falls within a known partition
    BEYOND   = "BEYOND_BOUNDARY"     # offset is past every partition's end LBA
    UNKNOWN  = "UNKNOWN"             # no partition table could be parsed


@dataclass
class PartitionEntry:
    index:       int
    start_lba:   int
    end_lba:     int       # inclusive
    sector_count: int
    part_type:   int       # raw MBR type byte, or 0xFF for GPT entries
    type_name:   str
    is_bootable: bool
    scheme:      str       # "MBR" | "GPT"

    @property
    def start_offset(self) -> int:
        return self.start_lba * SECTOR_SIZE

    @property
    def end_offset(self) -> int:
        return (self.end_lba + 1) * SECTOR_SIZE - 1   # inclusive byte offset

    def to_dict(self) -> dict:
        return {
            "index":        self.index,
            "start_lba":    self.start_lba,
            "end_lba":      self.end_lba,
            "start_offset": self.start_offset,
            "end_offset":   self.end_offset,
            "size_bytes":   self.sector_count * SECTOR_SIZE,
            "type_code":    hex(self.part_type),
            "type_name":    self.type_name,
            "is_bootable":  self.is_bootable,
            "scheme":       self.scheme,
        }


@dataclass
class PartitionMap:
    scheme:         str                              # "MBR" | "GPT" | "HYBRID" | "UNKNOWN"
    partitions:     List[PartitionEntry] = field(default_factory=list)
    last_used_lba:  int = 0                          # highest end_lba across all partitions
    disk_size_lba:  int = 0                          # total LBAs in image (image_size / 512)
    parse_errors:   List[str] = field(default_factory=list)

    def classify_offset(self, byte_offset: int) -> BoundaryContext:
        """
        Return the boundary context for a given byte offset.

        INSIDE   — the offset falls within at least one known partition
        BEYOND   — the offset is past every known partition's end byte
        UNKNOWN  — partition table could not be parsed (no information)
        """
        if self.scheme == "UNKNOWN" or not self.partitions:
            return BoundaryContext.UNKNOWN

        for p in self.partitions:
            if p.start_offset <= byte_offset <= p.end_offset:
                return BoundaryContext.INSIDE

        # Check whether the offset is simply before the first partition
        # (MBR gap, GPT header area) — also treat as INSIDE for forensics,
        # since these areas are part of the disk's "used" layout.
        first_start = min(p.start_offset for p in self.partitions)
        if byte_offset < first_start:
            return BoundaryContext.INSIDE

        # The offset is past the last partition's end — "unwritten" territory
        last_end = max(p.end_offset for p in self.partitions)
        if byte_offset > last_end:
            return BoundaryContext.BEYOND

        # Between two partitions (inter-partition gap) — treat as INSIDE
        # since the OS placed partition structures here (alignment padding etc.)
        return BoundaryContext.INSIDE

    def classify_region(self, start_byte: int, end_byte: int) -> BoundaryContext:
        """
        Classify an entire region.

        INSIDE   — the majority of the region is inside known partitions
        BEYOND   — the entire region is beyond every partition boundary
        UNKNOWN  — no partition table
        """
        if self.scheme == "UNKNOWN" or not self.partitions:
            return BoundaryContext.UNKNOWN

        last_end = max(p.end_offset for p in self.partitions)

        if start_byte > last_end:
            return BoundaryContext.BEYOND

        # If the region starts inside but extends past the last partition,
        # check whether the majority (>50%) of bytes are beyond.
        if end_byte > last_end:
            beyond_bytes  = end_byte - last_end
            total_bytes   = end_byte - start_byte + 1
            if beyond_bytes / total_bytes > 0.5:
                return BoundaryContext.BEYOND

        return BoundaryContext.INSIDE

    def to_dict(self) -> dict:
        return {
            "scheme":        self.scheme,
            "partitions":    [p.to_dict() for p in self.partitions],
            "last_used_lba": self.last_used_lba,
            "disk_size_lba": self.disk_size_lba,
            "parse_errors":  self.parse_errors,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def parse_partition_map(image_path) -> PartitionMap:
    """
    Parse the partition table from a raw disk image file.

    Tries GPT first (after reading MBR to detect protective MBR),
    then falls back to MBR-only parsing, then returns UNKNOWN.

    Parameters
    ----------
    image_path : str or Path

    Returns
    -------
    PartitionMap — never raises; errors are recorded in parse_errors
    """
    image_path = Path(image_path)
    errors: List[str] = []

    try:
        image_size = image_path.stat().st_size
    except OSError as e:
        return PartitionMap(scheme="UNKNOWN", parse_errors=[f"Cannot stat image: {e}"])

    disk_size_lba = image_size // SECTOR_SIZE

    try:
        with open(image_path, "rb") as f:
            sector0 = f.read(SECTOR_SIZE)
            sector1 = f.read(SECTOR_SIZE) if image_size >= SECTOR_SIZE * 2 else b""
    except OSError as e:
        return PartitionMap(
            scheme="UNKNOWN", disk_size_lba=disk_size_lba,
            parse_errors=[f"Cannot read image: {e}"],
        )

    # ── Check MBR signature ───────────────────────────────────────────────────
    has_mbr_sig = len(sector0) >= 512 and sector0[510:512] == MBR_SIGNATURE

    if not has_mbr_sig:
        return PartitionMap(
            scheme="UNKNOWN", disk_size_lba=disk_size_lba,
            parse_errors=["No MBR signature — not a raw partitioned image"],
        )

    # ── Check for protective MBR → GPT ────────────────────────────────────────
    mbr_entries = _parse_mbr_entries(sector0, errors)
    has_protective = any(e.part_type == MBR_PROTECTIVE_GPT for e in mbr_entries)
    has_gpt_sig    = len(sector1) >= 8 and sector1[:8] == GPT_SIGNATURE

    if has_protective or has_gpt_sig:
        # Try GPT parse
        gpt_parts, gpt_errors = _parse_gpt(image_path, image_size, errors)
        if gpt_parts:
            scheme = "HYBRID" if not has_protective else "GPT"
            last_used = max((p.end_lba for p in gpt_parts), default=0)
            return PartitionMap(
                scheme=scheme,
                partitions=gpt_parts,
                last_used_lba=last_used,
                disk_size_lba=disk_size_lba,
                parse_errors=errors + gpt_errors,
            )
        errors.extend(gpt_errors)
        errors.append("GPT parse failed — falling back to MBR")

    # ── MBR-only ──────────────────────────────────────────────────────────────
    # Expand extended partitions
    all_parts: List[PartitionEntry] = []
    extended_entry: Optional[PartitionEntry] = None

    for entry in mbr_entries:
        if entry.part_type == MBR_TYPE_EMPTY:
            continue
        if entry.part_type in MBR_TYPE_EXTENDED:
            extended_entry = entry
        else:
            all_parts.append(entry)

    if extended_entry is not None:
        logical = _parse_extended(image_path, extended_entry, len(all_parts), errors)
        all_parts.extend(logical)

    if not all_parts:
        return PartitionMap(
            scheme="MBR", disk_size_lba=disk_size_lba,
            parse_errors=errors + ["MBR has no usable partition entries"],
        )

    last_used = max(p.end_lba for p in all_parts)
    return PartitionMap(
        scheme="MBR",
        partitions=all_parts,
        last_used_lba=last_used,
        disk_size_lba=disk_size_lba,
        parse_errors=errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# MBR PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _parse_mbr_entries(
    sector0: bytes,
    errors: List[str],
) -> List[PartitionEntry]:
    """Parse the four primary MBR partition entries from sector 0."""
    entries = []
    for i in range(MBR_PART_COUNT):
        off = MBR_PART_OFFSET + i * MBR_PART_SIZE
        raw = sector0[off : off + MBR_PART_SIZE]
        if len(raw) < MBR_PART_SIZE:
            errors.append(f"MBR entry {i}: truncated")
            continue

        status, _, _, part_type, _, _, lba_start, sector_count = struct.unpack_from(
            "<B3sB3sII", raw
        )
        # status byte: 0x80 = bootable, 0x00 = not bootable, other = invalid
        is_bootable = status == 0x80
        if status not in (0x00, 0x80):
            # Invalid status byte — likely not a real partition table
            errors.append(f"MBR entry {i}: invalid status byte 0x{status:02X}")

        if part_type == MBR_TYPE_EMPTY or lba_start == 0 or sector_count == 0:
            entries.append(PartitionEntry(
                index=i, start_lba=0, end_lba=0, sector_count=0,
                part_type=MBR_TYPE_EMPTY, type_name="Empty",
                is_bootable=False, scheme="MBR",
            ))
            continue

        entries.append(PartitionEntry(
            index        = i,
            start_lba    = lba_start,
            end_lba      = lba_start + sector_count - 1,
            sector_count = sector_count,
            part_type    = part_type,
            type_name    = _mbr_type_name(part_type),
            is_bootable  = is_bootable,
            scheme       = "MBR",
        ))

    return entries


def _parse_extended(
    image_path: Path,
    extended: PartitionEntry,
    base_index: int,
    errors: List[str],
) -> List[PartitionEntry]:
    """
    Walk the linked list of EBRs (Extended Boot Records) inside an
    extended partition container.  Returns logical partition entries.
    Handles only one level of nesting (standard practice).
    """
    logical = []
    ebr_lba = extended.start_lba   # first EBR is at the start of extended partition
    extended_base_lba = extended.start_lba
    visited = set()
    idx = base_index + 4            # logical partitions start at index 5 by convention

    try:
        with open(image_path, "rb") as f:
            while ebr_lba not in visited:
                visited.add(ebr_lba)
                f.seek(ebr_lba * SECTOR_SIZE)
                ebr = f.read(SECTOR_SIZE)

                if len(ebr) < 512 or ebr[510:512] != MBR_SIGNATURE:
                    errors.append(f"EBR at LBA {ebr_lba}: invalid signature")
                    break

                # Entry 0: the logical partition (relative to this EBR)
                raw0 = ebr[MBR_PART_OFFSET : MBR_PART_OFFSET + MBR_PART_SIZE]
                _, _, _, ptype0, _, _, rel_start0, count0 = struct.unpack_from("<B3sB3sII", raw0)

                if ptype0 != MBR_TYPE_EMPTY and count0 > 0:
                    abs_start = ebr_lba + rel_start0
                    logical.append(PartitionEntry(
                        index        = idx,
                        start_lba    = abs_start,
                        end_lba      = abs_start + count0 - 1,
                        sector_count = count0,
                        part_type    = ptype0,
                        type_name    = _mbr_type_name(ptype0),
                        is_bootable  = False,
                        scheme       = "MBR",
                    ))
                    idx += 1

                # Entry 1: next EBR (relative to start of extended partition)
                raw1 = ebr[MBR_PART_OFFSET + MBR_PART_SIZE : MBR_PART_OFFSET + 2 * MBR_PART_SIZE]
                _, _, _, ptype1, _, _, rel_start1, count1 = struct.unpack_from("<B3sB3sII", raw1)

                if ptype1 in MBR_TYPE_EXTENDED and rel_start1 > 0:
                    ebr_lba = extended_base_lba + rel_start1
                else:
                    break   # no more logical partitions

    except OSError as e:
        errors.append(f"Extended partition read error: {e}")

    return logical


# ─────────────────────────────────────────────────────────────────────────────
# GPT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _parse_gpt(
    image_path: Path,
    image_size: int,
    errors: List[str],
) -> Tuple[List[PartitionEntry], List[str]]:
    """
    Parse the primary GPT header and partition entries.

    Returns (partitions, local_errors).
    Falls back to secondary GPT header if primary is damaged.
    """
    gpt_errors: List[str] = []
    partitions: List[PartitionEntry] = []

    try:
        with open(image_path, "rb") as f:
            # Primary header at LBA 1
            f.seek(GPT_HEADER_LBA * SECTOR_SIZE)
            header = f.read(92)   # minimum GPT header size

        if len(header) < 92 or header[:8] != GPT_SIGNATURE:
            gpt_errors.append("GPT primary header: bad signature")
            return [], gpt_errors

        # header layout (all LE):
        #  0-7   signature
        #  8-11  revision
        #  12-15 header size
        #  16-19 CRC32 of header
        #  20-23 reserved (must be 0)
        #  24-31 current LBA
        #  32-39 backup LBA
        #  40-47 first usable LBA
        #  48-55 last usable LBA
        #  56-71 disk GUID
        #  72-79 partition entries start LBA
        #  80-83 number of partition entries
        #  84-87 size of partition entry
        #  88-91 CRC32 of partition array

        (header_size, _, _, _, my_lba, backup_lba,
         first_usable, last_usable) = struct.unpack_from("<IIIIqqqq", header, 12)

        part_entry_lba, num_entries, entry_size = struct.unpack_from("<qII", header, 72)

        if entry_size < GPT_PART_ENTRY_SIZE_MIN:
            gpt_errors.append(
                f"GPT: entry size {entry_size} < minimum {GPT_PART_ENTRY_SIZE_MIN}"
            )
            return [], gpt_errors

        # Safety cap: never try to read more than 256 entries (spec max is 128)
        num_entries = min(num_entries, 256)

        try:
            with open(image_path, "rb") as f:
                f.seek(part_entry_lba * SECTOR_SIZE)
                raw_entries = f.read(num_entries * entry_size)
        except OSError as e:
            gpt_errors.append(f"GPT: cannot read partition entries: {e}")
            return [], gpt_errors

        idx = 0
        for i in range(num_entries):
            off = i * entry_size
            entry_raw = raw_entries[off : off + entry_size]
            if len(entry_raw) < 32:
                break

            type_guid  = entry_raw[0:16]
            first_lba  = struct.unpack_from("<q", entry_raw, 32)[0]
            last_lba   = struct.unpack_from("<q", entry_raw, 40)[0]
            attributes = struct.unpack_from("<Q", entry_raw, 48)[0]
            name_raw   = entry_raw[56:128] if len(entry_raw) >= 128 else b""
            name       = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00") or "Unknown"

            if type_guid == _GPT_TYPE_UNUSED or first_lba <= 0 or last_lba <= 0:
                continue
            if first_lba >= last_lba:
                gpt_errors.append(f"GPT entry {i}: first_lba >= last_lba, skipping")
                continue

            sector_count = last_lba - first_lba + 1
            partitions.append(PartitionEntry(
                index        = idx,
                start_lba    = first_lba,
                end_lba      = last_lba,
                sector_count = sector_count,
                part_type    = 0xFF,   # GPT uses GUIDs not type bytes
                type_name    = name,
                is_bootable  = bool(attributes & 0x04),  # "Legacy BIOS bootable" attribute
                scheme       = "GPT",
            ))
            idx += 1

    except Exception as e:
        gpt_errors.append(f"GPT parse exception: {e}")
        return [], gpt_errors

    return partitions, gpt_errors


# ─────────────────────────────────────────────────────────────────────────────
# MBR TYPE CODE → HUMAN NAME
# ─────────────────────────────────────────────────────────────────────────────

_MBR_TYPES: dict = {
    0x01: "FAT12",
    0x04: "FAT16 (<32 MB)",
    0x05: "Extended (CHS)",
    0x06: "FAT16",
    0x07: "NTFS / exFAT / HPFS",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 (LBA)",
    0x27: "Windows Recovery",
    0x39: "Plan 9",
    0x3C: "PartitionMagic",
    0x42: "Windows LDM (dynamic disk)",
    0x82: "Linux swap / Solaris",
    0x83: "Linux",
    0x84: "Hibernation / Hidden",
    0x85: "Linux Extended",
    0x86: "FAT16 volume set",
    0x87: "NTFS volume set",
    0x8E: "Linux LVM",
    0x9F: "BSD/OS",
    0xA0: "Hibernation (IBM/Toshiba)",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA8: "macOS X",
    0xA9: "NetBSD",
    0xAB: "macOS X Boot",
    0xAF: "macOS X HFS+",
    0xBE: "Solaris Boot",
    0xBF: "Solaris",
    0xDB: "CP/M / CTOS",
    0xDE: "Dell Diagnostics",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
    0xFB: "VMware VMFS",
    0xFC: "VMware swap / VMKCORE",
    0xFD: "Linux RAID auto",
    0xFE: "LANstep / PS/2 IML",
    0xFF: "XENIX bad track",
}


def _mbr_type_name(type_code: int) -> str:
    return _MBR_TYPES.get(type_code, f"Unknown (0x{type_code:02X})")
