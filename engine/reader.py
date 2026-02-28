"""
reader.py
─────────
Streams a raw disk image (.dd / .img / .raw) in fixed-size blocks.
Never loads the whole file into memory — yields one block at a time.

Usage:
    from engine.reader import BlockReader

    for block in BlockReader("suspect.dd"):
        print(block.id, block.offset, len(block.data))
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


BLOCK_SIZE = 4096   # 4 KB — one NTFS/ext4 cluster


@dataclass
class Block:
    id:     int     # sequential block number, 0-indexed
    offset: int     # byte offset in the image (id * BLOCK_SIZE)
    data:   bytes   # raw bytes, len <= BLOCK_SIZE (last block may be shorter)


class BlockReader:
    """
    Iterate over a disk image one 4 KB block at a time.

    Parameters
    ----------
    path : str | Path
        Path to the raw disk image.
    block_size : int
        Bytes per block. Default 4096.
    start_block : int
        First block to yield (skip earlier blocks). Default 0.
    end_block : int | None
        Stop after this block id (inclusive). None = read to EOF.
    """

    def __init__(
        self,
        path:        str | Path,
        block_size:  int       = BLOCK_SIZE,
        start_block: int       = 0,
        end_block:   int | None = None,
    ):
        self.path        = Path(path)
        self.block_size  = block_size
        self.start_block = start_block
        self.end_block   = end_block

        if not self.path.exists():
            raise FileNotFoundError(f"Image not found: {self.path}")

        self.image_size  = self.path.stat().st_size
        self.total_blocks = (self.image_size + block_size - 1) // block_size

    # ── Iterator ──────────────────────────────────────────────────────────────

    def __iter__(self) -> Iterator[Block]:
        block_id = self.start_block
        byte_offset = self.start_block * self.block_size

        with open(self.path, "rb") as f:
            if byte_offset > 0:
                f.seek(byte_offset)

            while True:
                # Respect end_block ceiling
                if self.end_block is not None and block_id > self.end_block:
                    break

                data = f.read(self.block_size)
                if not data:
                    break

                yield Block(
                    id     = block_id,
                    offset = block_id * self.block_size,
                    data   = data,
                )

                block_id += 1

    # ── Convenience ───────────────────────────────────────────────────────────

    def read_block(self, block_id: int) -> Block:
        """Random-access read of a single block by id."""
        offset = block_id * self.block_size
        if offset >= self.image_size:
            raise IndexError(f"Block {block_id} out of range (image has {self.total_blocks} blocks).")

        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read(self.block_size)

        return Block(id=block_id, offset=offset, data=data)

    def __repr__(self) -> str:
        return (
            f"<BlockReader path={self.path.name!r} "
            f"size={self.image_size} blocks={self.total_blocks}>"
        )
