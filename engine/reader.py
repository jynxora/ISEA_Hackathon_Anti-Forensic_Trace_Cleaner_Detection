"""
reader.py
─────────
Streams a raw disk image in fixed-size blocks.
Never loads the full file into memory — yields one block at a time.

Directly mirrors the logic of the team's block_reader.py
(from backend.scanner.block_reader) with added:
- Random-access read_block() for hex viewer use
- Total block count pre-computation for progress reporting
- Configurable start/end block range for partial scans

Usage:
    from engine.reader import BlockReader, BLOCK_SIZE

    for block in BlockReader("suspect.dd"):
        print(block.id, block.offset, len(block.data))
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


BLOCK_SIZE = 512          # matches team's config.BLOCK_SIZE
READ_CHUNK_BLOCKS = 1024  # read 512 KB at a time for I/O efficiency


@dataclass
class Block:
    id:     int     # sequential block number, 0-indexed
    offset: int     # byte offset in image = id * BLOCK_SIZE
    data:   bytes   # raw bytes (last block may be shorter than BLOCK_SIZE)


class BlockReader:
    """
    Iterate over a raw disk image one block at a time.

    Mirrors team's read_blocks(file_path) generator, wrapped in a
    class to expose total_blocks and random-access reads.
    """

    def __init__(
        self,
        path:        str | Path,
        block_size:  int        = BLOCK_SIZE,
        start_block: int        = 0,
        end_block:   int | None = None,
    ):
        self.path        = Path(path)
        self.block_size  = block_size
        self.start_block = start_block
        self.end_block   = end_block

        if not self.path.exists():
            raise FileNotFoundError(f"Image not found: {self.path}")

        self.image_size   = self.path.stat().st_size
        self.total_blocks = (self.image_size + block_size - 1) // block_size

    def __iter__(self) -> Iterator[Block]:
        """
        Yields Block objects from start_block to end_block (or EOF).

        Reads in large chunks (READ_CHUNK_BLOCKS * block_size bytes) to
        minimise syscall overhead — ~5x faster than one f.read(512) per block.
        """
        block_id    = self.start_block
        byte_offset = self.start_block * self.block_size
        chunk_size  = READ_CHUNK_BLOCKS * self.block_size

        try:
            with open(self.path, "rb") as f:
                if byte_offset > 0:
                    f.seek(byte_offset)

                while True:
                    if self.end_block is not None and block_id > self.end_block:
                        break

                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for i in range(0, len(chunk), self.block_size):
                        if self.end_block is not None and block_id > self.end_block:
                            break
                        data = chunk[i : i + self.block_size]
                        if not data:
                            break
                        yield Block(
                            id     = block_id,
                            offset = block_id * self.block_size,
                            data   = data,
                        )
                        block_id += 1

        except FileNotFoundError:
            # Mirror team's block_reader behaviour: silently return on missing file
            return

    def read_block(self, block_id: int) -> Block:
        """Random-access read of a single block by ID (used by hex viewer)."""
        offset = block_id * self.block_size
        if offset >= self.image_size:
            raise IndexError(
                f"Block {block_id} out of range "
                f"(image has {self.total_blocks} blocks)."
            )
        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read(self.block_size)
        return Block(id=block_id, offset=offset, data=data)

    def __repr__(self) -> str:
        return (
            f"<BlockReader path={self.path.name!r} "
            f"size={self.image_size} "
            f"blocks={self.total_blocks}>"
        )
