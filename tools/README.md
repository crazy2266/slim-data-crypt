# SM4 constant-time S-box derivation

This directory contains the generators that produced the table-free
constant-time SM4 S-box used by `src/sm4/sm4_ct.c`.

## Files

- `sm4_sbox_bitsliced_derive.py`
  Derives the SM4 S-box as a pure boolean circuit from its algebraic
  structure: GF(2^8) inverse (via the tower GF(2^4)^2 and the norm trick)
  plus the SM4 affine transforms.  Everything is brute-force verified
  against the official SM4 S-box (GB/T 32907-2016) for all 256 inputs,
  then emitted as a 64-lane bitsliced circuit.

- `gen_word_sbox.py`
  Re-packs the (already verified) bitsliced circuit into the
  "4 bytes in a uint32_t" form used by `sm4_sbox_word()`.  Each bit plane
  becomes a 0x01010101-style mask; the AND/XOR/NOT structure is preserved
  (with `~x` masked back to `0x01010101`).  Re-validated for all 256 bytes.

## Regenerating

    python3 sm4_sbox_bitsliced_derive.py   # prints constants, verifies 256/256
    python3 gen_word_sbox.py               # writes sm4_sbox_word_generated.c, verifies 256/256

## Why not bitslicing?

The bundled `sm4_sbox_word()` is *word-packed byte-parallel*, not
cross-block bitslicing: one `uint32_t` holds one SM4 round-function word
(4 bytes), so a single block can be processed without gathering 64 blocks.
This keeps the state in registers and avoids the interleave/deinterleave
overhead that made an earlier "4-group" bitslice layout slower than the
scalar table lookup.
