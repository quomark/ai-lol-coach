# ROFL Decoding Progress & Next Steps

## Current State (2026-03-14)

### What Works
| Component | Status | File |
|-----------|--------|------|
| ROFL v2 parser | Working | `ml/parsers/rofl_parser.py` |
| Frame/packet parser | Working | `ml/parsers/chunk_parser.py` |
| 0x025B movement decoder | 100% (32,037/32,037) | `ml/parsers/movement_decoder.py` |
| 0x0228 state decoder | 100% (57,523/57,523) | `ml/emulator/decode_0228.py` |
| Game state reconstruction | Working | `ml/parsers/game_state.py` |
| Coaching analyzer | Draft | `ml/parsers/coaching_analyzer.py` |
| Cipher extraction tool | Working | `ml/tools/extract_ciphers.py` |
| Runtime dump script (Win) | Created, untested | `ml/emulator/dump_runtime.py` |

### Position Coordinates: FIXED (2026-03-14)
**Previously the #1 blocker — now resolved.**
- macOS runtime dump captured via `ml/tools/macos_dump.py` (Mach VM APIs, no lldb needed)
- LUT extracted from runtime dump: 256-byte permutation table at offset 0x1EF5228
- Same LUT works for both 0x025B and 0x0228 decoders
- LUT is now embedded directly in code — no binary dump file dependency
- Positions verified: 10 champions show distinct positions, blue/red team separation works
- Coordinate system: unsigned 14-bit (0-16383), mapping to LoL map (~15000x15000 units)

## Key RVAs (Windows Binary — for reference)

| What | RVA | Notes |
|------|-----|-------|
| Packet dispatcher | 0x0066E5F0 | Entry point for all packet processing |
| 0x025B deserializer | 0x00DE3410 | Movement packet decoder |
| 0x0228 deserializer | 0x00E748B0 | State/entity packet decoder |
| LUT (used by 0x0228) | 0x19B60F0 | 256-byte lookup table |
| Function pointer table | 0x019B6200 | 776 entries, stride 48 bytes |
| VARINT_DEC function | 0x01150B40 | Shared varint reader |
| f10 cipher (0x025B) | 0x00FAF080 | Position field: `sub 0x62, bitswap, add 7` |

## Architecture Overview

```
.rofl file
  → ROFLParser (decompress payload frames)
    → chunk_parser (extract packets: id, param, timestamp, data)
      → MovementDecoder (0x025B packets → entity_id, x, z, speed)
      → Decoder0228 (0x0228 packets → entity state: f0-f9)
        → GameStateBuilder (combine into per-champion timelines)
          → CoachingAnalyzer (generate insights)
```

### Packet Format
- Each packet: 4-byte schema (little-endian) + encrypted payload
- Schema bits select "type code" per field → determines if field is read or default
- Each field has its own cipher (combinations of add, xor, ror, bitswap, LUT)
- Varints use protobuf-like encoding (7-bit chunks, MSB continuation)

### Key Decoded Fields
**0x025B (movement):** entity_id, x, z, speed, movement_type, waypoint_count
**0x0228 (state):** f0 (1-byte), f1 (entity_id), f3 (float), f4 (varint), f5 (death-related), f6-f7, f8 (gold/XP or killer_id on death), f9 (float)

### Death Detection
- f8 normally increases over time (cumulative stat)
- On death: f8 drops from >500 to <200 (value = killer's entity_id)
- Stays low for death timer duration (≥5 seconds)
- Currently ~2x overcount (102 detected vs ~47 actual)

### Team Detection
- Kill graph from f8_after values: kills always cross-team
- BFS graph coloring splits entities into two teams
- Early position average determines blue (lower coords) vs red (upper coords)

## File Inventory

### Core Pipeline (keep these)
- `ml/parsers/rofl_parser.py` — ROFL v2 file format parser
- `ml/parsers/chunk_parser.py` — Payload frame + packet extractor
- `ml/parsers/movement_decoder.py` — 0x025B movement packet decoder
- `ml/emulator/decode_0228.py` — 0x0228 state packet decoder
- `ml/parsers/game_state.py` — Game state reconstruction
- `ml/parsers/coaching_analyzer.py` — Coaching insights generator
- `ml/tools/extract_ciphers.py` — Auto-extract cipher params from binary dumps

### Dump Tools
- `ml/tools/macos_dump.py` — macOS runtime dump via Mach VM APIs (working, used to extract LUT)
- `ml/tools/scan_macos_dump.py` — Scan binary dumps for LUT/cipher tables
- `ml/emulator/dump_via_suspended.py` — CREATE_SUSPENDED dump (Windows)
- `ml/emulator/dump_runtime.py` — Runtime dump (Windows, needs Vanguard bypass)

### Binary Data
- `ml/data/macos_lut.bin` — 256-byte LUT extracted from macOS runtime dump (the key cipher table)
- `ml/data/league_macos_dump.bin` — 161MB macOS runtime dump (gitignored, not needed — LUT is embedded in code)

### Research/Analysis Scripts (in ml/emulator/)
Many analysis scripts were created during reverse engineering. Most are one-off experiments.
Key ones: `find_all_deserializers.py`, `find_decrypt_rvas.py`, `unicorn_emulator.py`

## Next Steps

1. **Fix death detection overcount** — currently ~2x (102 detected vs ~47 actual). Need better heuristics for f8 drop detection.
2. **Improve coaching analyzer** — currently draft. With working positions + state data, can now generate real insights (CS/min, positioning, death timing, etc.)
3. **Build user-facing pipeline** — end-to-end: upload .rofl → parse → analyze → show coaching feedback
4. **Test with more replays** — verify decoder works across different patches and game modes
