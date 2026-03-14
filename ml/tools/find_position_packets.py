"""
Analyze ALL packet types in a ROFL replay to find which ones contain position data.

Goals:
1. Distribution of all packet_id values
2. For top 10 (excl 0x025B): check for 14-bit packed coords, champion net_ids
3. Look for WaypointGroup-style packets with repeated (entity, x, z) tuples
"""

import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Add project root to path
proj = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(proj))

from ml.parsers.rofl_parser import ROFLParser
from ml.parsers.chunk_parser import parse_payload_frames

REPLAY = r"C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays\TW2-396324158.rofl"
BINARY = str(proj / "ml" / "data" / "league_unpacked_patched.bin")

# Champion net_ids (from memory file)
CHAMP_NETIDS = set(range(0x400000AE, 0x400000B8))  # 10 champions
CHAMP_NETID_MIN = 0x400000AE
CHAMP_NETID_MAX = 0x400000B7

def try_read_varint(data, pos):
    """Read a raw varint (no cipher) from data at pos. Returns (value, new_pos) or None."""
    result = 0
    shift = 0
    start = pos
    while pos < len(data) and shift < 35:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return result, pos
    return None

def check_14bit_coords(val):
    """Check if a value could be 14-bit packed XZ coordinates."""
    x = val & 0x3FFF
    z = (val >> 14) & 0x3FFF
    # LoL map is roughly 0-15000 units, so valid coords are in that range
    return 0 < x < 16000 and 0 < z < 16000

def main():
    print("=" * 80)
    print("PACKET TYPE ANALYSIS - Finding Position Data")
    print("=" * 80)

    # Parse replay
    print(f"\nParsing replay: {REPLAY}")
    parser = ROFLParser(REPLAY)
    frames = parser.decompress_payload_frames()
    print(f"  Decompressed {len(frames)} frames")

    result = parse_payload_frames(frames)
    all_packets = [p for f in result.frames for p in f.packets]
    print(f"  Total packets: {len(all_packets):,}")

    # ===== STEP 1: Distribution of ALL packet_id values =====
    print(f"\n{'=' * 80}")
    print("STEP 1: Packet ID Distribution (top 30)")
    print(f"{'=' * 80}")

    pid_counter = Counter(p.packet_id for p in all_packets)
    pid_sizes = defaultdict(list)
    pid_params = defaultdict(set)

    for p in all_packets:
        pid_sizes[p.packet_id].append(p.size)
        pid_params[p.packet_id].add(p.param)

    print(f"\n  {'PktID':>8s} {'Hex':>8s} | {'Count':>8s} | {'AvgSz':>6s} | {'MinSz':>5s} | {'MaxSz':>6s} | {'#Params':>7s}")
    print(f"  {'-' * 70}")

    top30 = pid_counter.most_common(30)
    for pid, count in top30:
        sizes = pid_sizes[pid]
        avg_sz = sum(sizes) / len(sizes)
        min_sz = min(sizes)
        max_sz = max(sizes)
        n_params = len(pid_params[pid])
        print(f"  {pid:>8d} 0x{pid:04X} | {count:>8,} | {avg_sz:>6.1f} | {min_sz:>5d} | {max_sz:>6d} | {n_params:>7d}")

    print(f"\n  Total unique packet IDs: {len(pid_counter)}")

    # ===== STEP 2: Champion net_id analysis =====
    print(f"\n{'=' * 80}")
    print("STEP 2: Champion NetID Analysis (param field)")
    print(f"{'=' * 80}")
    print(f"  Champion net_ids: 0x{CHAMP_NETID_MIN:08X} - 0x{CHAMP_NETID_MAX:08X}")

    # Which packet types have champion net_ids in param?
    champ_pid_counts = Counter()
    for p in all_packets:
        if p.param in CHAMP_NETIDS:
            champ_pid_counts[p.packet_id] += 1

    if champ_pid_counts:
        print(f"\n  Packet types with champion net_ids in param:")
        print(f"  {'PktID':>8s} {'Hex':>8s} | {'ChampPkts':>10s} | {'TotalPkts':>10s} | {'%Champ':>6s}")
        print(f"  {'-' * 55}")
        for pid, count in champ_pid_counts.most_common(20):
            total = pid_counter[pid]
            pct = count / total * 100
            print(f"  {pid:>8d} 0x{pid:04X} | {count:>10,} | {total:>10,} | {pct:>5.1f}%")
    else:
        print("\n  No packets found with exact champion net_ids in param field.")
        # Check broader range
        print("  Checking broader param ranges...")
        param_range_counter = Counter()
        for p in all_packets:
            if 0x40000000 <= p.param <= 0x400FFFFF:
                param_range_counter[p.packet_id] += 1
        if param_range_counter:
            print(f"\n  Packet types with params in 0x40000000-0x400FFFFF range:")
            for pid, count in param_range_counter.most_common(20):
                total = pid_counter[pid]
                sample_params = sorted(p.param for p in all_packets if p.packet_id == pid and 0x40000000 <= p.param <= 0x400FFFFF)[:5]
                param_hex = " ".join(f"0x{p:08X}" for p in sample_params)
                print(f"    0x{pid:04X}: {count:>6,}/{total:>6,}  samples: {param_hex}")

    # ===== STEP 3: Deep analysis of top 10 (excl 0x025B) =====
    print(f"\n{'=' * 80}")
    print("STEP 3: Deep Analysis of Top 10 Packet Types (excl 0x025B)")
    print(f"{'=' * 80}")

    top10_excl = [(pid, c) for pid, c in pid_counter.most_common(40) if pid != 0x025B][:10]

    for pid, count in top10_excl:
        print(f"\n  --- Packet 0x{pid:04X} (decimal {pid}) ---")
        print(f"  Count: {count:,}, Avg size: {sum(pid_sizes[pid])/len(pid_sizes[pid]):.1f}")

        # Sample unique params
        params = sorted(pid_params[pid])
        print(f"  Unique params: {len(params)}")
        if len(params) <= 20:
            print(f"  Params: {', '.join(f'0x{p:08X}' for p in params)}")
        else:
            print(f"  Param range: 0x{min(params):08X} - 0x{max(params):08X}")
            print(f"  Sample params: {', '.join(f'0x{p:08X}' for p in params[:10])}")

        # Check for champion net_ids in param
        champ_match = [p for p in params if p in CHAMP_NETIDS]
        if champ_match:
            print(f"  *** CHAMPION NET_IDS FOUND: {', '.join(f'0x{p:08X}' for p in champ_match)}")

        # Sample payloads - look for coordinate-like data
        sample_pkts = [p for p in all_packets if p.packet_id == pid][:50]

        # Check for raw varints that could be 14-bit coords
        coord_hits = 0
        for pkt in sample_pkts:
            if len(pkt.data) < 2:
                continue
            # Try reading varints at various offsets
            for off in range(min(len(pkt.data) - 1, 20)):
                vr = try_read_varint(pkt.data, off)
                if vr:
                    val, _ = vr
                    if val > 0 and check_14bit_coords(val):
                        coord_hits += 1
                        break

        if coord_hits > 0:
            print(f"  Raw varint 14-bit coord matches: {coord_hits}/{len(sample_pkts)} samples")

        # Show first 5 payloads hex
        print(f"  Sample payloads:")
        for i, pkt in enumerate(sample_pkts[:5]):
            hex_str = pkt.data[:48].hex()
            hex_fmt = " ".join(hex_str[j:j+2] for j in range(0, len(hex_str), 2))
            print(f"    [{i}] param=0x{pkt.param:08X} t={pkt.timestamp:.2f}s sz={pkt.size:>4d}: {hex_fmt}")

    # ===== STEP 4: WaypointGroup search =====
    print(f"\n{'=' * 80}")
    print("STEP 4: WaypointGroup-style packet search")
    print(f"{'=' * 80}")
    print("  Looking for packets with count byte + repeated (entity, x, z) tuples...")

    for pid, count in pid_counter.most_common(30):
        if pid == 0x025B:
            continue
        sample_pkts = [p for p in all_packets if p.packet_id == pid][:20]

        # Check if payload starts with a small count byte followed by structured data
        pattern_matches = 0
        for pkt in sample_pkts:
            d = pkt.data
            if len(d) < 8:
                continue
            first_byte = d[0]
            # Count byte should be small (1-20 entities)
            if 1 <= first_byte <= 20:
                # Check if remaining size is divisible by entry size
                remaining = len(d) - 1
                for entry_sz in (6, 8, 10, 12):
                    if remaining > 0 and remaining % entry_sz == 0:
                        n_entries = remaining // entry_sz
                        if n_entries == first_byte:
                            pattern_matches += 1
                            break

        if pattern_matches > 0:
            print(f"\n  0x{pid:04X}: {pattern_matches}/{len(sample_pkts)} packets match count+tuples pattern")
            for pkt in sample_pkts[:3]:
                hex_str = pkt.data[:48].hex()
                hex_fmt = " ".join(hex_str[j:j+2] for j in range(0, len(hex_str), 2))
                print(f"    param=0x{pkt.param:08X} sz={pkt.size}: {hex_fmt}")

    # ===== STEP 5: Frequency analysis =====
    print(f"\n{'=' * 80}")
    print("STEP 5: Frequency Analysis (packets per second)")
    print(f"{'=' * 80}")

    # Get game duration from timestamps
    all_times = [p.timestamp for p in all_packets if p.timestamp > 0]
    if all_times:
        game_duration = max(all_times)
        print(f"  Game duration: {game_duration:.1f}s ({game_duration/60:.1f} min)")

        print(f"\n  {'PktID':>8s} | {'Count':>8s} | {'Pkts/sec':>8s} | {'Description':>30s}")
        print(f"  {'-' * 65}")
        for pid, count in pid_counter.most_common(20):
            pps = count / game_duration if game_duration > 0 else 0
            desc = ""
            if pid == 0x025B:
                desc = "MOVEMENT (known)"
            elif pps > 1 and pps < 200:
                # Count unique params to see if it's per-entity
                n_params = len(pid_params[pid])
                if n_params > 0:
                    per_entity_pps = pps / n_params
                    desc = f"~{per_entity_pps:.1f}/s/entity ({n_params} entities)"
            print(f"  0x{pid:04X}    | {count:>8,} | {pps:>8.1f} | {desc}")

    # ===== STEP 6: Param-based entity grouping for position candidates =====
    print(f"\n{'=' * 80}")
    print("STEP 6: Position Candidate Summary")
    print(f"{'=' * 80}")

    print("\n  Criteria for position packets:")
    print("    - Has params matching entity/champion IDs")
    print("    - Frequent enough (>1/s per entity)")
    print("    - Payload contains coordinate-like data")
    print()

    # For each candidate packet type, show params that appear most frequently
    candidates = []
    for pid, count in pid_counter.most_common(30):
        if pid == 0x025B:
            continue
        pps = count / game_duration if game_duration > 0 else 0
        n_params = len(pid_params[pid])

        # Look for entity-like behavior: multiple params, moderate frequency
        if n_params >= 5 and pps >= 5:
            per_entity = pps / n_params
            candidates.append((pid, count, pps, n_params, per_entity))

    if candidates:
        print(f"  {'PktID':>8s} | {'Count':>8s} | {'Pkts/s':>7s} | {'#Params':>7s} | {'Per-ent/s':>9s}")
        print(f"  {'-' * 55}")
        for pid, count, pps, n_params, per_ent in sorted(candidates, key=lambda x: -x[4]):
            print(f"  0x{pid:04X}    | {count:>8,} | {pps:>7.1f} | {n_params:>7d} | {per_ent:>9.2f}")
    else:
        print("  No strong candidates found with standard criteria.")

    # ===== STEP 7: Check 0x025B specifically for context =====
    print(f"\n{'=' * 80}")
    print("STEP 7: 0x025B Reference Stats")
    print(f"{'=' * 80}")

    pkt_025b = [p for p in all_packets if p.packet_id == 0x025B]
    if pkt_025b:
        print(f"  Count: {len(pkt_025b):,}")
        params_025b = set(p.param for p in pkt_025b)
        print(f"  Unique params: {len(params_025b)}")
        print(f"  Param range: 0x{min(params_025b):08X} - 0x{max(params_025b):08X}")
        print(f"  Sample params: {', '.join(f'0x{p:08X}' for p in sorted(params_025b)[:10])}")
        sizes_025b = [p.size for p in pkt_025b]
        print(f"  Size range: {min(sizes_025b)} - {max(sizes_025b)}, avg: {sum(sizes_025b)/len(sizes_025b):.1f}")

    print(f"\n{'=' * 80}")
    print("DONE")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
