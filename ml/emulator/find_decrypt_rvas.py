"""
Find movement decryption function RVAs in our League binary dump (patch 16.5)
using known RVAs from Mowokuma's patch 5-5 config as reference.

Known from patch 5-5:
  alloc1_rva:    0xF60420
  alloc2_rva:    0x1DE520
  skip_rva:      0xFCA950
  mov_decrypt:   rva_start=0xE45710, rva_end=0xE45B35, netid=980
  ward_spawn:    rva_start=0xE3D7B0, rva_end=0xE3FD61, netid=571

Our binary:
  Base: 0x7FF76C300000 (RVA = file offset)
  .text: 0x1000 - ~0x18BD000
  PKT_0x0425 constructor: RVA 0x00DFFD80
  PKT_0x0425 vtable:      RVA 0x019B9BC0
  PKT_0x0425 vtable[1] (Deserialize): RVA 0x00F60EF0
  Constructor region: 0xDFF000-0xE10000 (~299 constructors)
"""

import struct
import sys
import os
from pathlib import Path
from collections import defaultdict

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

DUMP_PATH = Path(__file__).resolve().parent.parent / "data" / "league_unpacked_patched.bin"
BASE_ADDR = 0x7FF76C300000

# Known from our previous analysis
KNOWN_0425_CONSTRUCTOR = 0x00DFFD80
KNOWN_0425_VTABLE = 0x019B9BC0
CONSTRUCTOR_REGION_START = 0x00DFF000
CONSTRUCTOR_REGION_END = 0x00E10000

# Target packet IDs from replay
TARGET_IDS = [0x0458, 0x0092, 0x0228, 0x025B, 0x047A]


def load_binary():
    p = Path(DUMP_PATH)
    if not p.exists():
        print(f"ERROR: Binary not found at {p}")
        sys.exit(1)
    data = p.read_bytes()
    print(f"Loaded: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)")
    return data


def rva_to_va(rva):
    return BASE_ADDR + rva


def va_to_rva(va):
    return va - BASE_ADDR


# ═══════════════════════════════════════════════════════════════
# APPROACH 1: Enumerate ALL packet constructors in the region
# ═══════════════════════════════════════════════════════════════

def find_all_constructors(data):
    """
    Find all packet constructors in the 0xDFF000-0xE10000 region.
    Each constructor stores a packet_id at [this+0x08] via:
      mov word ptr [rcx+0x08], <imm16>    (66 C7 41 08 xx xx)
      or mov dword ptr [rcx+0x08], <imm32> (C7 41 08 xx xx xx xx)
      or mov word ptr [rax+0x08], ...
    and sets a vtable at [this+0x00] via LEA.
    """
    print(f"\n{'='*80}")
    print("APPROACH 1: Enumerate packet constructors")
    print(f"{'='*80}")

    region = data[CONSTRUCTOR_REGION_START:CONSTRUCTOR_REGION_END]
    region_size = len(region)
    constructors = []

    # Pattern 1: mov word ptr [reg+0x08], imm16
    # 66 C7 41 08 xx xx  (reg=rcx, disp=0x08)
    # 66 C7 40 08 xx xx  (reg=rax, disp=0x08)
    # 66 C7 43 08 xx xx  (reg=rbx, disp=0x08)
    # Pattern 2: mov dword ptr [reg+0x08], imm32
    # C7 41 08 xx xx xx xx

    for i in range(region_size - 6):
        rva = CONSTRUCTOR_REGION_START + i
        pkt_id = None

        # 66 C7 4x 08 xx xx - mov word ptr [reg+0x08], imm16
        if region[i] == 0x66 and region[i+1] == 0xC7:
            modrm = region[i+2]
            mod = (modrm >> 6) & 3
            reg_field = (modrm >> 3) & 7
            rm = modrm & 7
            if reg_field == 0 and mod == 1:  # mod=01 (disp8), /0 = mov
                disp = region[i+3]
                if disp == 0x08:
                    pkt_id = struct.unpack_from("<H", region, i+4)[0]
                    if 0 < pkt_id < 0x1000:
                        constructors.append((rva, pkt_id, "mov word [reg+0x08]"))

        # C7 4x 08 xx xx xx xx - mov dword ptr [reg+0x08], imm32
        if i + 7 <= region_size and region[i] == 0xC7:
            modrm = region[i+1]
            mod = (modrm >> 6) & 3
            reg_field = (modrm >> 3) & 7
            rm = modrm & 7
            if reg_field == 0 and mod == 1:  # mod=01 (disp8), /0 = mov
                disp = region[i+2]
                if disp == 0x08:
                    val = struct.unpack_from("<I", region, i+3)[0]
                    if 0 < val < 0x1000:
                        pkt_id = val
                        constructors.append((rva, pkt_id, "mov dword [reg+0x08]"))

    # Deduplicate: group by packet_id, keep first occurrence
    seen = {}
    for rva, pkt_id, pattern in constructors:
        if pkt_id not in seen:
            seen[pkt_id] = (rva, pattern)

    sorted_ids = sorted(seen.keys())
    print(f"\nFound {len(sorted_ids)} unique packet IDs in constructor region")
    print(f"ID range: 0x{min(sorted_ids):04X} - 0x{max(sorted_ids):04X}")

    # Show all
    print(f"\nAll packet IDs:")
    for i, pkt_id in enumerate(sorted_ids):
        rva, pattern = seen[pkt_id]
        marker = ""
        if pkt_id in TARGET_IDS:
            marker = " <<< TARGET"
        if pkt_id == 0x0425:
            marker = " <<< PKT_0x0425 (known)"
        if pkt_id == 980:
            marker = " <<< mov_decrypt netid (5-5)"
        if pkt_id == 571:
            marker = " <<< ward_spawn netid (5-5)"
        print(f"  [{i+1:3d}] ID=0x{pkt_id:04X} ({pkt_id:5d})  constructor @ RVA 0x{rva:08X}  ({pattern}){marker}")

    return seen


def find_vtable_for_constructor(data, constructor_rva):
    """
    Given a constructor RVA, find the FINAL (derived class) vtable it sets
    at [this+0x00].

    In C++ constructors, the base class vtable is set first, then overwritten
    by the derived class vtable. We need to find the LAST LEA-to-rdata followed
    by a store to [reg] (vtable pointer write).

    We search the entire function containing the constructor (from function
    start to the ret instruction).
    """
    # Find function start by scanning backwards for CC padding
    func_start = constructor_rva
    for off in range(1, 300):
        pos = constructor_rva - off
        if pos < 0:
            break
        if data[pos] == 0xCC and pos > 0 and data[pos-1] == 0xCC:
            func_start = pos + 1
            break
        # Common prologue patterns
        if pos >= 3:
            if data[pos] == 0x48 and data[pos+1] == 0x89 and data[pos+2] == 0x5C and data[pos+3] == 0x24:
                func_start = pos
                break
            if data[pos] == 0x40 and data[pos+1] == 0x53:
                func_start = pos
                break

    # Find function end (search for ret = 0xC3 after int3 padding, or just cap at +500)
    func_end = min(len(data), constructor_rva + 500)
    for off in range(constructor_rva + 10, func_end):
        if data[off] == 0xC3:
            func_end = off + 1
            break

    search_region = data[func_start:func_end]

    # Collect ALL LEA instructions pointing to .rdata/.data that are followed
    # by a store to [reg] (vtable write pattern)
    vtable_candidates = []
    for i in range(len(search_region) - 7):
        # 48 8D xx [rip+disp32] or 4C 8D xx [rip+disp32]
        prefix = search_region[i]
        if prefix not in (0x48, 0x4C):
            continue
        if search_region[i+1] != 0x8D:
            continue
        modrm = search_region[i+2]
        if (modrm & 0xC7) != 0x05:  # not RIP-relative
            continue

        disp = struct.unpack_from("<i", search_region, i+3)[0]
        target_rva = (func_start + i + 7) + disp
        # Must point to .rdata or .data section
        if not (0x18BD000 <= target_rva < len(data)):
            continue

        # Check if followed by a store to [reg] within next 15 bytes
        # 48 89 xx or 4C 89 xx where modrm indicates [reg] (mod=00)
        is_vtable_write = False
        for j in range(i + 7, min(i + 22, len(search_region) - 3)):
            b0 = search_region[j]
            if b0 in (0x48, 0x4C, 0x49) and search_region[j+1] == 0x89:
                modrm2 = search_region[j+2]
                mod2 = (modrm2 >> 6) & 3
                rm2 = modrm2 & 7
                if mod2 == 0 and rm2 in (0, 1, 3, 6, 7):  # [rax/rcx/rbx/rsi/rdi]
                    is_vtable_write = True
                    break

        vtable_candidates.append((target_rva, func_start + i, is_vtable_write))

    # Return the LAST vtable candidate with a confirmed store, or the last one overall
    confirmed = [v for v in vtable_candidates if v[2]]
    if confirmed:
        return confirmed[-1][0]  # Last confirmed vtable write
    elif vtable_candidates:
        return vtable_candidates[-1][0]  # Last candidate
    return None


def read_vtable_entries(data, vtable_rva, count=10):
    """Read function pointers from a vtable in the binary dump.
    Since this is a dump at a known base, pointers are VAs that need conversion to RVAs."""
    entries = []
    for i in range(count):
        offset = vtable_rva + i * 8
        if offset + 8 > len(data):
            break
        va = struct.unpack_from("<Q", data, offset)[0]
        if va == 0:
            entries.append(None)
        else:
            rva = va - BASE_ADDR
            if 0 < rva < len(data):
                entries.append(rva)
            else:
                entries.append(None)
    return entries


def approach1_full(data):
    """Full Approach 1: enumerate constructors, find vtables, get deserializers."""
    constructors = find_all_constructors(data)

    print(f"\n{'='*80}")
    print("APPROACH 1b: Find vtables and deserializers for key packet IDs")
    print(f"{'='*80}")

    # Focus on target IDs + a few extras for comparison
    interesting_ids = TARGET_IDS + [0x0425, 980, 571]
    # Also add nearby IDs to 980 and 571 (in case netids shifted)
    for base_id in [980, 571]:
        for delta in range(-5, 6):
            nid = base_id + delta
            if nid > 0 and nid not in interesting_ids:
                interesting_ids.append(nid)

    # Actually, let's process ALL constructors to find vtables
    print(f"\nProcessing all {len(constructors)} constructors for vtables...")
    results = {}
    for pkt_id, (con_rva, pattern) in sorted(constructors.items()):
        vtable_rva = find_vtable_for_constructor(data, con_rva)
        if vtable_rva:
            entries = read_vtable_entries(data, vtable_rva, count=3)
            deser_rva = entries[1] if len(entries) > 1 and entries[1] else None
            results[pkt_id] = {
                'constructor_rva': con_rva,
                'vtable_rva': vtable_rva,
                'vtable_entries': entries,
                'deserialize_rva': deser_rva,
            }

    print(f"\nFound vtables for {len(results)}/{len(constructors)} packet IDs")

    # Show interesting ones
    print(f"\n--- Key packet IDs ---")
    for pkt_id in sorted(interesting_ids):
        if pkt_id in results:
            r = results[pkt_id]
            deser = f"0x{r['deserialize_rva']:08X}" if r['deserialize_rva'] else "N/A"
            print(f"  ID=0x{pkt_id:04X} ({pkt_id:5d}): vtable=0x{r['vtable_rva']:08X}, "
                  f"deserialize={deser}")
        elif pkt_id in constructors:
            print(f"  ID=0x{pkt_id:04X} ({pkt_id:5d}): constructor found, no vtable")
        else:
            print(f"  ID=0x{pkt_id:04X} ({pkt_id:5d}): NOT FOUND in constructors")

    # Show ALL results for target IDs
    print(f"\n--- Target replay packet IDs ---")
    for pkt_id in TARGET_IDS:
        if pkt_id in results:
            r = results[pkt_id]
            print(f"\n  PKT_0x{pkt_id:04X}:")
            print(f"    Constructor: 0x{r['constructor_rva']:08X}")
            print(f"    Vtable:      0x{r['vtable_rva']:08X}")
            print(f"    Vtable entries:")
            for j, e in enumerate(r['vtable_entries']):
                label = ["destructor", "deserialize", "vfunc2"][j] if j < 3 else f"vfunc{j}"
                if e:
                    print(f"      [{j}] {label}: 0x{e:08X}")
                else:
                    print(f"      [{j}] {label}: NULL/invalid")

    # Now look for the "movement-like" deserializer
    # In patch 5-5, the mov_decrypt function is ~1061 bytes long
    # and writes to struct+0x10 (pointer) and struct+0x18 (size)
    # Let's check which deserializers are in the ~1000 byte size range
    print(f"\n--- Deserializers similar to mov_decrypt (size ~1000 bytes) ---")
    deser_rvas = set()
    for pkt_id, r in results.items():
        if r['deserialize_rva']:
            deser_rvas.add(r['deserialize_rva'])

    # Group packet IDs by deserializer (multiple types can share one)
    deser_to_ids = defaultdict(list)
    for pkt_id, r in results.items():
        if r['deserialize_rva']:
            deser_to_ids[r['deserialize_rva']].append(pkt_id)

    print(f"\n  {len(deser_rvas)} unique deserializer functions")
    print(f"\n  Shared deserializers (used by multiple packet IDs):")
    for deser_rva, ids in sorted(deser_to_ids.items()):
        if len(ids) > 1:
            id_strs = [f"0x{i:04X}" for i in sorted(ids)]
            print(f"    0x{deser_rva:08X}: used by {', '.join(id_strs)}")

    return results, deser_to_ids


# ═══════════════════════════════════════════════════════════════
# APPROACH 3: Find alloc functions near known RVAs
# ═══════════════════════════════════════════════════════════════

def approach3_alloc_functions(data):
    """
    In patch 5-5, alloc1 is at 0xF60420. In our binary, PKT_0x0425's
    deserializer is at 0xF60EF0. Check if there's a function at/near
    0xF60420 that looks like an allocator.
    """
    print(f"\n{'='*80}")
    print("APPROACH 3: Find alloc functions near known patch 5-5 RVAs")
    print(f"{'='*80}")

    # Check for function boundaries near each known RVA
    known_rvas = {
        'alloc1': 0xF60420,
        'alloc2': 0x1DE520,
        'skip':   0xFCA950,
        'mov_decrypt_start': 0xE45710,
        'mov_decrypt_end':   0xE45B35,
        'ward_spawn_start':  0xE3D7B0,
        'ward_spawn_end':    0xE3FD61,
    }

    for name, rva_55 in known_rvas.items():
        print(f"\n  Patch 5-5 {name}: 0x{rva_55:08X}")

        # Search for function starts near this RVA (within +/- 0x5000)
        search_start = max(0x1000, rva_55 - 0x5000)
        search_end = min(len(data), rva_55 + 0x5000)

        # Find CC CC boundaries (function boundaries)
        func_starts = []
        region = data[search_start:search_end]
        for i in range(1, len(region) - 1):
            if region[i-1] == 0xCC and region[i] != 0xCC:
                func_rva = search_start + i
                func_starts.append(func_rva)

        # Find the function start nearest to the target RVA
        if func_starts:
            nearest = min(func_starts, key=lambda x: abs(x - rva_55))
            delta = nearest - rva_55
            print(f"    Nearest function start: 0x{nearest:08X} (delta={delta:+d})")

            # Show a few nearby function starts
            nearby = sorted([f for f in func_starts if abs(f - rva_55) < 0x200])
            for f in nearby[:10]:
                d = f - rva_55
                # Show first few bytes
                preview = data[f:f+16].hex(' ')
                print(f"    0x{f:08X} (delta={d:+5d}): {preview}")

    # Special check: alloc1 at 0xF60420 vs our deserializer at 0xF60EF0
    print(f"\n  NOTE: Our PKT_0x0425 deserializer is at 0xF60EF0")
    print(f"  Patch 5-5 alloc1 is at 0xF60420")
    print(f"  Delta: {0xF60EF0 - 0xF60420:+d} = 0x{0xF60EF0 - 0xF60420:X}")
    print(f"  These are {0xF60EF0 - 0xF60420} bytes apart - same general region!")

    # Check if 0xF60420 in our binary is a valid function
    rva = 0xF60420
    if rva < len(data):
        preview = data[rva:rva+32].hex(' ')
        print(f"\n  Our binary at 0x{rva:08X}: {preview}")
        # Check if it's in the middle of something or a function start
        if rva > 0 and data[rva-1] == 0xCC:
            print(f"    Preceded by CC (int3) - likely function start!")
        elif rva > 1 and data[rva-2:rva] == b'\xCC\xCC':
            print(f"    Preceded by CC CC - likely function boundary")


# ═══════════════════════════════════════════════════════════════
# APPROACH 4: Search for PathPacket parsing patterns
# ═══════════════════════════════════════════════════════════════

def approach4_pathpacket_patterns(data):
    """
    The PathPacket parser reads:
    - parsing_type as u16 (movzx reg, word ptr [reg])
    - entity_id as u32
    - speed as f32 (movss / cvtss2sd)

    Search for code that does: movzx u16 read followed by f32 read (movss).
    """
    print(f"\n{'='*80}")
    print("APPROACH 4: Search for PathPacket parsing patterns")
    print(f"{'='*80}")

    # Search for movss (F3 0F 10) near movzx word (0F B7) patterns
    # in the .text section
    text_end = min(0x18BD000, len(data))
    hits = []

    for i in range(0x1000, text_end - 20):
        # Look for movzx reg, word ptr [reg+disp]  (0F B7 xx xx)
        if data[i] == 0x0F and data[i+1] == 0xB7:
            # Check if there's a movss within the next 50 bytes
            for j in range(i+3, min(i+60, text_end - 4)):
                if data[j] == 0xF3 and data[j+1] == 0x0F and data[j+2] == 0x10:
                    # Also check if there's a u32 read (mov reg, [reg+disp]) between
                    hits.append((i, j))
                    break

    # Filter: look for clusters (a real PathPacket parser would have
    # these instructions close together)
    print(f"  Found {len(hits)} movzx-word + movss pairs")

    # Focus on hits in the region near where we'd expect handlers
    # (between 0xE00000 and 0xF80000, roughly where constructors and handlers are)
    handler_region_hits = [(a, b) for a, b in hits
                          if 0xE00000 <= a <= 0xF80000]
    print(f"  In handler region (0xE00000-0xF80000): {len(handler_region_hits)}")

    # Show first 30
    for a, b in handler_region_hits[:30]:
        gap = b - a
        ctx_a = data[a:a+6].hex(' ')
        ctx_b = data[b:b+6].hex(' ')
        print(f"    movzx@0x{a:08X} ({ctx_a}) -> movss@0x{b:08X} ({ctx_b}) gap={gap}")

    return handler_region_hits


# ═══════════════════════════════════════════════════════════════
# APPROACH 5: Search for player_id_start constant
# ═══════════════════════════════════════════════════════════════

def approach5_player_id(data):
    """
    In patch 5-5: player_id_start = 0x40000099
    In our replay: first champion netID = 0x400000AE
    Search for 0x400000AE (and nearby values) in the binary.
    """
    print(f"\n{'='*80}")
    print("APPROACH 5: Search for player_id_start constants")
    print(f"{'='*80}")

    for const_name, const_val in [
        ("0x40000099 (patch 5-5)", 0x40000099),
        ("0x400000AE (our replay)", 0x400000AE),
        ("0x40000001 (generic base)", 0x40000001),
    ]:
        target = struct.pack("<I", const_val)
        pos = 0
        hits = []
        while True:
            idx = data.find(target, pos)
            if idx == -1:
                break
            hits.append(idx)
            pos = idx + 1
        print(f"\n  {const_name}: {len(hits)} hits")
        for h in hits[:10]:
            ctx = data[max(0,h-4):h+8].hex(' ')
            section = "text" if h < 0x18BD000 else "rdata" if h < 0x1CDD000 else "data"
            print(f"    RVA 0x{h:08X} ({section}): {ctx}")


# ═══════════════════════════════════════════════════════════════
# APPROACH 2: Find by function signature (capstone disassembly)
# ═══════════════════════════════════════════════════════════════

def approach2_function_signature(data, deser_to_ids):
    """
    Analyze deserializer functions to find ones that write to
    struct+0x10 and struct+0x18 (movement decrypt signature).
    """
    if not HAS_CAPSTONE:
        print("\n  SKIPPED: capstone not available")
        return

    print(f"\n{'='*80}")
    print("APPROACH 2: Analyze deserializer functions for mov_decrypt signature")
    print(f"{'='*80}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    candidates = []

    for deser_rva, pkt_ids in sorted(deser_to_ids.items()):
        if deser_rva >= len(data):
            continue

        # Disassemble up to 2000 bytes (mov_decrypt is ~1061 bytes)
        code = data[deser_rva:min(deser_rva + 2000, len(data))]
        va = rva_to_va(deser_rva)

        writes_0x10 = False
        writes_0x18 = False
        has_movss = False
        has_cvtss = False
        func_size = 0
        call_count = 0
        ret_found = False

        # Track rcx (this pointer) aliases
        this_regs = {x86_const.X86_REG_RCX}

        for insn in md.disasm(code, va):
            func_size = (insn.address - va) + insn.size
            mn = insn.mnemonic
            ops = insn.operands

            if mn == "ret":
                ret_found = True
                break

            if mn == "call":
                call_count += 1

            # Track register copies
            if mn == "mov" and len(ops) == 2:
                if (ops[0].type == x86_const.X86_OP_REG and
                    ops[1].type == x86_const.X86_OP_REG):
                    if ops[1].reg in this_regs:
                        this_regs.add(ops[0].reg)

            # Check for movss (float operations)
            if mn in ("movss", "movsd"):
                has_movss = True
            if mn in ("cvtss2sd", "cvtsd2ss"):
                has_cvtss = True

            # Check for writes to struct+0x10 and struct+0x18
            for i, op in enumerate(ops):
                if op.type == x86_const.X86_OP_MEM and i == 0:
                    base = op.mem.base
                    disp = op.mem.disp
                    if base in this_regs:
                        if disp == 0x10 and mn in ("mov", "lea"):
                            writes_0x10 = True
                        if disp == 0x18 and mn in ("mov", "lea"):
                            writes_0x18 = True

        if writes_0x10 and writes_0x18:
            id_strs = [f"0x{i:04X}" for i in sorted(pkt_ids)]
            candidates.append({
                'rva': deser_rva,
                'ids': pkt_ids,
                'size': func_size,
                'has_float': has_movss or has_cvtss,
                'calls': call_count,
            })
            print(f"\n  CANDIDATE: 0x{deser_rva:08X} (size={func_size}, "
                  f"float={has_movss or has_cvtss}, calls={call_count})")
            print(f"    Packet IDs: {', '.join(id_strs)}")

    if not candidates:
        print("  No candidates found writing to both struct+0x10 and struct+0x18")
    else:
        # Rank by similarity to mov_decrypt (size ~1061, has floats)
        print(f"\n  --- Ranking by similarity to mov_decrypt ---")
        for c in sorted(candidates, key=lambda x: abs(x['size'] - 1061)):
            id_strs = [f"0x{i:04X}" for i in sorted(c['ids'])]
            print(f"    0x{c['rva']:08X}: size={c['size']}, float={c['has_float']}, "
                  f"calls={c['calls']}, IDs={', '.join(id_strs)}")

    return candidates


# ═══════════════════════════════════════════════════════════════
# APPROACH 6: Compare section layout shift
# ═══════════════════════════════════════════════════════════════

def approach6_section_shift(data):
    """
    Compare section layouts between patch 5-5 and our binary to
    estimate a global RVA shift factor.
    """
    print(f"\n{'='*80}")
    print("APPROACH 6: Estimate RVA shift from section layout")
    print(f"{'='*80}")

    # Patch 5-5 sections:
    #   .text:  RVA 0x1000,    size 23,699,456 (0x169A000)  -> end 0x169B000
    #   .rdata: RVA 0x169B000, size 3,993,600  (0x3CE600)   -> end 0x1A69600
    #   .data:  RVA 0x1A6A000, size 1,265,664  (0x135000)   -> end 0x1B9F000

    # Our binary sections:
    #   .text:  RVA 0x1000,    size ~25,935,872 (0x18BC000) -> end 0x18BD000
    #   .rdata: RVA 0x18BD000, size ~4,325,376  (0x41F800)  -> end 0x1CDCC00
    #   .data:  RVA 0x1CDD000, size ~622,592

    text_shift = 0x18BD000 - 0x169B000  # = 0x222000
    rdata_shift = 0x18BD000 - 0x169B000
    data_shift = 0x1CDD000 - 0x1A6A000   # = 0x273000

    print(f"  .text end shift:  0x{text_shift:X} ({text_shift} bytes)")
    print(f"  .rdata start shift: 0x{rdata_shift:X}")
    print(f"  .data start shift:  0x{data_shift:X}")

    print(f"\n  Estimated shifted RVAs for patch 5-5 functions:")
    known_funcs = {
        'mov_decrypt_start': 0xE45710,
        'mov_decrypt_end':   0xE45B35,
        'ward_spawn_start':  0xE3D7B0,
        'alloc1':            0xF60420,
        'alloc2':            0x1DE520,
        'skip':              0xFCA950,
    }

    # The shift within .text is not uniform (code grows/shrinks)
    # But we can try proportional scaling:
    # In 5-5: .text size = 0x169A000, our .text size = 0x18BC000
    scale = 0x18BC000 / 0x169A000
    print(f"\n  .text scale factor: {scale:.4f}")

    for name, rva_55 in known_funcs.items():
        if rva_55 < 0x169B000:  # in .text
            # Proportional estimate
            scaled = int(rva_55 * scale)
            print(f"    {name}: 5-5=0x{rva_55:08X} -> estimated=0x{scaled:08X} "
                  f"(scale), delta=0x{scaled - rva_55:X}")
        else:
            # In .rdata or .data
            shifted = rva_55 + data_shift
            print(f"    {name}: 5-5=0x{rva_55:08X} -> estimated=0x{shifted:08X} (shift)")


# ═══════════════════════════════════════════════════════════════
# APPROACH 7: Disassemble PKT_0x0425 deserializer chain
# ═══════════════════════════════════════════════════════════════

def approach7_disassemble_0425_chain(data):
    """
    We know PKT_0x0425 Deserialize is at 0xF60EF0.
    Disassemble it fully and follow its call chain to find
    what sub-functions it calls - one of them may be the
    actual movement decryptor.
    """
    if not HAS_CAPSTONE:
        print("\n  SKIPPED: capstone not available")
        return

    print(f"\n{'='*80}")
    print("APPROACH 7: Follow PKT_0x0425 deserialize call chain")
    print(f"{'='*80}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    deser_rva = 0xF60EF0
    print(f"\n  Starting at Deserialize RVA 0x{deser_rva:08X}")

    # Disassemble the top-level function
    analyzed = set()
    to_analyze = [deser_rva]
    all_functions = {}

    while to_analyze:
        func_rva = to_analyze.pop(0)
        if func_rva in analyzed or func_rva >= len(data):
            continue
        analyzed.add(func_rva)

        code = data[func_rva:min(func_rva + 3000, len(data))]
        va = rva_to_va(func_rva)

        func_info = {
            'calls': [],
            'struct_writes': {},
            'has_movss': False,
            'has_cvtss': False,
            'size': 0,
        }

        this_regs = {x86_const.X86_REG_RCX}

        print(f"\n  --- Function at 0x{func_rva:08X} ---")
        for insn in md.disasm(code, va):
            irva = va_to_rva(insn.address)
            func_info['size'] = irva - func_rva + insn.size
            mn = insn.mnemonic
            ops = insn.operands

            if mn == "ret":
                break

            # Track register copies
            if mn == "mov" and len(ops) == 2:
                if (ops[0].type == x86_const.X86_OP_REG and
                    ops[1].type == x86_const.X86_OP_REG):
                    if ops[1].reg in this_regs:
                        this_regs.add(ops[0].reg)

            if mn == "call" and ops and ops[0].type == x86_const.X86_OP_IMM:
                target = va_to_rva(ops[0].imm)
                if 0x1000 < target < len(data):
                    func_info['calls'].append(target)
                    if target not in analyzed and len(analyzed) < 20:
                        to_analyze.append(target)

            if mn in ("movss", "movsd"):
                func_info['has_movss'] = True
            if mn in ("cvtss2sd", "cvtsd2ss"):
                func_info['has_cvtss'] = True

            for i, op in enumerate(ops):
                if op.type == x86_const.X86_OP_MEM and i == 0:
                    base = op.mem.base
                    disp = op.mem.disp
                    if base in this_regs and mn in ("mov", "lea", "movss"):
                        func_info['struct_writes'][disp] = True

        all_functions[func_rva] = func_info
        print(f"    Size: {func_info['size']} bytes")
        print(f"    Calls: {[f'0x{c:08X}' for c in func_info['calls']]}")
        print(f"    Struct writes: {[f'0x{k:X}' for k in sorted(func_info['struct_writes'].keys())]}")
        print(f"    Float ops: movss={func_info['has_movss']}, cvtss={func_info['has_cvtss']}")

    # Identify which sub-function is most likely the movement decryptor
    print(f"\n  --- Movement decryptor candidates ---")
    for rva, info in all_functions.items():
        writes_10 = 0x10 in info['struct_writes']
        writes_18 = 0x18 in info['struct_writes']
        has_float = info['has_movss'] or info['has_cvtss']
        score = (writes_10 * 2 + writes_18 * 2 + has_float * 3 +
                 (1 if 800 < info['size'] < 1500 else 0) * 2)
        if score > 0:
            print(f"    0x{rva:08X}: score={score}, size={info['size']}, "
                  f"writes_0x10={writes_10}, writes_0x18={writes_18}, "
                  f"float={has_float}")


def approach8b_trace_0x03D4_chain(data):
    """
    Deep trace the PKT_0x03D4 deserializer call chain to find the
    actual movement decryption logic. Follow up to 4 levels of calls.
    """
    if not HAS_CAPSTONE:
        print("\n  SKIPPED: capstone not available")
        return

    print(f"\n{'='*80}")
    print("APPROACH 8b: Deep trace PKT_0x03D4 call chain")
    print(f"{'='*80}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # BFS through call chain
    analyzed = set()
    queue = [(0x00F65D30, 0, "PKT_0x03D4::Deserialize")]
    all_funcs = {}

    while queue:
        func_rva, depth, label = queue.pop(0)
        if func_rva in analyzed or func_rva >= len(data) or func_rva < 0x1000:
            continue
        if depth > 3:
            continue
        analyzed.add(func_rva)

        code = data[func_rva:min(func_rva + 5000, len(data))]
        va = rva_to_va(func_rva)

        calls = []
        float_ops = []
        struct_writes = {}
        struct_reads = {}
        func_size = 0
        insn_count = 0
        has_bitmask = False
        has_loop = False

        # Track this pointer
        this_regs = {x86_const.X86_REG_RCX}

        for insn in md.disasm(code, va):
            irva = va_to_rva(insn.address)
            func_size = irva - func_rva + insn.size
            mn = insn.mnemonic
            ops = insn.operands
            insn_count += 1

            if mn == "ret":
                break

            # Register tracking
            if mn == "mov" and len(ops) == 2:
                if (ops[0].type == x86_const.X86_OP_REG and
                    ops[1].type == x86_const.X86_OP_REG):
                    if ops[1].reg in this_regs:
                        this_regs.add(ops[0].reg)

            if mn == "call" and ops and ops[0].type == x86_const.X86_OP_IMM:
                target = va_to_rva(ops[0].imm)
                if 0x1000 < target < len(data):
                    calls.append(target)

            # Float ops
            if mn in ("movss", "movsd", "cvtss2sd", "cvtsd2ss", "cvtsi2ss",
                       "mulss", "divss", "addss", "subss", "comiss", "ucomiss",
                       "sqrtss", "maxss", "minss"):
                float_ops.append(f"0x{irva:08X}: {mn} {insn.op_str}")

            # Bitmask operations (important for waypoint decoder)
            if mn in ("and", "or", "shr", "shl", "bt", "btr", "bts"):
                has_bitmask = True

            # Loop detection (backwards jump)
            if mn.startswith("j") and ops and ops[0].type == x86_const.X86_OP_IMM:
                jump_target = va_to_rva(ops[0].imm)
                if jump_target < irva:
                    has_loop = True

            # Struct access
            for i, op in enumerate(ops):
                if op.type == x86_const.X86_OP_MEM:
                    base = op.mem.base
                    disp = op.mem.disp
                    if base in this_regs:
                        if i == 0:
                            struct_writes[disp] = struct_writes.get(disp, 0) + 1
                        else:
                            struct_reads[disp] = struct_reads.get(disp, 0) + 1

        indent = "  " * (depth + 1)
        print(f"\n{indent}{'─'*60}")
        print(f"{indent}[depth={depth}] {label} @ 0x{func_rva:08X}")
        print(f"{indent}  Size: {func_size} bytes, {insn_count} instructions")
        print(f"{indent}  Calls: {[f'0x{c:08X}' for c in calls]}")
        if struct_writes:
            print(f"{indent}  Struct writes: {dict(sorted([(f'0x{k:X}', v) for k, v in struct_writes.items()]))}")
        if struct_reads:
            print(f"{indent}  Struct reads: {dict(sorted([(f'0x{k:X}', v) for k, v in struct_reads.items()]))}")
        print(f"{indent}  Float ops: {len(float_ops)}, Bitmask: {has_bitmask}, Loop: {has_loop}")
        if float_ops:
            for fo in float_ops[:20]:
                print(f"{indent}    {fo}")

        # Score as movement decryptor candidate
        score = 0
        score += min(len(float_ops), 10) * 2
        score += has_bitmask * 3
        score += has_loop * 3
        score += (500 < func_size < 2000) * 5
        if score > 5:
            print(f"{indent}  >>> MOVEMENT DECRYPT CANDIDATE (score={score})")

        all_funcs[func_rva] = {
            'size': func_size, 'calls': calls, 'float_ops': float_ops,
            'bitmask': has_bitmask, 'loop': has_loop, 'score': score,
            'struct_writes': struct_writes, 'struct_reads': struct_reads,
        }

        # Queue sub-calls
        for i, sub in enumerate(calls):
            if sub not in analyzed:
                queue.append((sub, depth + 1, f"sub_{i} of 0x{func_rva:08X}"))

    # Summary: rank all by score
    print(f"\n  === Call chain summary ===")
    for rva, info in sorted(all_funcs.items(), key=lambda x: -x[1]['score']):
        if info['score'] > 0:
            print(f"    0x{rva:08X}: score={info['score']}, size={info['size']}, "
                  f"floats={len(info['float_ops'])}, bitmask={info['bitmask']}, loop={info['loop']}")


def approach8_deep_disassemble_key_deserializers(data):
    """
    Deep disassembly of the most interesting deserializer functions,
    especially PKT_0x03D4 (mov_decrypt netid from patch 5-5).
    """
    if not HAS_CAPSTONE:
        print("\n  SKIPPED: capstone not available")
        return

    print(f"\n{'='*80}")
    print("APPROACH 8: Deep disassemble key deserializers")
    print(f"{'='*80}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Key deserializers to analyze
    key_funcs = {
        'PKT_0x03D4 (mov_decrypt 5-5 netid=980)': 0x00F65D30,
        'PKT_0x0425 (known movement)': 0x00F60EF0,
        'PKT_0x0092 (target)': 0x01023EE0,
        'PKT_0x0228 (target)': 0x00E748B0,
    }

    for name, deser_rva in key_funcs.items():
        if deser_rva >= len(data):
            continue

        print(f"\n  {'─'*70}")
        print(f"  {name}: Deserialize @ RVA 0x{deser_rva:08X}")
        print(f"  {'─'*70}")

        # Disassemble up to 2000 bytes to find ret
        code = data[deser_rva:min(deser_rva + 2000, len(data))]
        va = rva_to_va(deser_rva)

        this_regs = {x86_const.X86_REG_RCX}
        ptrptr_regs = {x86_const.X86_REG_RDX}
        end_regs = {x86_const.X86_REG_R8}

        struct_writes = {}
        struct_reads = {}
        calls_found = []
        has_movss = False
        has_cvtss = False
        float_ops = []
        func_size = 0
        insn_count = 0

        for insn in md.disasm(code, va):
            irva = va_to_rva(insn.address)
            func_size = irva - deser_rva + insn.size
            mn = insn.mnemonic
            ops = insn.operands
            insn_count += 1

            if mn == "ret":
                break

            # Track register copies
            if mn == "mov" and len(ops) == 2:
                if (ops[0].type == x86_const.X86_OP_REG and
                    ops[1].type == x86_const.X86_OP_REG):
                    dst, src = ops[0].reg, ops[1].reg
                    if src in this_regs:
                        this_regs.add(dst)
                    if src in ptrptr_regs:
                        ptrptr_regs.add(dst)
                    if src in end_regs:
                        end_regs.add(dst)

            if mn == "call" and ops and ops[0].type == x86_const.X86_OP_IMM:
                calls_found.append(va_to_rva(ops[0].imm))

            if mn in ("movss", "movsd"):
                has_movss = True
                float_ops.append(f"0x{irva:08X}: {mn} {insn.op_str}")
            if mn in ("cvtss2sd", "cvtsd2ss", "cvtsi2ss"):
                has_cvtss = True
                float_ops.append(f"0x{irva:08X}: {mn} {insn.op_str}")
            if mn in ("mulss", "divss", "addss", "subss", "comiss", "ucomiss"):
                float_ops.append(f"0x{irva:08X}: {mn} {insn.op_str}")

            for i, op in enumerate(ops):
                if op.type == x86_const.X86_OP_MEM:
                    base = op.mem.base
                    disp = op.mem.disp
                    if base in this_regs:
                        if i == 0 and mn in ("mov", "lea", "movss", "movsd", "or", "and", "add", "sub"):
                            struct_writes[disp] = struct_writes.get(disp, 0) + 1
                        elif i > 0:
                            struct_reads[disp] = struct_reads.get(disp, 0) + 1

        print(f"    Function size: {func_size} bytes, {insn_count} instructions")
        print(f"    Calls: {[f'0x{c:08X}' for c in calls_found]}")
        print(f"    Struct writes: {dict(sorted([(f'0x{k:X}', v) for k, v in struct_writes.items()]))}")
        print(f"    Struct reads: {dict(sorted([(f'0x{k:X}', v) for k, v in struct_reads.items()]))}")
        print(f"    Has float ops: {has_movss or has_cvtss}")
        if float_ops:
            print(f"    Float instructions:")
            for fo in float_ops[:20]:
                print(f"      {fo}")

        # Now follow calls to see if sub-functions have float ops
        for sub_rva in calls_found:
            if sub_rva >= len(data) or sub_rva < 0x1000:
                continue
            sub_code = data[sub_rva:min(sub_rva + 3000, len(data))]
            sub_va = rva_to_va(sub_rva)
            sub_float = []
            sub_writes = {}
            sub_size = 0
            sub_calls = []

            for insn in md.disasm(sub_code, sub_va):
                sirva = va_to_rva(insn.address)
                sub_size = sirva - sub_rva + insn.size
                smn = insn.mnemonic
                sops = insn.operands

                if smn == "ret":
                    break

                if smn == "call" and sops and sops[0].type == x86_const.X86_OP_IMM:
                    sub_calls.append(va_to_rva(sops[0].imm))

                if smn in ("movss", "movsd", "cvtss2sd", "cvtsd2ss", "cvtsi2ss",
                           "mulss", "divss", "addss", "subss"):
                    sub_float.append(f"0x{sirva:08X}: {smn} {insn.op_str}")

            if sub_float or sub_size > 500:
                print(f"\n    Sub-function 0x{sub_rva:08X}: {sub_size} bytes, calls={[f'0x{c:08X}' for c in sub_calls]}")
                if sub_float:
                    print(f"      Float ops ({len(sub_float)}):")
                    for sf in sub_float[:15]:
                        print(f"        {sf}")

                # Follow one more level
                for sub2_rva in sub_calls:
                    if sub2_rva >= len(data) or sub2_rva < 0x1000:
                        continue
                    sub2_code = data[sub2_rva:min(sub2_rva + 3000, len(data))]
                    sub2_va = rva_to_va(sub2_rva)
                    sub2_float = []
                    sub2_size = 0

                    for insn in md.disasm(sub2_code, sub2_va):
                        s2irva = va_to_rva(insn.address)
                        sub2_size = s2irva - sub2_rva + insn.size
                        s2mn = insn.mnemonic

                        if s2mn == "ret":
                            break
                        if s2mn in ("movss", "movsd", "cvtss2sd", "cvtsd2ss",
                                    "mulss", "divss", "addss", "subss", "cvtsi2ss"):
                            sub2_float.append(f"0x{s2irva:08X}: {s2mn} {insn.op_str}")

                    if sub2_float:
                        print(f"\n      Sub2-function 0x{sub2_rva:08X}: {sub2_size} bytes")
                        print(f"        Float ops ({len(sub2_float)}):")
                        for sf in sub2_float[:15]:
                            print(f"          {sf}")


def print_mowokuma_config(data, results, deser_to_ids):
    """
    Print a Mowokuma-style config for our binary based on all findings.
    """
    print(f"\n{'='*80}")
    print("MOWOKUMA-EQUIVALENT CONFIG FOR OUR BINARY")
    print(f"{'='*80}")

    # Section layout
    print(f"""
{{
  "binary": "league_unpacked_patched.bin",
  "base_addr": "0x7FF76C300000",
  "patch": "16.5 (approximate)",

  "sections": {{
    "text": {{"rva": "0x1000", "size": {0x18BC000}}},
    "rdata": {{"rva": "0x18BD000", "size": {0x41F800}}},
    "data": {{"rva": "0x1CDD000", "size": {0x98000}}}
  }},

  "dispatcher_rva": "0x0066E5F0",
  "player_id_start": "0x400000AE",
""")

    # PKT_0x03D4 = movement packet (same netid as patch 5-5)
    if 0x03D4 in results:
        r = results[0x03D4]
        deser = r.get('deserialize_rva', 0)
        print(f"""  "mov_decrypt": {{
    "netid": 980,
    "constructor_rva": "0x{r['constructor_rva']:08X}",
    "vtable_rva": "0x{r['vtable_rva']:08X}",
    "deserialize_rva": "0x{deser:08X}",
    "NOTES": "Deserializer calls: 0x01150B40 (cipher), 0x00E7F010 (bitmask), 0x010D4100 (size write), 0x00F04360 (decode loop)"
  }},
""")

    # PKT_0x0425 = the packet we previously identified
    if 0x0425 in results:
        r = results[0x0425]
        deser = r.get('deserialize_rva', 0)
        print(f"""  "pkt_0x0425": {{
    "netid": 1061,
    "constructor_rva": "0x{r['constructor_rva']:08X}",
    "vtable_rva": "0x{r['vtable_rva']:08X}",
    "deserialize_rva": "0x{deser:08X}",
    "NOTES": "Previously identified as movement input. Calls: 0x01150B40, 0x00E7F010"
  }},
""")

    # PKT_0x0228 = one of the targets with a LARGE deserializer (1998 bytes!)
    if 0x0228 in results:
        r = results[0x0228]
        deser = r.get('deserialize_rva', 0)
        print(f"""  "pkt_0x0228": {{
    "netid": 552,
    "constructor_rva": "0x{r['constructor_rva']:08X}",
    "vtable_rva": "0x{r['vtable_rva']:08X}",
    "deserialize_rva": "0x{deser:08X}",
    "deserialize_size": 1998,
    "NOTES": "Large deserializer! Reads struct+0x10,0x14,0x18,0x1C. Could be movement/waypoint."
  }},
""")

    # Shared utility functions
    print(f"""  "shared_functions": {{
    "byte_cipher": "0x01150B40",
    "bitmask_transform": "0x00E7F010",
    "payload_copy": "0x00DCB020",
    "field_extract": "0x00DC3E80"
  }},

  "alloc_candidates": {{
    "near_alloc1_55": "0x00F605D0",
    "near_alloc2_55": "0x001DE550"
  }},

  "total_packet_types": 299,
  "unique_deserializers": {len(deser_to_ids)},
  "constructor_region": "0x00DFF000 - 0x00E10000"
}}""")

    # Also dump the full packet ID -> deserializer mapping for key IDs
    print(f"\n  --- Full packet mapping (top replay packet IDs) ---")
    replay_ids = [0x0092, 0x0228, 0x025B, 0x0458, 0x047A, 0x03D4, 0x0425]
    for pid in replay_ids:
        if pid in results:
            r = results[pid]
            deser = r.get('deserialize_rva', 0)
            print(f"    0x{pid:04X} (netid={pid}): deser=0x{deser:08X}, vtable=0x{r['vtable_rva']:08X}")
        else:
            print(f"    0x{pid:04X} (netid={pid}): NOT FOUND in constructors")


def main():
    data = load_binary()

    # Approach 1: Enumerate constructors (most reliable)
    results, deser_to_ids = approach1_full(data)

    # Approach 3: Check alloc function locations
    approach3_alloc_functions(data)

    # Approach 6: Estimate RVA shift
    approach6_section_shift(data)

    # Approach 2: Function signature analysis (needs capstone)
    approach2_function_signature(data, deser_to_ids)

    # Approach 4: PathPacket patterns
    approach4_pathpacket_patterns(data)

    # Approach 5: Player ID constants
    approach5_player_id(data)

    # Approach 7: Follow the call chain
    approach7_disassemble_0425_chain(data)

    # Approach 8: Deep disassemble key deserializers
    approach8_deep_disassemble_key_deserializers(data)

    # Approach 8b: Deep trace PKT_0x03D4 call chain
    approach8b_trace_0x03D4_chain(data)

    # Final summary: Mowokuma-equivalent config
    print_mowokuma_config(data, results, deser_to_ids)

    print(f"\n{'='*80}")
    print("DONE - All approaches completed")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
