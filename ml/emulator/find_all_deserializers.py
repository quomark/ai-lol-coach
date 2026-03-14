"""Find ALL deserializer functions by searching for calls to VARINT_DEC.

Every packet deserializer calls VARINT_DEC (0x01150B40) as its first operation.
By finding all call sites, we can identify all deserializer functions.
Then match them to packet types via vtable cross-referencing.
"""
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

dump = Path("ml/data/league_unpacked_patched.bin").read_bytes()
BASE = 0x7FF76C300000
md = Cs(CS_ARCH_X86, CS_MODE_64)

VARINT_DEC = 0x01150B40
READER_FUNC_0228 = 0x00E7F010  # Known READER_FUNC for 0x0228

# Find all CALL instructions targeting VARINT_DEC
print("=== Finding all calls to VARINT_DEC (0x01150B40) ===")
varint_callers = []

for offset in range(0, len(dump) - 5):
    if dump[offset] == 0xE8:  # CALL rel32
        disp = struct.unpack_from("<i", dump, offset + 1)[0]
        target_va = BASE + offset + 5 + disp
        target_rva = target_va - BASE
        if target_rva == VARINT_DEC:
            varint_callers.append(offset)

print(f"Found {len(varint_callers)} calls to VARINT_DEC")

# For each caller, find the function start (walk back to CC padding or function prologue)
def find_func_start(rva):
    """Walk backward from an instruction to find function start."""
    # Look for int3 padding (CC CC) followed by function prologue
    for i in range(rva - 1, max(rva - 200, 0), -1):
        if dump[i] == 0xCC:
            # Found CC padding, next non-CC byte is function start
            start = i + 1
            while start < rva and dump[start] == 0xCC:
                start += 1
            if start < rva:
                return start
    return None

# Group callers by containing function
func_to_callers = {}
for caller_rva in varint_callers:
    func_start = find_func_start(caller_rva)
    if func_start is not None:
        if func_start not in func_to_callers:
            func_to_callers[func_start] = []
        func_to_callers[func_start].append(caller_rva)

print(f"\n{len(func_to_callers)} unique functions call VARINT_DEC")

# Now for each function, check if it also calls READER_FUNC
# and count how many READER_FUNC calls it has (= number of fields)
print(f"\n=== Deserializer candidates (VARINT_DEC + READER_FUNC callers) ===")

# Known READER_FUNC patterns: each deserializer has its own READER_FUNC.
# The READER_FUNC is typically defined AFTER the deserializer.
# For 0x0228, READER_FUNC is at 0x00E7F010, deserializer at 0x00E748B0.
# For 0x025B, READER_FUNC would be at a different address.

# Let me look at the function size and number of calls to identify deserializers
deserializer_candidates = []

for func_start, callers in sorted(func_to_callers.items()):
    # Find function end
    func_end = func_start + 20000  # max size
    for pos in range(func_start, min(func_start + 20000, len(dump) - 1)):
        if dump[pos] == 0xC3:  # ret
            if pos + 1 < len(dump) and dump[pos + 1] == 0xCC:
                func_end = pos + 1
                break

    func_size = func_end - func_start
    if func_size < 100:  # too small to be a deserializer
        continue

    # Count calls within the function
    call_count = 0
    unique_targets = set()
    code = dump[func_start:func_end]
    for i in range(len(code) - 5):
        if code[i] == 0xE8:
            disp = struct.unpack_from("<i", code, i + 1)[0]
            target_rva = func_start + i + 5 + disp
            if 0 < target_rva < len(dump):
                call_count += 1
                unique_targets.add(target_rva)

    # Deserializers typically have 10+ calls and are 1000+ bytes
    if func_size > 1000 and call_count > 5:
        deserializer_candidates.append((func_start, func_size, call_count, len(unique_targets)))

print(f"\nFound {len(deserializer_candidates)} candidates (size>1000, calls>5)")
print(f"\n{'RVA':<14} {'Size':<8} {'Calls':<8} {'Unique':<8} {'Notes'}")
print("-" * 60)

# Known deserializers for reference
KNOWN = {
    0x00E748B0: "0x0228 deserializer",
    0x00DE3410: "0x025B deserializer (estimated)",
}

for func_rva, size, calls, unique in sorted(deserializer_candidates):
    note = KNOWN.get(func_rva, "")
    print(f"0x{func_rva:08X}  {size:<8} {calls:<8} {unique:<8} {note}")
