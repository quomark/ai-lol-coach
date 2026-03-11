"""
Ghidra helper — find packet handler functions in League of Legends.exe.

This script is meant to be run INSIDE Ghidra's Python console (Jython)
or as a Ghidra script. It searches for known string references and
cross-references to locate the main packet processing function.

═══════════════════════════════════════════════════════════════════════
HOW TO USE:
═══════════════════════════════════════════════════════════════════════

1. Download Ghidra: https://ghidra-sre.org/
2. Create a new project
3. Import: C:/Riot Games/League of Legends/Game/League of Legends.exe
4. Analyze (accept defaults, enable "Decompiler Parameter ID")
5. Wait for analysis to complete (~10-30 min for a 50MB+ binary)
6. Window → Script Manager → paste this script → Run

Alternatively, use the Ghidra Python console:
  >>> exec(open("path/to/ghidra_find_handlers.py").read())

═══════════════════════════════════════════════════════════════════════
WHAT TO LOOK FOR:
═══════════════════════════════════════════════════════════════════════

The main packet handler typically:
  - Has a large switch/case or if-else chain on packet type IDs
  - References strings like "ENet", "Packet", "HandlePacket",
    "Channel", "S2C" (server-to-client)
  - Takes 3-4 args: context ptr, channel (u8), data (u8*), length (u32)
  - Is called from the network receive loop

Known packet type IDs (from LeagueSandbox/GameServer):
  - 0x62 = MovementDataNormal (champion positions + waypoints)
  - 0x4B = SpawnMinionS2C
  - 0x65 = Die_S2C (death event)
  - 0x17 = LevelUp
  - 0x80 = SpellCastS2C
  - 0x4C = TurretDie_S2C
  - 0x6B = GoldChange

═══════════════════════════════════════════════════════════════════════
MANUAL APPROACH (if script doesn't find it):
═══════════════════════════════════════════════════════════════════════

1. Search → For Strings → look for:
   - "HandlePacket"
   - "ProcessPacket"
   - "ENetPacket"
   - "S2C_"
   - "OnPacket"

2. For each string hit, right-click → References → Find References To
   This shows which functions reference that string.

3. Look for functions with signature like:
   void __fastcall FUN_xxxxx(longlong this, byte channel, byte* data, uint length)

4. The packet handler will have a switch on the first 1-2 bytes of data.
   In the decompiler, look for:
     switch(*(byte *)data) {
       case 0x17: ...  // LevelUp
       case 0x62: ...  // Movement
       case 0x65: ...  // Die
       ...
     }

5. Once found, note the function address. Subtract the image base
   (usually 0x140000000 for 64-bit) to get the RVA.

   Example: function at 0x141234567
   Image base:      0x140000000
   RVA:             0x01234567

6. Set this RVA in emulator.py:
   emu.PACKET_HANDLER_RVA = 0x01234567

═══════════════════════════════════════════════════════════════════════
KNOWN PACKET IDS (LeagueSandbox reference):
═══════════════════════════════════════════════════════════════════════
"""

# Packet type IDs from LeagueSandbox/GameServer
# https://github.com/LeagueSandbox/GameServer/tree/master/PacketDefinitions420
KNOWN_PACKET_TYPES = {
    # Movement & Position
    0x62: "MovementDataNormal",       # x,y + waypoints
    0x61: "MovementDataWithSpeed",

    # Combat
    0x80: "SpellCastS2C",            # ability cast (Q/W/E/R)
    0x6F: "BasicAttackS2C",          # auto-attack
    0x65: "Die_S2C",                 # death
    0x3F: "ChampionRespawn",         # respawn
    0x17: "LevelUp",                 # level up

    # Economy
    0x6B: "GoldChange",              # gold gained/spent
    0x0D: "ItemPurchase",            # item buy

    # Objectives
    0x4C: "TurretDie_S2C",          # turret destroyed
    0x4B: "SpawnMinionS2C",          # minion spawn
    0x2F: "InhibitorDie_S2C",        # inhibitor destroyed

    # Vision
    0x40: "WardPlaced",              # ward placed
    0x08: "FogOfWar",                # fog update

    # Spawns
    0x34: "SpawnChampS2C",           # champion spawn
    0x6A: "SpawnProjectileS2C",      # projectile spawn

    # UI / State
    0x2C: "SynchVersionS2C",         # version sync
    0x64: "OnEnterLocalVisibilityClient",
    0x3A: "UpdateStats",             # stat update
    0x3D: "SetAnimation",

    # Team
    0x42: "TeamSurrenderVote",
    0x48: "TeamSurrenderStatus",
}

# Strings to search for in the binary
SEARCH_STRINGS = [
    b"HandlePacket",
    b"ProcessPacket",
    b"ENetPacket",
    b"OnPacket",
    b"PacketHandler",
    b"S2C_",
    b"C2S_",
    b"Channel",
    b"MovementData",
    b"SpellCast",
    b"Die_S2C",
    b"BasicAttack",
    b"LevelUp",
    b"GoldChange",
    b"NetID",
    b"netId",
]


def print_packet_reference():
    """Print the packet type reference table."""
    print("\n" + "=" * 60)
    print("  PACKET TYPE REFERENCE")
    print("=" * 60)
    print(f"  {'ID':>4s} {'Hex':>5s}  {'Name':<35s}")
    print(f"  {'─' * 50}")
    for pid, name in sorted(KNOWN_PACKET_TYPES.items()):
        print(f"  {pid:>4d} 0x{pid:02X}   {name}")
    print(f"\n  Total: {len(KNOWN_PACKET_TYPES)} known packet types")

    print(f"\n  STRINGS TO SEARCH IN GHIDRA:")
    for s in SEARCH_STRINGS:
        print(f"    {s.decode()}")


# ═══════════════════════════════════════════════════════════════════
# GHIDRA SCRIPT (only runs inside Ghidra's Jython interpreter)
# ═══════════════════════════════════════════════════════════════════

GHIDRA_SCRIPT = '''
# Run this in Ghidra's Script Manager or Python console.
# It searches for strings related to packet handling and
# finds the functions that reference them.

from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtils

program = getCurrentProgram()
listing = program.getListing()
memory = program.getMemory()
refManager = program.getReferenceManager()

search_terms = [
    "HandlePacket", "ProcessPacket", "ENetPacket",
    "OnPacket", "S2C_", "Channel", "PacketHandler",
]

print("=" * 60)
print("  Searching for packet handler strings...")
print("=" * 60)

# Search all defined strings
found_funcs = set()
for data in DefinedDataIterator.definedStrings(program):
    val = data.getValue()
    if val is None:
        continue
    s = str(val)
    for term in search_terms:
        if term.lower() in s.lower():
            addr = data.getAddress()
            print(f"\\n  String: \\"{s}\\" at {addr}")

            # Find cross-references to this string
            refs = getReferencesTo(addr)
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = getFunctionContaining(from_addr)
                if func:
                    print(f"    Referenced by: {func.getName()} at {func.getEntryPoint()}")
                    found_funcs.add((str(func.getEntryPoint()), func.getName()))
                else:
                    print(f"    Referenced from: {from_addr} (no function)")

print("\\n" + "=" * 60)
print(f"  Found {len(found_funcs)} candidate functions:")
print("=" * 60)
for addr, name in sorted(found_funcs):
    image_base = program.getImageBase().getOffset()
    rva = int(addr, 16) - image_base
    print(f"  {addr}  RVA=0x{rva:08X}  {name}")

print("\\n  Copy the RVA of the main packet handler to emulator.py:")
print("  emu.PACKET_HANDLER_RVA = 0x________")
'''


if __name__ == "__main__":
    print_packet_reference()
    print("\n\n" + "=" * 60)
    print("  GHIDRA SCRIPT")
    print("  Copy the script below into Ghidra's Script Manager")
    print("=" * 60)
    print(GHIDRA_SCRIPT)
