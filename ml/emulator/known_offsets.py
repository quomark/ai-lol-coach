"""
Known offsets for League of Legends binary.

These are discovered by scanning the original binary for packet-related
strings and tracing cross-references to find the dispatcher function.

Auto-discovered using: pattern_scanner.py / inline analysis
Game binary: C:/Riot Games/League of Legends/Game/League of Legends.exe

NOTE: These offsets are for a SPECIFIC patch version. When the game updates,
re-run the scanner to find updated offsets.
"""

# ═══════════════════════════════════════════════════════════════
# Patch info
# ═══════════════════════════════════════════════════════════════

GAME_EXE = r"C:\Riot Games\League of Legends\Game\League of Legends.exe"
IMAGE_BASE = 0x0000000140000000

# Binary details
# PE size: 32.2 MB, .text starts at RVA 0x1000 (code at +0x3000)
# Packed with Packman (stub.dll) but .text is NOT encrypted

# ═══════════════════════════════════════════════════════════════
# Core packet processing
# ═══════════════════════════════════════════════════════════════

# The main packet dispatcher — giant switch/case on packet type byte
# 42,018 bytes, 734 CALL instructions, 240 CMP al,imm8 comparisons
# Prologue: 48 89 5c 24 08 55 56 57 41 54 41 55 41 56 41 57
PACKET_DISPATCHER_RVA = 0x0066E5F0

# PacketRcv logging/stats function
PACKET_RCV_STATS_RVA = 0x005736E0

# PacketSnd logging/stats function
PACKET_SND_STATS_RVA = 0x00573DB0

# ═══════════════════════════════════════════════════════════════
# Game event handlers (called BY the dispatcher)
# ═══════════════════════════════════════════════════════════════

# "Received Game Start Packet." handler
GAME_START_HANDLER_RVA = 0x00601110

# "Received Game End Packet." — inside larger function at:
GAME_END_HANDLER_RVA = 0x005FF678

# ═══════════════════════════════════════════════════════════════
# String registration functions
# ═══════════════════════════════════════════════════════════════

# These register packet type names — both call into 0x010E3160
BASIC_ATTACK_REGISTER_RVA = 0x000A9130
SPELL_CAST_REGISTER_RVA = 0x000A9640

# The function they both call (likely a packet type registry)
PACKET_TYPE_REGISTRY_RVA = 0x010E3160
PACKET_TYPE_REGISTRY_2_RVA = 0x010DBEF0

# ═══════════════════════════════════════════════════════════════
# String locations in .rdata (for validation / future scanning)
# ═══════════════════════════════════════════════════════════════

STRINGS = {
    0x018CD258: "SpellCast",
    0x018CE428: "BasicAttack",
    0x018D3A4E: "NetID",
    0x018CC851: "LevelUp",
    0x018FD0E8: "S2C_SkinAugmentEntry_s",
    0x01925D08: "PacketSnd  ",
    0x01925D18: "PacketRcv  ",
    0x019259D9: "packet=%u",
    0x01929090: "Received StartSpawn packet.",
    0x019290D8: "Received Game Start Packet.",
    0x019291E8: "Received Game End Packet.",
    0x01934EE1: "PacketID} {Size}bytes",
    0x01935175: "Received: {:%s}",
}
