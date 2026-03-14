# Replay emulator — decodes .rofl using League's own binary
#
# Two implementations:
#   - emulator.py:        Unicorn-based (cross-platform, slow ~5 min/replay)
#   - native_emulator.py: Native execution + VEH (Windows only, fast ~3 sec/replay)
