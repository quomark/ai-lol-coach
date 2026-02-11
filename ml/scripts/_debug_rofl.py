"""Quick debug: dump raw bytes of a .rofl file to figure out the format."""
import sys
from pathlib import Path

replay_dir = Path("ml/data/raw/high_elo/replays")
files = sorted(replay_dir.glob("*.rofl"))
if not files:
    print("No .rofl files found")
    sys.exit(1)

f = files[0]
data = f.read_bytes()
print(f"File: {f.name}")
print(f"Size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

# Dump first 512 bytes as hex + ascii
print(f"\n=== First 512 bytes ===")
for i in range(0, min(512, len(data)), 16):
    hex_part = " ".join(f"{b:02x}" for b in data[i:i+16])
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
    print(f"  {i:06x}: {hex_part:<48s}  {ascii_part}")

# Look for JSON anywhere in first 10KB
print(f"\n=== Searching for JSON in first 10KB ===")
search = data[:10240]
for marker in [b'{"', b'"game', b'"stats', b'"player', b'metadata']:
    idx = search.find(marker)
    if idx >= 0:
        # Show context around it
        start = max(0, idx - 20)
        end = min(len(data), idx + 200)
        snippet = data[start:end]
        print(f"  Found '{marker.decode()}' at offset {idx}")
        print(f"  Context: {snippet}")

# Search whole file for JSON
print(f"\n=== Searching for JSON in entire file ===")
for marker in [b'{"', b'"gameLength"', b'"statsJson"', b'"CHAMPIONS_KILLED"']:
    idx = data.find(marker)
    if idx >= 0:
        end = min(len(data), idx + 300)
        snippet = data[idx:end]
        # Try to find the end of JSON
        try:
            text = snippet.decode('utf-8', errors='replace')
            print(f"  Found '{marker.decode()}' at offset {idx}")
            print(f"  Text: {text[:300]}")
        except:
            print(f"  Found '{marker.decode()}' at offset {idx} (binary)")
    else:
        print(f"  '{marker.decode()}' NOT found")

# Check magic bytes
print(f"\n=== Magic bytes ===")
print(f"  First 20 bytes: {data[:20].hex()}")
print(f"  As string: {repr(data[:20])}")

# Try to find the ROFL header structure by scanning for known patterns
print(f"\n=== Looking for format markers ===")
# Check if it starts with RIOT
if data[:4] == b'RIOT':
    print("  Starts with RIOT magic")
elif data[:4] == b'ROFL':
    print("  Starts with ROFL magic")
elif data[:2] == b'\x1f\x8b':
    print("  Starts with gzip magic — file might be gzip compressed!")
elif data[:4] == b'PK\x03\x04':
    print("  Starts with ZIP magic!")
else:
    print(f"  Unknown magic: {data[:4].hex()} = {repr(data[:4])}")

# Check for compression
import zlib
try:
    decompressed = zlib.decompress(data)
    print(f"\n  File is zlib compressed! Decompressed size: {len(decompressed)}")
    print(f"  First 200 bytes of decompressed: {repr(decompressed[:200])}")
except:
    pass

try:
    decompressed = zlib.decompress(data, 15+32)  # gzip
    print(f"\n  File is gzip compressed! Decompressed size: {len(decompressed)}")
    print(f"  First 200 bytes of decompressed: {repr(decompressed[:200])}")
except:
    pass

# Check if entire file is JSON
try:
    import json
    json.loads(data)
    print("\n  ENTIRE FILE IS JSON!")
except:
    pass

# Scan for large JSON blobs
print(f"\n=== Scanning for JSON blobs ===")
pos = 0
while pos < len(data):
    idx = data.find(b'{', pos)
    if idx < 0:
        break
    # Try to parse JSON starting here
    try:
        text = data[idx:idx+50000].decode('utf-8', errors='strict')
        import json
        obj = json.loads(text[:text.index('\x00')] if '\x00' in text else text)
        print(f"  JSON at offset {idx}: keys={list(obj.keys())[:10]}")
        break
    except:
        pass
    pos = idx + 1
    if pos - idx > 100000:
        break
