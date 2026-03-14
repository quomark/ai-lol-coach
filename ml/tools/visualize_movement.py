"""
Interactive movement visualizer for League of Legends ROFL replays.

Decodes all 0x025B movement packets and launches a browser-based visualization
showing champion positions over time on a Summoner's Rift map.

Usage:
    uv run python -m ml.tools.visualize_movement "C:\\path\\to\\replay.rofl"
    uv run python -m ml.tools.visualize_movement "C:\\path\\to\\replay.rofl" --binary "C:\\path\\to\\dump.bin"
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import tempfile
import threading
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

from ml.parsers.chunk_parser import parse_payload_frames
from ml.parsers.movement_decoder import MovementDecoder
from ml.parsers.rofl_parser import ROFLParser

DEFAULT_BINARY = Path(__file__).resolve().parent.parent / "data" / "league_unpacked_patched.bin"

# Entity ID -> (champion_name, team)
# Team assignment TBD - using "unknown" so user can identify visually
MAPPING = {
    174: ("174", "unknown"),
    175: ("175", "unknown"),
    176: ("176", "unknown"),
    177: ("177", "unknown"),
    178: ("178", "unknown"),
    179: ("179", "unknown"),
    180: ("180", "unknown"),
    181: ("181", "unknown"),
    182: ("182", "unknown"),
    183: ("183", "unknown"),
}

# 10 maximally distinct colors for entity identification
ENTITY_COLORS = [
    "#FF0000",  # 174 - Red
    "#00FF00",  # 175 - Green
    "#4488FF",  # 176 - Blue
    "#FFFF00",  # 177 - Yellow
    "#FF00FF",  # 178 - Magenta
    "#00FFFF",  # 179 - Cyan
    "#FF8800",  # 180 - Orange
    "#FFFFFF",  # 181 - White
    "#88FF88",  # 182 - Light green
    "#FF88FF",  # 183 - Pink
]


def decode_replay(rofl_path: str, binary_path: str) -> tuple[list[dict], float]:
    """Decode all 0x025B movement packets from a replay file.

    Returns (records, max_timestamp) where each record is:
        {"t": timestamp, "id": entity_id, "x": x, "z": z, "speed": speed}
    """
    print(f"Parsing ROFL: {rofl_path}")
    parser = ROFLParser(rofl_path)
    parser.parse()

    print("Decompressing payload frames...")
    frames = parser.decompress_payload_frames()
    print(f"  {len(frames)} frames decompressed")

    print("Parsing packets from frames...")
    result = parse_payload_frames(frames)
    all_packets = [p for f in result.frames for p in f.packets]
    movement_packets = [p for p in all_packets if p.packet_id == 0x025B]
    print(f"  {len(all_packets):,} total packets, {len(movement_packets):,} movement (0x025B)")

    print(f"Loading binary: {binary_path}")
    decoder = MovementDecoder(binary_path)

    print("Decoding movement packets...")
    records = []
    max_t = 0.0
    champion_ids = set(MAPPING.keys())

    # First pass: collect all records to detect shared initialization positions
    raw_records = []
    for ts, mv in decoder.decode_all(all_packets):
        if mv.entity_id not in champion_ids:
            continue
        if mv.x == 0 and mv.z == 0:
            continue
        raw_records.append((ts, mv))

    # Find positions shared by many entities at t=0 (initialization noise)
    from collections import Counter
    t0_positions: dict[tuple[int, int], set[int]] = {}
    for ts, mv in raw_records:
        if ts < 1.0:  # first second = initialization batch
            pos = (mv.x, mv.z)
            t0_positions.setdefault(pos, set()).add(mv.entity_id)
    shared_init_positions = {pos for pos, ids in t0_positions.items() if len(ids) >= 5}
    print(f"  Filtering {len(shared_init_positions)} shared initialization positions")

    for ts, mv in raw_records:
        # Skip shared initialization positions (map objects, not champion locations)
        if (mv.x, mv.z) in shared_init_positions:
            continue
        # Filter keyframe noise: speed > 5000 is teleport/respawn artifact
        if mv.speed is not None and mv.speed > 5000:
            continue

        records.append({
            "t": round(ts, 3),
            "id": mv.entity_id,
            "x": mv.x,
            "z": mv.z,
            "speed": round(mv.speed, 1) if mv.speed is not None else None,
        })
        if ts > max_t:
            max_t = ts

    print(f"  {len(records):,} champion movement records (filtered)")
    return records, max_t


def build_entity_info() -> list[dict]:
    """Build entity metadata for the visualization."""
    entities = []
    for i, eid in enumerate(sorted(MAPPING.keys())):
        name, team = MAPPING[eid]
        color = ENTITY_COLORS[i % len(ENTITY_COLORS)]
        entities.append({
            "id": eid,
            "name": name,
            "team": team,
            "color": color,
        })
    return entities


def simulate_positions(records: list[dict], max_timestamp: float, step: float = 0.25) -> dict:
    """Interpolate champion positions between movement packet snapshots.

    Treats f10 as the entity's position at the time of the packet.
    Between packets, linearly interpolates position over time.

    Returns: {entity_id: [[t, x, z], ...]} with positions sampled every `step` seconds.
    """

    # Group records by entity, sorted by time
    by_entity: dict[int, list[dict]] = {}
    for r in records:
        by_entity.setdefault(r["id"], []).append(r)
    for arr in by_entity.values():
        arr.sort(key=lambda r: r["t"])

    result = {}
    for eid, snapshots in by_entity.items():
        if not snapshots:
            continue

        positions = []
        t = 0.0
        end_t = min(max_timestamp, snapshots[-1]["t"] + 10)
        snap_idx = 0

        while t <= end_t:
            # Advance snap_idx to the last snapshot <= t
            while snap_idx + 1 < len(snapshots) and snapshots[snap_idx + 1]["t"] <= t:
                snap_idx += 1

            if t < snapshots[0]["t"]:
                # Before first data: stay at first snapshot position
                positions.append([round(t, 2), snapshots[0]["x"], snapshots[0]["z"]])
            elif snap_idx + 1 < len(snapshots):
                # Between two snapshots: linear interpolation
                a = snapshots[snap_idx]
                b = snapshots[snap_idx + 1]
                dt = b["t"] - a["t"]
                if dt > 0 and dt < 60:  # interpolate within 60s gaps
                    frac = (t - a["t"]) / dt
                    x = round(a["x"] + (b["x"] - a["x"]) * frac)
                    z = round(a["z"] + (b["z"] - a["z"]) * frac)
                    positions.append([round(t, 2), x, z])
                else:
                    positions.append([round(t, 2), a["x"], a["z"]])
            else:
                # After last snapshot: stay at last position
                s = snapshots[snap_idx]
                positions.append([round(t, 2), s["x"], s["z"]])

            t += step

        result[str(eid)] = positions

    return result


def generate_html(records: list[dict], max_timestamp: float, entities: list[dict]) -> str:
    """Generate a self-contained HTML visualization."""

    # Pre-simulate positions: for each entity, compute actual position over time
    # by moving from one waypoint to the next at the given speed
    simulated = simulate_positions(records, max_timestamp)
    simulated_json = json.dumps(simulated, separators=(",", ":"))
    entities_json = json.dumps(entities, separators=(",", ":"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LoL Movement Visualizer</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    background: #0a0a0f;
    color: #ccc;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    min-height: 100vh;
    padding: 16px;
}}
h1 {{
    font-size: 18px;
    color: #c9aa71;
    margin-bottom: 12px;
    font-weight: 500;
    letter-spacing: 1px;
}}
#map-container {{
    position: relative;
    width: 620px;
    height: 620px;
    margin-bottom: 16px;
}}
canvas {{
    border: 1px solid #2a2a3a;
    border-radius: 4px;
    cursor: crosshair;
}}
#controls {{
    width: 620px;
    background: #12121a;
    border: 1px solid #2a2a3a;
    border-radius: 6px;
    padding: 16px;
}}
#time-display {{
    text-align: center;
    font-size: 22px;
    font-weight: 600;
    color: #e0d6c2;
    margin-bottom: 10px;
    font-variant-numeric: tabular-nums;
}}
#slider-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
}}
#timeline {{
    flex: 1;
    height: 6px;
    -webkit-appearance: none;
    appearance: none;
    background: #2a2a3a;
    border-radius: 3px;
    outline: none;
    cursor: pointer;
}}
#timeline::-webkit-slider-thumb {{
    -webkit-appearance: none;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #c9aa71;
    cursor: grab;
}}
#timeline::-moz-range-thumb {{
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #c9aa71;
    cursor: grab;
    border: none;
}}
#btn-row {{
    display: flex;
    align-items: center;
    gap: 8px;
    justify-content: center;
}}
button {{
    background: #1e1e2e;
    color: #c9aa71;
    border: 1px solid #3a3a4a;
    border-radius: 4px;
    padding: 6px 14px;
    cursor: pointer;
    font-size: 13px;
    transition: background 0.15s;
}}
button:hover {{ background: #2a2a3e; }}
button.active {{ background: #c9aa71; color: #0a0a0f; font-weight: 600; }}
#legend {{
    width: 620px;
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    margin-top: 12px;
    justify-content: center;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
}}
.legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
}}
#tooltip {{
    position: absolute;
    background: rgba(10,10,15,0.92);
    border: 1px solid #3a3a4a;
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 12px;
    pointer-events: none;
    display: none;
    color: #e0d6c2;
    z-index: 10;
}}
</style>
</head>
<body>
<h1>MOVEMENT VISUALIZER</h1>
<div id="map-container">
    <canvas id="map" width="620" height="620"></canvas>
    <div id="tooltip"></div>
</div>
<div id="controls">
    <div id="time-display">00:00</div>
    <div id="slider-row">
        <span style="font-size:11px;color:#666;">0:00</span>
        <input type="range" id="timeline" min="0" max="1000" value="0" step="1">
        <span id="max-time" style="font-size:11px;color:#666;">0:00</span>
    </div>
    <div id="btn-row">
        <button id="btn-play">&#9654; Play</button>
        <button class="speed-btn active" data-speed="1">1x</button>
        <button class="speed-btn" data-speed="2">2x</button>
        <button class="speed-btn" data-speed="5">5x</button>
        <button class="speed-btn" data-speed="10">10x</button>
    </div>
</div>
<div id="legend"></div>

<script>
// Simulated positions: {{entity_id: [[t, x, z], ...]}}
const SIM = {simulated_json};
const ENTITIES = {entities_json};
const MAX_TIME = {max_timestamp:.3f};
const MAP_SIZE = 620;
const COORD_MAX = 16383;
const TRAIL_LEN = 40;  // ~10 seconds of trail at 0.25s step
const STEP = 0.25;

const canvas = document.getElementById('map');
const ctx = canvas.getContext('2d');
const timeline = document.getElementById('timeline');
const timeDisplay = document.getElementById('time-display');
const maxTimeSpan = document.getElementById('max-time');
const tooltip = document.getElementById('tooltip');
const btnPlay = document.getElementById('btn-play');

let currentTime = 0;
let playing = false;
let playSpeed = 1;
let lastFrame = 0;
let animId = null;

function fmt(s) {{
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return m + ':' + (sec < 10 ? '0' : '') + sec;
}}

maxTimeSpan.textContent = fmt(MAX_TIME);
timeline.max = Math.ceil(MAX_TIME * 10);

// Binary search: find index of last entry with time <= t
function findIdx(arr, t) {{
    if (!arr || arr.length === 0) return -1;
    let lo = 0, hi = arr.length - 1;
    while (lo < hi) {{
        const mid = (lo + hi + 1) >> 1;
        if (arr[mid][0] <= t) lo = mid;
        else hi = mid - 1;
    }}
    if (arr[lo][0] > t) return -1;
    return lo;
}}

// Get current position for entity at time t
function getPosition(entityId, t) {{
    const arr = SIM[entityId];
    if (!arr) return null;
    const idx = findIdx(arr, t);
    if (idx < 0) return null;
    const pt = arr[idx];
    return {{ x: pt[1], z: pt[2] }};
}}

// Get trail positions (last N steps)
function getTrail(entityId, t) {{
    const arr = SIM[entityId];
    if (!arr) return [];
    const idx = findIdx(arr, t);
    if (idx < 0) return [];
    const start = Math.max(0, idx - TRAIL_LEN + 1);
    return arr.slice(start, idx + 1).map(p => ({{ x: p[1], z: p[2] }}));
}}

// Convert game coords to canvas coords
function toCanvas(x, z) {{
    const pad = 10;
    const usable = MAP_SIZE - 2 * pad;
    return [
        pad + (x / COORD_MAX) * usable,
        MAP_SIZE - pad - (z / COORD_MAX) * usable  // flip Y
    ];
}}

// Draw lane paths (rough lines)
function drawLanes() {{
    ctx.strokeStyle = 'rgba(60, 60, 80, 0.4)';
    ctx.lineWidth = 2;
    ctx.setLineDash([6, 4]);

    // Base positions (approximate)
    const blueBase = toCanvas(1000, 1000);
    const redBase = toCanvas(14000, 14000);

    // Mid lane: diagonal
    ctx.beginPath();
    ctx.moveTo(...blueBase);
    ctx.lineTo(...redBase);
    ctx.stroke();

    // Top lane: blue base -> top-left -> top-right -> red base
    const topL = toCanvas(1000, 14000);
    ctx.beginPath();
    ctx.moveTo(...blueBase);
    ctx.lineTo(...topL);
    ctx.lineTo(...redBase);
    ctx.stroke();

    // Bot lane: blue base -> bot-right -> red base
    const botR = toCanvas(14000, 1000);
    ctx.beginPath();
    ctx.moveTo(...blueBase);
    ctx.lineTo(...botR);
    ctx.lineTo(...redBase);
    ctx.stroke();

    // River: top-right to bot-left roughly
    ctx.strokeStyle = 'rgba(40, 80, 120, 0.35)';
    ctx.lineWidth = 3;
    const rivTL = toCanvas(3500, 12500);
    const rivBR = toCanvas(12500, 3500);
    ctx.beginPath();
    ctx.moveTo(...rivTL);
    ctx.lineTo(...rivBR);
    ctx.stroke();

    ctx.setLineDash([]);
}}

// Draw base markers
function drawBases() {{
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';

    // Blue base
    const [bx, by] = toCanvas(1000, 1000);
    ctx.fillStyle = 'rgba(74, 144, 217, 0.3)';
    ctx.beginPath();
    ctx.arc(bx, by, 18, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#4A90D9';
    ctx.fillText('BLUE', bx, by + 3);

    // Red base
    const [rx, ry] = toCanvas(14000, 14000);
    ctx.fillStyle = 'rgba(229, 62, 62, 0.3)';
    ctx.beginPath();
    ctx.arc(rx, ry, 18, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#E53E3E';
    ctx.fillText('RED', rx, ry + 3);
}}

function draw() {{
    ctx.fillStyle = '#0f0f18';
    ctx.fillRect(0, 0, MAP_SIZE, MAP_SIZE);

    drawLanes();
    drawBases();

    ENTITIES.forEach(ent => {{
        const trail = getTrail(ent.id, currentTime);
        if (trail.length === 0) return;

        // Draw trail
        if (trail.length > 1) {{
            for (let i = 0; i < trail.length - 1; i++) {{
                const alpha = 0.1 + 0.3 * (i / trail.length);
                const [x1, y1] = toCanvas(trail[i].x, trail[i].z);
                const [x2, y2] = toCanvas(trail[i + 1].x, trail[i + 1].z);
                ctx.strokeStyle = ent.color + Math.round(alpha * 255).toString(16).padStart(2, '0');
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.moveTo(x1, y1);
                ctx.lineTo(x2, y2);
                ctx.stroke();

                // Faint dot at each trail point
                ctx.fillStyle = ent.color + Math.round(alpha * 200).toString(16).padStart(2, '0');
                ctx.beginPath();
                ctx.arc(x1, y1, 2, 0, Math.PI * 2);
                ctx.fill();
            }}
        }}

        // Draw current position dot
        const cur = trail[trail.length - 1];
        const [cx, cy] = toCanvas(cur.x, cur.z);

        // Outer glow
        ctx.fillStyle = ent.color + '40';
        ctx.beginPath();
        ctx.arc(cx, cy, 10, 0, Math.PI * 2);
        ctx.fill();

        // Main dot
        ctx.fillStyle = ent.color;
        ctx.beginPath();
        ctx.arc(cx, cy, 5, 0, Math.PI * 2);
        ctx.fill();

        // Border
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(cx, cy, 5, 0, Math.PI * 2);
        ctx.stroke();

        // Label
        ctx.fillStyle = '#e0d6c2';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(ent.name, cx, cy - 10);
    }});
}}

function updateTime(t) {{
    currentTime = Math.max(0, Math.min(t, MAX_TIME));
    timeline.value = Math.round(currentTime * 10);
    timeDisplay.textContent = fmt(currentTime);
    draw();
}}

// Timeline slider
timeline.addEventListener('input', () => {{
    updateTime(parseInt(timeline.value) / 10);
}});

// Play/pause
function togglePlay() {{
    playing = !playing;
    btnPlay.textContent = playing ? '\\u23F8 Pause' : '\\u25B6 Play';
    if (playing) {{
        lastFrame = performance.now();
        animate();
    }} else {{
        if (animId) cancelAnimationFrame(animId);
    }}
}}
btnPlay.addEventListener('click', togglePlay);

function animate() {{
    if (!playing) return;
    const now = performance.now();
    const dt = (now - lastFrame) / 1000;
    lastFrame = now;
    updateTime(currentTime + dt * playSpeed);
    if (currentTime >= MAX_TIME) {{
        playing = false;
        btnPlay.textContent = '\\u25B6 Play';
        return;
    }}
    animId = requestAnimationFrame(animate);
}}

// Speed buttons
document.querySelectorAll('.speed-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
        document.querySelectorAll('.speed-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        playSpeed = parseInt(btn.dataset.speed);
    }});
}});

// Tooltip on hover
canvas.addEventListener('mousemove', (e) => {{
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    let found = null;
    ENTITIES.forEach(ent => {{
        const pos = getPosition(ent.id, currentTime);
        if (!pos) return;
        const [cx, cy] = toCanvas(pos.x, pos.z);
        const dist = Math.sqrt((mx - cx) ** 2 + (my - cy) ** 2);
        if (dist < 14) {{
            found = {{ ent, cur: pos }};
        }}
    }});

    if (found) {{
        const {{ ent, cur }} = found;
        tooltip.style.display = 'block';
        tooltip.style.left = (e.clientX - canvas.parentElement.getBoundingClientRect().left + 14) + 'px';
        tooltip.style.top = (e.clientY - canvas.parentElement.getBoundingClientRect().top - 10) + 'px';
        const spd = cur.speed != null ? cur.speed.toFixed(0) : '?';
        tooltip.innerHTML = '<b style="color:' + ent.color + '">' + ent.name + '</b> (ID ' + ent.id + ')<br>'
            + 'X: ' + cur.x + ' Z: ' + cur.z + '<br>'
            + 'Speed: ' + spd + ' | Team: ' + ent.team;
    }} else {{
        tooltip.style.display = 'none';
    }}
}});
canvas.addEventListener('mouseleave', () => {{ tooltip.style.display = 'none'; }});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {{
    if (e.code === 'Space') {{ e.preventDefault(); togglePlay(); }}
    if (e.code === 'ArrowRight') updateTime(currentTime + 5);
    if (e.code === 'ArrowLeft') updateTime(currentTime - 5);
}});

// Build legend
const legendDiv = document.getElementById('legend');
ENTITIES.forEach(ent => {{
    const item = document.createElement('div');
    item.className = 'legend-item';
    item.innerHTML = '<span class="legend-dot" style="background:' + ent.color + '"></span>'
        + '<span>' + ent.name + ' (' + ent.id + ')</span>';
    legendDiv.appendChild(item);
}});

// Initial draw
draw();
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Visualize champion movement from ROFL replays")
    parser.add_argument("replay", help="Path to .rofl replay file")
    parser.add_argument(
        "--binary",
        default=str(DEFAULT_BINARY),
        help="Path to unpacked game binary dump (default: ml/data/league_unpacked_patched.bin)",
    )
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    parser.add_argument("--port", type=int, default=0, help="HTTP server port (0 = random)")
    args = parser.parse_args()

    # Decode movement data
    records, max_t = decode_replay(args.replay, args.binary)
    if not records:
        print("ERROR: No movement records found!")
        sys.exit(1)

    entities = build_entity_info()
    print(f"\nGenerating visualization ({len(records):,} records, {max_t:.0f}s game time)...")

    html = generate_html(records, max_t, entities)

    # Save to ml/tools/movement_vis.html for reuse
    output_path = Path(__file__).resolve().parent / "movement_vis.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"Saved: {output_path}")

    # Also save to temp file and open in browser
    tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8")
    tmp.write(html)
    tmp.close()
    print(f"Temp:  {tmp.name}")

    if not args.no_browser:
        webbrowser.open(f"file:///{tmp.name}")
        print("\nOpened in browser. Press Ctrl+C to exit.")
    else:
        print(f"\nOpen {tmp.name} in your browser.")


if __name__ == "__main__":
    main()
