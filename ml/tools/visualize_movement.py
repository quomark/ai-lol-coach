"""
Interactive champion movement visualizer for League of Legends ROFL replays.

Decodes all 0x025B movement packets from the 10 champion params,
uses lane-aware nearest-neighbor tracking to separate champion positions
from other entity positions, and generates an interactive HTML visualization.

Usage:
    uv run python -m ml.tools.visualize_movement
"""

from __future__ import annotations

import json
import math
import os
import sys
import webbrowser
from collections import defaultdict
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml.parsers.chunk_parser import parse_payload_frames
from ml.parsers.movement_decoder import MovementDecoder
from ml.parsers.rofl_parser import ROFLParser


# ── Champion definitions ──────────────────────────────────────────────

CHAMPIONS = [
    {"index": 0, "name": "Mordekaiser", "team": "blue", "lane": "TOP",     "param": 0x400000AE},
    {"index": 1, "name": "Viego",       "team": "blue", "lane": "JUNGLE",  "param": 0x400000AF},
    {"index": 2, "name": "Zilean",      "team": "blue", "lane": "MIDDLE",  "param": 0x400000B0},
    {"index": 3, "name": "Jhin",        "team": "blue", "lane": "BOTTOM",  "param": 0x400000B1},
    {"index": 4, "name": "Zoe",         "team": "blue", "lane": "SUPPORT", "param": 0x400000B2},
    {"index": 5, "name": "Gnar",        "team": "red",  "lane": "TOP",     "param": 0x400000B3},
    {"index": 6, "name": "Graves",      "team": "red",  "lane": "JUNGLE",  "param": 0x400000B4},
    {"index": 7, "name": "Garen",       "team": "red",  "lane": "MIDDLE",  "param": 0x400000B5},
    {"index": 8, "name": "Karthus",     "team": "red",  "lane": "BOTTOM",  "param": 0x400000B6},
    {"index": 9, "name": "Mel",         "team": "red",  "lane": "SUPPORT", "param": 0x400000B7},
]

# Expected starting positions at ~2 minutes (14-bit coords, 0-16383)
LANE_STARTS = {
    # (team, lane) -> (x, z)
    # LoL map: Blue base bottom-left (~500,500), Red base top-right (~14500,14500)
    # Top lane: runs along LEFT edge then TOP edge
    # Bot lane: runs along BOTTOM edge then RIGHT edge
    ("blue", "TOP"):     (1000, 10500),   # blue outer top turret area
    ("blue", "JUNGLE"):  (4000, 5500),    # blue jungle
    ("blue", "MIDDLE"):  (5800, 6400),    # blue outer mid turret
    ("blue", "BOTTOM"):  (10500, 1000),   # blue outer bot turret area
    ("blue", "SUPPORT"): (10500, 1500),   # with ADC in bot lane
    ("red", "TOP"):      (4300, 13900),   # red outer top turret area
    ("red", "JUNGLE"):   (11000, 10000),  # red jungle
    ("red", "MIDDLE"):   (9000, 8500),    # red outer mid turret
    ("red", "BOTTOM"):   (13900, 4500),   # red outer bot turret area
    ("red", "SUPPORT"):  (13300, 4500),   # with ADC in bot lane
}

# Team colors for visualization
BLUE_COLORS = ["#1E90FF", "#4169E1", "#6495ED", "#00BFFF", "#87CEEB"]
RED_COLORS  = ["#FF4444", "#FF6347", "#FF7F50", "#FF1493", "#FFB6C1"]


def get_champion_color(champ):
    """Get a distinct color for each champion."""
    idx = champ["index"]
    if champ["team"] == "blue":
        return BLUE_COLORS[idx % 5]
    else:
        return RED_COLORS[idx % 5]


# ── Replay parsing ────────────────────────────────────────────────────

def parse_replay(replay_path: str) -> dict:
    """Parse the replay and extract all 0x025B movement data per champion param."""
    print(f"Parsing replay: {replay_path}")
    parser = ROFLParser(replay_path)

    # Decompress payload frames
    print("Decompressing payload frames...")
    frames = parser.decompress_payload_frames()
    print(f"  Got {len(frames)} decompressed frames")

    # Parse into structured frames with packets
    print("Parsing payload frames...")
    result = parse_payload_frames(frames)
    print(f"  Got {len(result.frames)} parsed frames, {result.total_packets} total packets")

    # Build param set for champion params
    champion_params = {c["param"] for c in CHAMPIONS}
    param_to_index = {c["param"]: c["index"] for c in CHAMPIONS}

    # Collect 0x025B packets per champion, only from chunks (frame_type==1)
    decoder = MovementDecoder()
    positions_by_champ = defaultdict(list)  # champ_index -> [(timestamp, x, z, speed, entity_id), ...]

    total_025b = 0
    champ_025b = 0

    for frame in result.frames:
        if frame.header.frame_type != 1:  # chunks only
            continue
        for pkt in frame.packets:
            if pkt.packet_id != 0x025B:
                continue
            total_025b += 1

            if pkt.param not in champion_params:
                continue
            champ_025b += 1

            mov = decoder.decode(pkt.data)
            if mov is None:
                continue
            if mov.x == 0 and mov.z == 0:
                continue

            champ_idx = param_to_index[pkt.param]
            positions_by_champ[champ_idx].append((
                pkt.timestamp,
                mov.x,
                mov.z,
                mov.speed if mov.speed is not None else 0,
                mov.entity_id,
            ))

    print(f"  Total 0x025B packets: {total_025b}")
    print(f"  Champion 0x025B packets: {champ_025b}")
    for idx in sorted(positions_by_champ.keys()):
        c = CHAMPIONS[idx]
        print(f"    {c['name']:15s} (param {c['param']:#010x}): {len(positions_by_champ[idx])} positions")

    return positions_by_champ


# ── Nearest-neighbor tracking ─────────────────────────────────────────

def _build_sync_exclusives(all_params_data, champ_params):
    """
    For each sync burst, find positions exclusive to each param.
    Returns {param: {sync_time: [(x, z), ...]}}
    """
    from collections import Counter

    # Identify sync burst timestamps
    ts_counts = Counter()
    for param, pts in all_params_data.items():
        for t, x, z in pts:
            ts_counts[round(t)] += 1
    sync_times = sorted(t for t, cnt in ts_counts.items() if cnt >= 30)

    # At each sync, track which positions appear under which params
    result = {p: {} for p in champ_params}
    for t_sync in sync_times:
        pos_params = defaultdict(set)
        param_positions = defaultdict(set)
        for param in champ_params:
            for t, x, z in all_params_data.get(param, []):
                if abs(t - t_sync) < 2:
                    pos_params[(x, z)].add(param)
                    param_positions[param].add((x, z))

        for param in champ_params:
            exclusives = []
            shared = []
            for pos in param_positions.get(param, set()):
                if len(pos_params[pos]) <= 2:
                    exclusives.append(pos)
                else:
                    shared.append(pos)
            result[param][t_sync] = (exclusives, shared)

    return result, sync_times


def track_champion_from_seed(positions: list, seed_x: float, seed_z: float,
                             seed_time: float = 56.0) -> list:
    """
    Track a champion using nearest-neighbor from a verified seed,
    searching through positions from the champion's own param.

    No static filter — structures are avoided by the tight search radius.
    Forward + backward tracking from the seed timestamp.
    """
    if not positions:
        return []

    # Group into 1s time windows
    time_groups = defaultdict(list)
    for ts, x, z, speed, eid in positions:
        t_key = round(ts)
        time_groups[t_key].append((x, z))

    sorted_times = sorted(time_groups.keys())

    def track_direction(times_iter, seed_x, seed_z):
        cur_x, cur_z = seed_x, seed_z
        result = []
        for t in times_iter:
            dt = abs(t - result[-1][0]) if result else 1.0
            dt = max(dt, 0.5)
            # Tight radius: champions move ~400 u/s, allow 600 for dashes/flash
            max_dist = min(600 * dt, 5000)

            best_dist = float('inf')
            best_x, best_z = None, None
            for cx, cz in time_groups[t]:
                dist = math.sqrt((cx - cur_x) ** 2 + (cz - cur_z) ** 2)
                if dist < best_dist and dist <= max_dist:
                    best_dist = dist
                    best_x, best_z = cx, cz

            if best_x is not None:
                cur_x, cur_z = best_x, best_z
            result.append((t, cur_x, cur_z))
        return result

    # Forward from seed
    forward_times = [t for t in sorted_times if t >= seed_time]
    forward = track_direction(forward_times, seed_x, seed_z)

    # Backward from seed
    backward_times = [t for t in reversed(sorted_times) if t < seed_time]
    backward = track_direction(backward_times, seed_x, seed_z)
    backward.reverse()

    tracked = backward + forward

    # Keep points where position changed, or every 15s if stationary
    if not tracked:
        return []
    deduped = [tracked[0]]
    for t, x, z in tracked[1:]:
        if x != deduped[-1][1] or z != deduped[-1][2]:
            deduped.append((t, x, z))
        elif t - deduped[-1][0] >= 15:
            deduped.append((t, x, z))

    return deduped


def track_all_champions(positions_by_champ: dict) -> dict:
    """Track all 10 champions simultaneously using Hungarian assignment at each sync burst."""
    import numpy as np
    from scipy.optimize import linear_sum_assignment
    from collections import Counter

    # Collect all decoded positions with timestamps
    all_decoded = []
    for idx, positions in positions_by_champ.items():
        for ts, x, z, spd, eid in positions:
            if x > 0 and z > 0:
                all_decoded.append((ts, x, z))

    # Find sync burst timestamps
    ts_counts = Counter(round(t) for t, x, z in all_decoded)
    sync_times = sorted(t for t, cnt in ts_counts.items() if cnt >= 30)
    print(f"  Sync bursts: {len(sync_times)} (every ~{sync_times[1]-sync_times[0]}s)")

    # At each sync, get unique positions
    sync_positions = {}
    for t_sync in sync_times:
        pts = set()
        for t, x, z in all_decoded:
            if abs(t - t_sync) < 2:
                pts.add((x, z))
        sync_positions[t_sync] = list(pts)

    # Identify structure positions: same (x,z) appearing in 4+ different syncs
    from collections import Counter as Ctr
    pos_sync_count = Ctr()
    for t_sync, pts in sync_positions.items():
        for p in pts:
            pos_sync_count[p] += 1
    structure_coords = {p for p, cnt in pos_sync_count.items() if cnt >= 4}
    print(f"  Structures removed: {len(structure_coords)} static positions")

    # Filter structures out
    for t_sync in sync_positions:
        sync_positions[t_sync] = [p for p in sync_positions[t_sync]
                                  if p not in structure_coords]

    # Seed positions at t=56 (verified by watching replay)
    cur_positions = [
        (1716, 12706),  # 0: Mordekaiser
        (3759, 7558),   # 1: Viego
        (7456, 7293),   # 2: Zilean
        (12931, 1471),  # 3: Jhin
        (12686, 1369),  # 4: Zoe
        (4596, 12829),  # 5: Gnar
        (8927, 10275),  # 6: Graves
        (9397, 8008),   # 7: Garen
        (13544, 1287),  # 8: Karthus
        (13258, 1287),  # 9: Mel
    ]

    # Track through sync bursts using Hungarian assignment
    tracks = {i: [] for i in range(10)}

    for t_sync in sync_times:
        candidates = sync_positions[t_sync]
        if len(candidates) < 10:
            # Not enough positions — keep current
            for i in range(10):
                tracks[i].append((t_sync, cur_positions[i][0], cur_positions[i][1]))
            continue

        # Build cost matrix: distance from each champion's CURRENT position
        n = len(candidates)
        cost = np.zeros((10, n))
        for i in range(10):
            cx, cz = cur_positions[i]
            for j, (px, pz) in enumerate(candidates):
                cost[i, j] = math.sqrt((px - cx) ** 2 + (pz - cz) ** 2)

        row_ind, col_ind = linear_sum_assignment(cost)

        for i, j in zip(row_ind, col_ind):
            px, pz = candidates[j]
            d = cost[i, j]
            # Only update if reasonable distance (champion can't teleport >8000u between syncs)
            if d < 8000:
                cur_positions[i] = (px, pz)
            tracks[i].append((t_sync, cur_positions[i][0], cur_positions[i][1]))

    # Build final tracked dict
    tracked = {}
    for champ in CHAMPIONS:
        idx = champ["index"]
        track = tracks[idx]
        # Dedup consecutive same positions
        deduped = [track[0]] if track else []
        for t, x, z in track[1:]:
            if x != deduped[-1][1] or z != deduped[-1][2] or t - deduped[-1][0] >= 60:
                deduped.append((t, x, z))
        tracked[idx] = deduped
        print(f"  {champ['name']:15s}: {len(deduped)} tracked points")

    return tracked


# ── HTML visualization generation ─────────────────────────────────────

def generate_html(tracked: dict, output_path: str):
    """Generate a self-contained interactive HTML visualization."""

    # Prepare data for JSON embedding
    champ_data = []
    all_times = set()

    for champ in CHAMPIONS:
        idx = champ["index"]
        track = tracked.get(idx, [])
        color = get_champion_color(champ)

        # Downsample to at most ~2000 points per champion for performance
        if len(track) > 2000:
            step = len(track) // 2000
            track = track[::step]

        positions = [{"t": round(t, 2), "x": x, "z": z} for t, x, z in track]
        for p in positions:
            all_times.add(p["t"])

        champ_data.append({
            "index": idx,
            "name": champ["name"],
            "team": champ["team"],
            "lane": champ["lane"],
            "color": color,
            "positions": positions,
        })

    sorted_times = sorted(all_times)
    min_time = sorted_times[0] if sorted_times else 0
    max_time = sorted_times[-1] if sorted_times else 0

    data_json = json.dumps(champ_data)
    min_time_json = json.dumps(min_time)
    max_time_json = json.dumps(max_time)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>LoL Champion Movement Visualization</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0a0a1a; color: #e0e0e0; font-family: 'Segoe UI', Arial, sans-serif; overflow: hidden; }}

#container {{
    display: flex;
    flex-direction: column;
    height: 100vh;
    padding: 10px;
}}

#header {{
    text-align: center;
    padding: 5px 0;
    font-size: 18px;
    font-weight: bold;
    color: #c9aa71;
}}

#main {{
    display: flex;
    flex: 1;
    gap: 15px;
    min-height: 0;
}}

#map-container {{
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}}

#map-canvas {{
    border: 2px solid #333;
    border-radius: 4px;
    cursor: crosshair;
}}

#sidebar {{
    width: 220px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    overflow-y: auto;
}}

.champ-card {{
    padding: 8px 10px;
    border-radius: 6px;
    background: #1a1a2e;
    border: 2px solid transparent;
    cursor: pointer;
    transition: border-color 0.2s;
    display: flex;
    align-items: center;
    gap: 8px;
}}

.champ-card:hover {{
    border-color: #555;
}}

.champ-card.active {{
    border-color: var(--champ-color);
}}

.champ-dot {{
    width: 14px;
    height: 14px;
    border-radius: 50%;
    flex-shrink: 0;
}}

.champ-name {{
    font-weight: bold;
    font-size: 13px;
}}

.champ-info {{
    font-size: 11px;
    color: #888;
}}

.champ-pos {{
    font-size: 11px;
    color: #aaa;
    font-family: monospace;
}}

.team-header {{
    font-weight: bold;
    font-size: 14px;
    padding: 4px 8px;
    border-radius: 4px;
}}

.team-blue {{ color: #4488ff; background: #0a1530; }}
.team-red {{ color: #ff4444; background: #300a0a; }}

#controls {{
    padding: 10px 20px;
    display: flex;
    align-items: center;
    gap: 15px;
    background: #111;
    border-radius: 6px;
    margin-top: 8px;
}}

#play-btn {{
    background: #c9aa71;
    color: #111;
    border: none;
    padding: 8px 20px;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    font-size: 14px;
    min-width: 70px;
}}

#play-btn:hover {{ background: #ddc090; }}

#timeline {{
    flex: 1;
    height: 6px;
    -webkit-appearance: none;
    appearance: none;
    background: #333;
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
    cursor: pointer;
}}

#time-display {{
    font-family: monospace;
    font-size: 14px;
    min-width: 80px;
    text-align: center;
    color: #c9aa71;
}}

#speed-control {{
    display: flex;
    align-items: center;
    gap: 5px;
}}

#speed-control label {{
    font-size: 12px;
    color: #888;
}}

#speed-select {{
    background: #222;
    color: #ddd;
    border: 1px solid #444;
    padding: 3px 6px;
    border-radius: 3px;
    font-size: 12px;
}}

#trail-toggle {{
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: #888;
    cursor: pointer;
}}

#trail-toggle input {{
    cursor: pointer;
}}

</style>
</head>
<body>

<div id="container">
    <div id="header">Champion Movement Tracker - ROFL Replay Analysis</div>

    <div id="main">
        <div id="map-container">
            <canvas id="map-canvas"></canvas>
        </div>

        <div id="sidebar">
            <div class="team-header team-blue">Blue Team</div>
            <div id="blue-champs"></div>
            <div class="team-header team-red">Red Team</div>
            <div id="red-champs"></div>
        </div>
    </div>

    <div id="controls">
        <button id="play-btn" onclick="togglePlay()">Play</button>
        <input type="range" id="timeline" min="0" max="1000" value="0" oninput="onTimelineInput(this.value)">
        <span id="time-display">0:00</span>
        <div id="speed-control">
            <label>Speed:</label>
            <select id="speed-select" onchange="setSpeed(this.value)">
                <option value="0.5">0.5x</option>
                <option value="1" selected>1x</option>
                <option value="2">2x</option>
                <option value="4">4x</option>
                <option value="8">8x</option>
                <option value="16">16x</option>
            </select>
        </div>
        <label id="trail-toggle">
            <input type="checkbox" id="trail-check" checked onchange="toggleTrail()"> Trail
        </label>
    </div>
</div>

<script>
// ── Data ──
const champData = {data_json};
const minTime = {min_time_json};
const maxTime = {max_time_json};

// ── State ──
let currentTime = minTime;
let playing = false;
let playSpeed = 1;
let showTrail = true;
let activeChamps = new Set(champData.map(c => c.index));
let animFrame = null;
let lastFrameTime = 0;

// Map dimensions (14-bit coords)
const MAP_MIN = 0;
const MAP_MAX = 16383;
const MAP_PADDING = 30;

// ── Canvas setup ──
const canvas = document.getElementById('map-canvas');
const ctx = canvas.getContext('2d');

function resizeCanvas() {{
    const container = document.getElementById('map-container');
    const size = Math.min(container.clientWidth - 20, container.clientHeight - 20);
    canvas.width = size;
    canvas.height = size;
    draw();
}}

window.addEventListener('resize', resizeCanvas);

// ── Coordinate transforms ──
function mapToCanvas(x, z) {{
    // LoL: x is horizontal, z is vertical. In LoL, z increases upward.
    // On canvas, y increases downward, so we flip z.
    const pad = MAP_PADDING;
    const drawSize = canvas.width - 2 * pad;
    const cx = pad + (x - MAP_MIN) / (MAP_MAX - MAP_MIN) * drawSize;
    const cy = pad + (1 - (z - MAP_MIN) / (MAP_MAX - MAP_MIN)) * drawSize;
    return [cx, cy];
}}

// ── Build sidebar ──
function buildSidebar() {{
    const blueDiv = document.getElementById('blue-champs');
    const redDiv = document.getElementById('red-champs');

    champData.forEach(champ => {{
        const card = document.createElement('div');
        card.className = 'champ-card active';
        card.style.setProperty('--champ-color', champ.color);
        card.id = 'card-' + champ.index;

        card.innerHTML = `
            <div class="champ-dot" style="background:${{champ.color}}"></div>
            <div>
                <div class="champ-name">${{champ.name}}</div>
                <div class="champ-info">${{champ.lane}}</div>
                <div class="champ-pos" id="pos-${{champ.index}}">--</div>
            </div>
        `;

        card.onclick = () => {{
            if (activeChamps.has(champ.index)) {{
                activeChamps.delete(champ.index);
                card.classList.remove('active');
            }} else {{
                activeChamps.add(champ.index);
                card.classList.add('active');
            }}
            draw();
        }};

        if (champ.team === 'blue') blueDiv.appendChild(card);
        else redDiv.appendChild(card);
    }});
}}

// ── Interpolate position at time t ──
function getPositionAtTime(champ, t) {{
    const pos = champ.positions;
    if (pos.length === 0) return null;
    if (t <= pos[0].t) return {{ x: pos[0].x, z: pos[0].z }};
    if (t >= pos[pos.length - 1].t) return {{ x: pos[pos.length - 1].x, z: pos[pos.length - 1].z }};

    // Binary search
    let lo = 0, hi = pos.length - 1;
    while (lo < hi - 1) {{
        const mid = (lo + hi) >> 1;
        if (pos[mid].t <= t) lo = mid;
        else hi = mid;
    }}

    const p0 = pos[lo], p1 = pos[hi];
    const dt = p1.t - p0.t;
    if (dt === 0) return {{ x: p0.x, z: p0.z }};
    const frac = (t - p0.t) / dt;

    return {{
        x: p0.x + (p1.x - p0.x) * frac,
        z: p0.z + (p1.z - p0.z) * frac,
    }};
}}

// ── Draw map ──
function drawMapBackground() {{
    const w = canvas.width;
    const h = canvas.height;

    // Dark green map background
    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, w, h);

    // Map area
    const pad = MAP_PADDING;
    const drawSize = w - 2 * pad;
    ctx.fillStyle = '#111a15';
    ctx.fillRect(pad, pad, drawSize, drawSize);

    // Grid lines
    ctx.strokeStyle = '#1a2a20';
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 10; i++) {{
        const frac = i / 10;
        const x = pad + frac * drawSize;
        const y = pad + frac * drawSize;
        ctx.beginPath();
        ctx.moveTo(x, pad); ctx.lineTo(x, pad + drawSize);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(pad, y); ctx.lineTo(pad + drawSize, y);
        ctx.stroke();
    }}

    // Lane indicators (subtle)
    ctx.strokeStyle = '#223322';
    ctx.lineWidth = 8;
    ctx.globalAlpha = 0.3;

    // Top lane (left edge, top edge)
    const [tlx1, tly1] = mapToCanvas(500, 500);
    const [tlx2, tly2] = mapToCanvas(500, 14500);
    const [tlx3, tly3] = mapToCanvas(14500, 14500);
    ctx.beginPath();
    ctx.moveTo(tlx1, tly1); ctx.lineTo(tlx2, tly2); ctx.lineTo(tlx3, tly3);
    ctx.stroke();

    // Bot lane (bottom edge, right edge)
    const [blx1, bly1] = mapToCanvas(500, 500);
    const [blx2, bly2] = mapToCanvas(14500, 500);
    const [blx3, bly3] = mapToCanvas(14500, 14500);
    ctx.beginPath();
    ctx.moveTo(blx1, bly1); ctx.lineTo(blx2, bly2); ctx.lineTo(blx3, bly3);
    ctx.stroke();

    // Mid lane (diagonal)
    const [mlx1, mly1] = mapToCanvas(500, 500);
    const [mlx2, mly2] = mapToCanvas(14500, 14500);
    ctx.beginPath();
    ctx.moveTo(mlx1, mly1); ctx.lineTo(mlx2, mly2);
    ctx.stroke();

    ctx.globalAlpha = 1.0;

    // Fountain markers
    ctx.fillStyle = '#224488';
    const [bfx, bfy] = mapToCanvas(500, 500);
    ctx.beginPath(); ctx.arc(bfx, bfy, 8, 0, Math.PI * 2); ctx.fill();

    ctx.fillStyle = '#884422';
    const [rfx, rfy] = mapToCanvas(14500, 14500);
    ctx.beginPath(); ctx.arc(rfx, rfy, 8, 0, Math.PI * 2); ctx.fill();

    // Labels
    ctx.font = '10px monospace';
    ctx.fillStyle = '#446644';
    ctx.textAlign = 'center';
    ctx.fillText('BLUE', bfx, bfy + 20);
    ctx.fillText('RED', rfx, rfy - 14);
}}

function draw() {{
    drawMapBackground();

    champData.forEach(champ => {{
        if (!activeChamps.has(champ.index)) return;

        const pos = champ.positions;
        if (pos.length === 0) return;

        // Draw trail
        if (showTrail) {{
            ctx.strokeStyle = champ.color;
            ctx.globalAlpha = 0.15;
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            let started = false;

            // Only draw trail up to current time, and limit to last 60s
            const trailStart = Math.max(minTime, currentTime - 60);

            for (let i = 0; i < pos.length; i++) {{
                if (pos[i].t > currentTime) break;
                if (pos[i].t < trailStart) continue;

                const [cx, cy] = mapToCanvas(pos[i].x, pos[i].z);
                if (!started) {{
                    ctx.moveTo(cx, cy);
                    started = true;
                }} else {{
                    ctx.lineTo(cx, cy);
                }}
            }}
            ctx.stroke();
            ctx.globalAlpha = 1.0;
        }}

        // Draw current position
        const curPos = getPositionAtTime(champ, currentTime);
        if (curPos) {{
            const [cx, cy] = mapToCanvas(curPos.x, curPos.z);

            // Outer glow
            ctx.fillStyle = champ.color;
            ctx.globalAlpha = 0.3;
            ctx.beginPath();
            ctx.arc(cx, cy, 10, 0, Math.PI * 2);
            ctx.fill();

            // Inner dot
            ctx.globalAlpha = 1.0;
            ctx.fillStyle = champ.color;
            ctx.beginPath();
            ctx.arc(cx, cy, 5, 0, Math.PI * 2);
            ctx.fill();

            // Label
            ctx.fillStyle = '#fff';
            ctx.font = 'bold 10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(champ.name, cx, cy - 12);

            // Update sidebar
            const posEl = document.getElementById('pos-' + champ.index);
            if (posEl) posEl.textContent = `(${{Math.round(curPos.x)}}, ${{Math.round(curPos.z)}})`;
        }}
    }});
}}

// ── Playback controls ──
function togglePlay() {{
    playing = !playing;
    document.getElementById('play-btn').textContent = playing ? 'Pause' : 'Play';
    if (playing) {{
        lastFrameTime = performance.now();
        animFrame = requestAnimationFrame(animate);
    }} else if (animFrame) {{
        cancelAnimationFrame(animFrame);
    }}
}}

function animate(timestamp) {{
    if (!playing) return;

    const elapsed = (timestamp - lastFrameTime) / 1000;
    lastFrameTime = timestamp;

    currentTime += elapsed * playSpeed;
    if (currentTime > maxTime) {{
        currentTime = maxTime;
        playing = false;
        document.getElementById('play-btn').textContent = 'Play';
    }}

    updateTimeline();
    draw();

    if (playing) {{
        animFrame = requestAnimationFrame(animate);
    }}
}}

function onTimelineInput(val) {{
    const frac = val / 1000;
    currentTime = minTime + frac * (maxTime - minTime);
    updateTimeline();
    draw();
}}

function updateTimeline() {{
    const frac = (currentTime - minTime) / (maxTime - minTime);
    document.getElementById('timeline').value = Math.round(frac * 1000);

    const totalSec = Math.floor(currentTime);
    const m = Math.floor(totalSec / 60);
    const s = totalSec % 60;
    document.getElementById('time-display').textContent = m + ':' + String(s).padStart(2, '0');
}}

function setSpeed(val) {{
    playSpeed = parseFloat(val);
}}

function toggleTrail() {{
    showTrail = document.getElementById('trail-check').checked;
    draw();
}}

// ── Init ──
buildSidebar();
resizeCanvas();
updateTimeline();
draw();

</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"HTML visualization saved to: {output_path}")


# ── Main ──────────────────────────────────────────────────────────────

def main():
    replay_path = "/Users/danielngai/Documents/League of Legends/Replays/TW2-396324158.rofl"
    output_path = str(PROJECT_ROOT / "ml" / "tools" / "movement_vis.html")

    print("=" * 60)
    print("  Champion Movement Visualization")
    print("=" * 60)

    # Step 1: Parse replay and extract movement packets
    positions_by_champ = parse_replay(replay_path)

    # Step 2: Track champions using lane-aware nearest-neighbor
    print("\nTracking champions...")
    tracked = track_all_champions(positions_by_champ)

    # Step 3: Generate HTML visualization
    print("\nGenerating visualization...")
    generate_html(tracked, output_path)

    # Step 4: Open in browser
    print("Opening in browser...")
    webbrowser.open("file://" + os.path.abspath(output_path))

    print("\nDone!")


if __name__ == "__main__":
    main()
