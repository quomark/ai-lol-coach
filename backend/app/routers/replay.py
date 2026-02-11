"""Replay upload and coaching endpoints."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from backend.app.core.config import settings
from backend.app.models.schemas import CoachingResponse, PlayerSummary
from backend.app.services.coach import coaching_service
from backend.replay_parser import RoflParser

router = APIRouter(prefix="/api/replay", tags=["replay"])
parser = RoflParser()


@router.post("/upload", response_model=CoachingResponse)
async def upload_replay(
    file: UploadFile = File(...),
    summoner_name: str | None = Form(None),
    focus_areas: str | None = Form(None),  # comma-separated
):
    """
    Upload a .rofl replay file and get coaching advice.

    - **file**: The .rofl replay file
    - **summoner_name**: (optional) Which player to focus the analysis on
    - **focus_areas**: (optional) Comma-separated areas like "vision,cs,macro"
    """
    if not file.filename or not file.filename.endswith(".rofl"):
        raise HTTPException(status_code=400, detail="Please upload a .rofl replay file")

    # Save uploaded file
    file_id = uuid.uuid4().hex[:12]
    save_path = settings.UPLOAD_DIR / f"{file_id}.rofl"

    try:
        content = await file.read()
        save_path.write_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

    # Parse replay
    try:
        replay_data = parser.parse_bytes(content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse replay: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error parsing replay: {e}")

    # Generate coaching advice
    areas = [a.strip() for a in focus_areas.split(",")] if focus_areas else None
    result = coaching_service.analyze(replay_data, summoner_name, areas)

    # Build response
    players = []
    for p in replay_data.players:
        players.append(
            PlayerSummary(
                champion=p.champion,
                summoner_name=p.summoner_name,
                team="Blue" if p.team == "100" else "Red",
                role=p.role,
                kda=f"{p.kills}/{p.deaths}/{p.assists}",
                cs=p.cs,
                gold=p.gold_earned,
                damage_dealt=p.damage_dealt,
                vision_score=p.vision_score,
            )
        )

    return CoachingResponse(
        game_summary=result.get("game_summary", ""),
        players=players,
        coaching_advice=result.get("coaching_advice", ""),
        focus_player=result.get("focus_player"),
        strengths=result.get("strengths", []),
        weaknesses=result.get("weaknesses", []),
        actionable_tips=result.get("actionable_tips", []),
    )


@router.get("/health")
async def health():
    return {"status": "ok", "model_loaded": coaching_service._model_loaded}
