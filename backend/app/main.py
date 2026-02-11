from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.routers import replay

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered League of Legends coaching from replay analysis",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(replay.router)


@app.get("/")
async def root():
    return {"message": "AI LoL Coach API", "docs": "/docs"}


@app.on_event("startup")
async def startup():
    # Optionally load model on startup
    # coaching_service.load_model()
    pass
