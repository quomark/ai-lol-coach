from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    APP_NAME: str = "AI LoL Coach"
    DEBUG: bool = True

    # Paths
    UPLOAD_DIR: Path = Path("uploads")
    MODEL_DIR: Path = Path("models")

    # Model
    BASE_MODEL: str = "mistralai/Mistral-7B-Instruct-v0.3"
    LORA_ADAPTER_PATH: str = ""  # set after fine-tuning
    USE_4BIT: bool = True

    # HuggingFace
    HF_DATASET: str = "maknee/league-of-legends-decoded-replay-packets"
    HF_TOKEN: str = ""

    # Riot API (optional, for enriching replay data with match metadata)
    RIOT_API_KEY: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
