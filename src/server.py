from fastapi import FastAPI
from src.core.config import settings


app = FastAPI(
    title=settings.PROJECT_NAME,
)

if settings.all_cors_origins:
    app.add_middleware(allow_origins=settings.all_cors_origins)

if __name__ == "__main__":
    print(app.title)
