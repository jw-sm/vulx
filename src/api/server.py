from fastapi import FastAPI
from src.core.config import settings


app = FastAPI(
    title=settings.PROJECT_NAME,
)

if __name__ == "__main__":
    print(app.title)
