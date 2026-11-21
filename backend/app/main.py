import asyncio
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.crypto import validate_master_key
from app.db.session import SessionLocal
from app.services.scheduler import tick_schedules
from app.services.seed import seed_default_signatures

logger = logging.getLogger(__name__)


async def _scheduler_loop() -> None:
    while True:
        try:
            await asyncio.sleep(30)
            with SessionLocal() as db:
                tick_schedules(db)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Błąd pętli harmonogramu skanów: %s", exc)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_master_key()
    try:
        with SessionLocal() as db:
            inserted = seed_default_signatures(db)
            if inserted:
                logger.info("Zasileno %d domyślnych sygnatur pasywnych.", inserted)
    except Exception as exc:
        logger.warning("Pominięto seed sygnatur przy starcie: %s", exc)
    sched_task = asyncio.create_task(_scheduler_loop())
    try:
        yield
    finally:
        sched_task.cancel()
        try:
            await sched_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description="Middleware/Orkiestrator Attack Surface Intelligence (CBI AGH) <-> DefectDojo",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],
)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/")
def root() -> dict:
    return {"service": settings.app_name, "docs": "/docs"}
