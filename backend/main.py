import os

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import auth, scan
from backend.core.graphLoader.s3Loader import IdentityNotFound, MinioError


app = FastAPI(title="S3CURE API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("S3CURE_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(IdentityNotFound)
async def identity_not_found(request, error):
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(MinioError)
@app.exception_handler(BotoCoreError)
@app.exception_handler(ClientError)
async def minio_unavailable(request, error):
    return JSONResponse(status_code=503, content={"detail": "The MinIO operation could not be completed."})


app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scanning & Risks"])
