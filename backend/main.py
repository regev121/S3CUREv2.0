from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import auth, scan
from backend.core.authentication.sessions import allowed_origins
from backend.core.graphLoader.s3Loader import IdentityConflict, IdentityNotFound, MinioError


app = FastAPI(title="S3CURE API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_cache_control(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": issue["loc"], "msg": issue["msg"], "type": issue["type"]}
        for issue in error.errors()
    ]})


@app.exception_handler(IdentityNotFound)
async def identity_not_found(request, error):
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(IdentityConflict)
async def identity_conflict(request, error):
    return JSONResponse(status_code=409, content={"detail": str(error)})


@app.exception_handler(MinioError)
@app.exception_handler(BotoCoreError)
@app.exception_handler(ClientError)
async def minio_unavailable(request, error):
    return JSONResponse(status_code=503, content={"detail": "The MinIO operation could not be completed."})


app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scanning & Risks"])
