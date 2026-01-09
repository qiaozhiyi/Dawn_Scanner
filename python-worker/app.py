"""
Dawn Scanner - Python Worker API
Exposes scanning capabilities over HTTP for the Go backend.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, AnyHttpUrl

from worker import VulnerabilityScanner


app = FastAPI(
    title="Dawn Scanner Python Worker",
    description="HTTP API for vulnerability scanning tasks",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    url: AnyHttpUrl


class ScanResponse(BaseModel):
    url: str
    vulnerabilities: list[dict]
    summary: str
    timestamp: str
    scan_duration: float


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "dawn-scanner-python-worker"}


@app.post("/api/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    try:
        async with VulnerabilityScanner() as scanner:
            result = await scanner.scan_url(str(request.url))
        return {
            "url": result.url,
            "vulnerabilities": result.vulnerabilities,
            "summary": result.summary,
            "timestamp": result.timestamp,
            "scan_duration": result.scan_duration,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
