from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class EngineDetection(BaseModel):
    engine_name: str
    category: str
    result: Optional[str] = None
    method: Optional[str] = None


class AnalysisStats(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0


class AnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    status: str
    sha256: str
    file_size: int
    is_cached: bool = False
    stats: Optional[Dict[str, int]] = None
    malicious: int = 0
    suspicious: int = 0
    total_engines: int = 0
    verdict: Optional[str] = None
    detections: List[EngineDetection] = Field(default_factory=list)


class StatusResponse(BaseModel):
    status: str
    stats: Optional[Dict[str, int]] = None
    malicious: int = 0
    suspicious: int = 0
    total_engines: int = 0
    verdict: Optional[str] = None
    detections: List[EngineDetection] = Field(default_factory=list)
