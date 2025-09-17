from dataclasses import dataclass
from typing import Dict, List
from datetime import datetime


@dataclass
class User:
    id: str
    username: str
    email: str
    role: str
    created_at: datetime
    last_login: datetime
    preferences: Dict


@dataclass
class ReviewResult:
    security_score: int
    quality_score: int
    vulnerabilities: List[Dict]
    issues: List[Dict]
    summary: str
    recommendations: List[str]
    approval: str
    ai_confidence: float