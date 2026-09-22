"""
Pydantic Models - Feedback Service
AI-Augmented SOC

Data models for alert persistence and analyst feedback.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, field_validator, model_validator


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertCategory(str, Enum):
    MALWARE = "malware"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    COMMAND_AND_CONTROL = "command_and_control"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    OTHER = "other"


# --- Request Models ---

class StoreAlertRequest(BaseModel):
    """Request to persist an alert and its triage result."""
    alert_id: str = Field(..., description="Unique alert identifier")
    wazuh_alert_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    rule_level: Optional[int] = None
    raw_alert: Optional[Dict[str, Any]] = Field(None, description="Full SecurityAlert as dict")
    triage_result: Optional[Dict[str, Any]] = Field(None, description="Full TriageResponse as dict")
    ai_severity: Optional[str] = None
    ai_category: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_is_true_positive: Optional[bool] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None


class FeedbackSubmission(BaseModel):
    """Analyst feedback on a triage result."""

    analyst_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Analyst identifier",
    )
    true_severity: Optional[SeverityLevel] = Field(None, description="Corrected severity")
    true_category: Optional[AlertCategory] = Field(None, description="Corrected category")
    is_false_positive: bool = Field(False, description="Mark as false positive")
    true_label: Optional[str] = Field(
        None,
        max_length=20,
        description="Ground truth label for current binary ML retraining (BENIGN or ATTACK)",
    )
    notes: Optional[str] = Field(None, max_length=2000, description="Analyst notes")

    @field_validator("analyst_id", mode="before")
    @classmethod
    def normalize_analyst_id(cls, value: str) -> str:
        """Reject blank identifiers while normalizing surrounding whitespace."""
        if not isinstance(value, str):
            raise ValueError("analyst_id must be a string")
        value = value.strip()
        if not value:
            raise ValueError("analyst_id must not be blank")
        return value

    @field_validator("true_label", mode="before")
    @classmethod
    def normalize_true_label(cls, value: Optional[str]) -> Optional[str]:
        """Normalize and restrict labels to the current binary ML contract."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("true_label must be a string")
        value = value.strip().upper()
        if value not in {"BENIGN", "ATTACK"}:
            raise ValueError("true_label must be BENIGN or ATTACK")
        return value

    @model_validator(mode="after")
    def validate_label_consistency(self):
        """Keep false-positive state consistent with the retraining label."""
        if self.true_label == "BENIGN" and not self.is_false_positive:
            raise ValueError("BENIGN feedback must be marked as a false positive")
        if self.true_label == "ATTACK" and self.is_false_positive:
            raise ValueError("ATTACK feedback cannot be marked as a false positive")
        return self


class AlertQuery(BaseModel):
    """Query parameters for alert search."""
    limit: int = Field(50, ge=1, le=200)
    offset: int = Field(0, ge=0)
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    has_feedback: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


# --- Response Models ---

class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""
    feedback_id: str
    alert_id: str
    analyst_id: str
    is_false_positive: bool
    created_at: datetime


class StoredAlertResponse(BaseModel):
    """A persisted alert with its triage result and feedback."""
    alert_id: str
    wazuh_alert_id: Optional[str] = None
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    rule_level: Optional[int] = None
    ai_severity: Optional[str] = None
    ai_category: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_is_true_positive: Optional[bool] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    created_at: datetime
    feedback_count: int = 0
    feedback: List[Dict[str, Any]] = []


class FeedbackStats(BaseModel):
    """Aggregated feedback statistics."""
    total_alerts: int = 0
    total_feedback: int = 0
    false_positive_count: int = 0
    false_positive_rate: float = 0.0
    severity_corrections: int = 0
    severity_correction_rate: float = 0.0
    category_corrections: int = 0
    labeled_for_retraining: int = 0
    avg_confidence_when_correct: Optional[float] = None
    avg_confidence_when_wrong: Optional[float] = None
    top_false_positive_sources: List[Dict[str, Any]] = []
