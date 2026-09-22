import sys
from pathlib import Path

ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

from models import ApprovalTier, BlastRadius  # noqa: E402
from safety import determine_approval_tier  # noqa: E402


def test_high_confidence_medium_blast_requires_human_until_veto_window_exists():
    tier = determine_approval_tier(
        confidence=0.95,
        blast_radius=BlastRadius.MEDIUM,
        target_criticality="high",
        auto_execute_min=0.70,
        auto_veto_min=0.85,
    )
    assert tier == ApprovalTier.HUMAN_REQUIRED


def test_high_confidence_low_blast_remains_auto_safe():
    tier = determine_approval_tier(
        confidence=0.95,
        blast_radius=BlastRadius.LOW,
        target_criticality="high",
        auto_execute_min=0.70,
        auto_veto_min=0.85,
    )
    assert tier == ApprovalTier.AUTO_SAFE
