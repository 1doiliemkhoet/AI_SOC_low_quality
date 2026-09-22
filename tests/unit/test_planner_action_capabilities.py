import sys
from pathlib import Path

ORCHESTRATOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "response-orchestrator"
)
if str(ORCHESTRATOR_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

from d3fend import get_countermeasures  # noqa: E402
from models import ActionType, AdapterType  # noqa: E402
from planner import DefensePlanner  # noqa: E402


def test_filter_executable_candidates_excludes_placeholder_adapters():
    planner = DefensePlanner()
    candidates = [
        get_countermeasures("T1110")[0],
        get_countermeasures("T1110")[1],
        get_countermeasures("T1110")[2],
    ]
    filtered = planner._filter_executable_candidates(candidates)
    assert filtered
    assert all(
        candidate.adapter == AdapterType.WAZUH
        and candidate.action_type in {ActionType.BLOCK_IP, ActionType.ISOLATE_HOST}
        for candidate in filtered
    )


def test_filter_executable_candidates_excludes_process_termination_without_runtime_params():
    planner = DefensePlanner()
    candidates = get_countermeasures("T1003")
    filtered = planner._filter_executable_candidates(candidates)
    assert all(candidate.action_type != ActionType.KILL_PROCESS for candidate in filtered)


def test_filter_executable_candidates_returns_empty_when_no_runtime_action_is_available():
    planner = DefensePlanner()
    candidates = get_countermeasures("T1078")
    filtered = planner._filter_executable_candidates(candidates)
    assert filtered == []
