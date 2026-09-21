"""Prometheus metrics shared by all Response Orchestrator workers."""

from prometheus_client import Counter, Histogram

PLANS_TRIGGERED = Counter(
    "defense_plans_triggered_total",
    "Total defense plans triggered",
    ["status"],
)

PLANS_COMPLETED = Counter(
    "defense_plans_completed_total",
    "Total defense plans completed",
    ["verification_result"],
)

ACTIONS_EXECUTED = Counter(
    "defense_actions_executed_total",
    "Total defense actions executed",
    ["action_type", "adapter", "result"],
)

PLAN_DURATION = Histogram(
    "defense_plan_duration_seconds",
    "Time from plan trigger to completion",
)

APPROVAL_LATENCY = Histogram(
    "defense_approval_latency_seconds",
    "Time actions spend waiting for human approval",
)
