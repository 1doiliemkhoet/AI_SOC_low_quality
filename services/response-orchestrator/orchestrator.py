"""
Core Orchestrator - Response Orchestrator Service
AI-Augmented SOC

The central state machine that drives the autonomous defense loop:

  TRIGGERED → SIMULATING → PLANNING → AWAITING_APPROVAL →
  EXECUTING → VERIFYING → COMPLETED (or ROLLED_BACK)

Each transition is logged, persisted, and observable via API.
The orchestrator coordinates between:
  - Correlation Engine (incident data, simulation)
  - Defense Planner (D3FEND lookup, LLM scoring)
  - Action Execution Layer (adapters)
  - Verification Engine (re-simulation, monitoring)
  - Feedback Service (outcome recording)
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


import httpx
from sqlalchemy import desc, select

from models import (
    ActionStatus, ActionType, AdapterType, ApprovalTier,
    DefensePlan, PlannedAction, PlanStatus, VerificationResult,
)
from planner import DefensePlanner
from verification import VerificationEngine
from adapters.base import BaseAdapter, AdapterResult
from adapters.wazuh import WazuhAdapter
from adapters.firewall import FirewallAdapter
from adapters.edr import EDRAdapter
from adapters.identity import IdentityAdapter
from config import Settings
from database import (
    db_session,
    DefensePlanModel,
    PlannedActionModel,
    VerificationResultModel,
)


logger = logging.getLogger(__name__)


class ResponseOrchestrator:
    """
    Drives the full autonomous defense loop.

    Manages active defense plans, coordinates simulation → planning →
    execution → verification, and handles approval workflows.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

        # Active plans (in-memory cache, backed by PostgreSQL)
        self._plans: Dict[str, DefensePlan] = {}

        # Components
        self.planner = DefensePlanner(
            ollama_host=settings.ollama_host,
            ollama_model=settings.ollama_model,
            auto_execute_min=settings.auto_execute_confidence_min,
            auto_veto_min=settings.auto_execute_with_veto_confidence_min,
        )
        self.verifier = VerificationEngine(
            simulation_url=settings.simulation_url,
            correlation_url=settings.correlation_engine_url,
            wazuh_api_url=settings.wazuh_api_url,
            wazuh_username=settings.wazuh_api_username,
            wazuh_password=settings.wazuh_api_password,
            wazuh_verify_ssl=settings.wazuh_api_verify_ssl,
            risk_reduction_threshold=settings.verification_risk_reduction_threshold,
            monitoring_duration_seconds=settings.verification_monitoring_duration_seconds,
        )

        # Adapters
        self._adapters: Dict[str, BaseAdapter] = {
            "wazuh": WazuhAdapter(
                api_url=settings.wazuh_api_url,
                username=settings.wazuh_api_username,
                password=settings.wazuh_api_password,
                verify_ssl=settings.wazuh_api_verify_ssl,
            ),
            "firewall": FirewallAdapter(),
            "edr": EDRAdapter(),
            "identity": IdentityAdapter(),
        }

        # ----- Database Persistence -----

    @staticmethod
    def _plan_from_rows(
        db_plan: DefensePlanModel,
        db_actions: List[PlannedActionModel],
        db_verification: Optional[VerificationResultModel] = None,
    ) -> DefensePlan:
        """Rehydrate a DefensePlan from PostgreSQL rows."""
        actions = [
            PlannedAction(
                action_id=row.action_id,
                action_type=ActionType(row.action_type),
                target=row.target,
                target_hostname=row.target_hostname,
                adapter=AdapterType(row.adapter),
                confidence=row.confidence,
                impact_score=row.impact_score,
                safety_score=row.safety_score,
                composite_score=row.composite_score,
                blast_radius=row.blast_radius,
                approval_tier=ApprovalTier(row.approval_tier),
                requires_approval=row.requires_approval,
                d3fend_technique=row.d3fend_technique or "",
                d3fend_label=row.d3fend_label or "",
                counters_techniques=row.counters_techniques or [],
                status=ActionStatus(row.status),
                rationale=row.rationale or "",
                executed_at=row.executed_at,
                completed_at=row.completed_at,
                rolled_back_at=row.rolled_back_at,
                adapter_response=row.adapter_response,
                error_message=row.error_message,
                approved_by=row.approved_by,
                approval_notes=row.approval_notes,
            )
            for row in db_actions
        ]

        verification = None
        if db_verification is not None:
            verification = VerificationResult(
                plan_id=db_verification.plan_id,
                verified_at=db_verification.verified_at,
                pre_attack_success_rate=db_verification.pre_attack_success_rate,
                post_attack_success_rate=db_verification.post_attack_success_rate,
                risk_reduction_pct=db_verification.risk_reduction_pct,
                re_simulation_id=db_verification.re_simulation_id,
                continued_indicators=db_verification.continued_indicators,
                monitoring_duration_seconds=db_verification.monitoring_duration_seconds,
                new_alerts_during_monitoring=db_verification.new_alerts_during_monitoring,
                verification_passed=db_verification.verification_passed,
                verdict_reason=db_verification.verdict_reason or "",
            )

        return DefensePlan(
            plan_id=db_plan.plan_id,
            incident_id=db_plan.incident_id,
            simulation_id=db_plan.simulation_id,
            status=PlanStatus(db_plan.status),
            created_at=db_plan.created_at,
            updated_at=db_plan.updated_at,
            completed_at=db_plan.completed_at,
            incident_summary=db_plan.incident_summary or "",
            detected_techniques=db_plan.detected_techniques or [],
            kill_chain_stage=db_plan.kill_chain_stage or "",
            source_ips=db_plan.source_ips or [],
            dest_ips=db_plan.dest_ips or [],
            pre_defense_risk=db_plan.pre_defense_risk,
            post_defense_risk=db_plan.post_defense_risk,
            simulation_summary=db_plan.simulation_summary,
            actions=actions,
            rationale=db_plan.rationale or "",
            verification=verification,
            total_actions=db_plan.total_actions,
            auto_executed_count=db_plan.auto_executed_count,
            human_approved_count=db_plan.human_approved_count,
            dry_run=db_plan.dry_run,
        )

    async def _load_plan_from_db(self, plan_id: str) -> Optional[DefensePlan]:
        """Load one plan and its actions from PostgreSQL into the local cache."""
        try:
            async with db_session() as session:
                result = await session.execute(
                    select(DefensePlanModel).where(
                        DefensePlanModel.plan_id == plan_id
                    )
                )
                db_plan = result.scalar_one_or_none()
                if db_plan is None:
                    return None

                actions_result = await session.execute(
                    select(PlannedActionModel)
                    .where(PlannedActionModel.plan_id == plan_id)
                    .order_by(PlannedActionModel.action_id)
                )
                db_actions = actions_result.scalars().all()

                verification_result = await session.execute(
                    select(VerificationResultModel)
                    .where(VerificationResultModel.plan_id == plan_id)
                    .order_by(desc(VerificationResultModel.verified_at))
                )
                db_verification = verification_result.scalars().first()

                plan = self._plan_from_rows(
                    db_plan, db_actions, db_verification
                )
                self._plans[plan_id] = plan
                return plan
        except Exception as e:
            logger.error(f"Failed to load plan {plan_id} from DB: {e}")
            return self._plans.get(plan_id)

    async def _load_plans_from_db(
        self,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[DefensePlan]:
        """Load plans from PostgreSQL so API reads are worker-independent."""
        try:
            async with db_session() as session:
                stmt = select(DefensePlanModel).order_by(
                    desc(DefensePlanModel.created_at)
                ).limit(limit)
                if status:
                    stmt = stmt.where(DefensePlanModel.status == status)

                result = await session.execute(stmt)
                db_plans = result.scalars().all()
                if not db_plans:
                    return []

                plan_ids = [p.plan_id for p in db_plans]
                actions_result = await session.execute(
                    select(PlannedActionModel)
                    .where(PlannedActionModel.plan_id.in_(plan_ids))
                    .order_by(PlannedActionModel.action_id)
                )
                action_map: Dict[str, List[PlannedActionModel]] = {
                    pid: [] for pid in plan_ids
                }
                for row in actions_result.scalars().all():
                    action_map[row.plan_id].append(row)

                verification_result = await session.execute(
                    select(VerificationResultModel)
                    .where(VerificationResultModel.plan_id.in_(plan_ids))
                    .order_by(desc(VerificationResultModel.verified_at))
                )
                verification_map: Dict[str, VerificationResultModel] = {}
                for row in verification_result.scalars().all():
                    verification_map.setdefault(row.plan_id, row)

                plans = [
                    self._plan_from_rows(
                        row,
                        action_map.get(row.plan_id, []),
                        verification_map.get(row.plan_id),
                    )
                    for row in db_plans
                ]
                self._plans.update({p.plan_id: p for p in plans})
                return plans
        except Exception as e:
            logger.error(f"Failed to load plans from DB: {e}")
            plans = list(self._plans.values())
            if status:
                plans = [p for p in plans if p.status.value == status]
            plans.sort(key=lambda p: p.created_at, reverse=True)
            return plans[:limit]

    async def _count_active_plans(self) -> int:
        """Count active plans from PostgreSQL, independent of worker-local cache."""
        terminal = (
            PlanStatus.COMPLETED.value,
            PlanStatus.FAILED.value,
            PlanStatus.ROLLED_BACK.value,
        )
        try:
            async with db_session() as session:
                result = await session.execute(
                    select(DefensePlanModel.plan_id).where(
                        ~DefensePlanModel.status.in_(terminal)
                    )
                )
                return len(result.scalars().all())
        except Exception as e:
            logger.warning(f"Active-plan DB count failed: {e}")
            return sum(
                1
                for p in self._plans.values()
                if p.status not in (
                    PlanStatus.COMPLETED,
                    PlanStatus.FAILED,
                    PlanStatus.ROLLED_BACK,
                )
            )

    async def _persist_plan(self, plan: DefensePlan) -> None:
        """Persist a defense plan and its actions to PostgreSQL."""
        try:
            async with db_session() as session:
                # Upsert defense plan
                result = await session.execute(
                    select(DefensePlanModel).where(
                        DefensePlanModel.plan_id == plan.plan_id
                    )
                )
                db_plan = result.scalar_one_or_none()

                if db_plan is None:
                    db_plan = DefensePlanModel(
                        plan_id=plan.plan_id,
                        incident_id=plan.incident_id,
                        simulation_id=plan.simulation_id,
                        status=plan.status.value,
                        incident_summary=plan.incident_summary,
                        detected_techniques=plan.detected_techniques,
                        kill_chain_stage=plan.kill_chain_stage,
                        source_ips=plan.source_ips,
                        dest_ips=plan.dest_ips,
                        pre_defense_risk=plan.pre_defense_risk,
                        post_defense_risk=plan.post_defense_risk,
                        simulation_summary=plan.simulation_summary,
                        rationale=plan.rationale,
                        total_actions=plan.total_actions,
                        auto_executed_count=plan.auto_executed_count,
                        human_approved_count=plan.human_approved_count,
                        dry_run=plan.dry_run,
                        completed_at=plan.completed_at,
                    )
                    session.add(db_plan)
                else:
                    db_plan.status = plan.status.value
                    db_plan.simulation_id = plan.simulation_id
                    db_plan.pre_defense_risk = plan.pre_defense_risk
                    db_plan.post_defense_risk = plan.post_defense_risk
                    db_plan.auto_executed_count = plan.auto_executed_count
                    db_plan.human_approved_count = plan.human_approved_count
                    db_plan.completed_at = plan.completed_at
                    db_plan.rationale = plan.rationale

                # Upsert planned actions
                for action in plan.actions:
                    result = await session.execute(
                        select(PlannedActionModel).where(
                            PlannedActionModel.action_id == action.action_id
                        )
                    )
                    db_action = result.scalar_one_or_none()

                    if db_action is None:
                        db_action = PlannedActionModel(
                            plan_id=plan.plan_id,
                            action_id=action.action_id,
                            action_type=action.action_type.value,
                            target=action.target,
                            target_hostname=action.target_hostname,
                            adapter=action.adapter.value,
                            confidence=action.confidence,
                            impact_score=action.impact_score,
                            safety_score=action.safety_score,
                            composite_score=action.composite_score,
                            blast_radius=action.blast_radius.value,
                            approval_tier=action.approval_tier.value,
                            requires_approval=action.requires_approval,
                            d3fend_technique=action.d3fend_technique,
                            d3fend_label=action.d3fend_label,
                            counters_techniques=action.counters_techniques,
                            status=action.status.value,
                            rationale=action.rationale,
                            executed_at=action.executed_at,
                            completed_at=action.completed_at,
                            rolled_back_at=action.rolled_back_at,
                            adapter_response=action.adapter_response,
                            error_message=action.error_message,
                            approved_by=action.approved_by,
                            approval_notes=action.approval_notes,
                        )
                        session.add(db_action)
                    else:
                        db_action.status = action.status.value
                        db_action.requires_approval = action.requires_approval
                        db_action.executed_at = action.executed_at
                        db_action.completed_at = action.completed_at
                        db_action.rolled_back_at = action.rolled_back_at
                        db_action.adapter_response = action.adapter_response
                        db_action.error_message = action.error_message
                        db_action.approved_by = action.approved_by
                        db_action.approval_notes = action.approval_notes

                if plan.verification is not None:
                    verification = plan.verification
                    result = await session.execute(
                        select(VerificationResultModel)
                        .where(VerificationResultModel.plan_id == plan.plan_id)
                        .order_by(desc(VerificationResultModel.verified_at))
                    )
                    db_verification = result.scalars().first()

                    if db_verification is None:
                        session.add(
                            VerificationResultModel(
                                plan_id=verification.plan_id,
                                verified_at=verification.verified_at,
                                pre_attack_success_rate=verification.pre_attack_success_rate,
                                post_attack_success_rate=verification.post_attack_success_rate,
                                risk_reduction_pct=verification.risk_reduction_pct,
                                re_simulation_id=verification.re_simulation_id,
                                continued_indicators=verification.continued_indicators,
                                monitoring_duration_seconds=verification.monitoring_duration_seconds,
                                new_alerts_during_monitoring=verification.new_alerts_during_monitoring,
                                verification_passed=verification.verification_passed,
                                verdict_reason=verification.verdict_reason,
                            )
                        )
                    else:
                        db_verification.verified_at = verification.verified_at
                        db_verification.pre_attack_success_rate = verification.pre_attack_success_rate
                        db_verification.post_attack_success_rate = verification.post_attack_success_rate
                        db_verification.risk_reduction_pct = verification.risk_reduction_pct
                        db_verification.re_simulation_id = verification.re_simulation_id
                        db_verification.continued_indicators = verification.continued_indicators
                        db_verification.monitoring_duration_seconds = verification.monitoring_duration_seconds
                        db_verification.new_alerts_during_monitoring = verification.new_alerts_during_monitoring
                        db_verification.verification_passed = verification.verification_passed
                        db_verification.verdict_reason = verification.verdict_reason


        except Exception as e:
            logger.error(
                f"Failed to persist defense plan {plan.plan_id}: {e}"
            )

    # ----- Main Loop -----

    async def trigger_defense(
        self,
        incident_id: str,
        environment_json: Optional[Dict] = None,
        auto_execute: bool = True,
        dry_run: bool = False,
        skip_simulation: bool = False,
    ) -> DefensePlan:
        """
        Entry point: trigger the full defense loop for an incident.

        1. Fetch incident context from correlation engine
        2. Run simulation (unless skipped)
        3. Generate defense plan
        4. Execute auto-approved actions
        5. Queue remaining actions for human approval
        6. Start verification (async)
        """
        logger.info(f"Defense triggered for incident {incident_id}")

        # Check concurrent plan limit
        active_count = await self._count_active_plans()
        if active_count >= self.settings.max_concurrent_plans:
            raise RuntimeError(
                f"Max concurrent plans ({self.settings.max_concurrent_plans}) reached. "
                f"Complete or cancel existing plans first."
            )

        # Step 1: Fetch incident context
        incident = await self._fetch_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        # Step 2: Run simulation
        simulation_results = None
        if not skip_simulation:
            simulation_results = await self._run_simulation(
                incident, environment_json
            )

        # Step 3: Generate plan
        plan = await self.planner.generate_plan(
            incident_id=incident_id,
            detected_techniques=incident.get("mitre_techniques", []),
            kill_chain_stage=incident.get("kill_chain_stage", ""),
            source_ips=incident.get("source_ips", []),
            dest_ips=incident.get("dest_ips", []),
            incident_summary=incident.get("summary", ""),
            simulation_results=simulation_results,
            environment=environment_json,
            dry_run=dry_run or self.settings.dry_run_mode,
        )
        
        await self._persist_plan(plan)
        self._plans[plan.plan_id] = plan

        # Step 4: Execute auto-approved actions
        if auto_execute and not plan.dry_run:
            await self._execute_auto_actions(plan)
        await self._persist_plan(plan)

        # Update status based on remaining actions
        pending_approval = [
            a for a in plan.actions
            if a.requires_approval and a.status == ActionStatus.PENDING
        ]
        if pending_approval:
            plan.status = PlanStatus.AWAITING_APPROVAL
        elif all(a.status in (ActionStatus.COMPLETED, ActionStatus.SKIPPED) for a in plan.actions):
            plan.status = PlanStatus.VERIFYING
            # Start async verification
            asyncio.create_task(self._verify_and_complete(plan))
        else:
            plan.status = PlanStatus.EXECUTING

        plan.updated_at = datetime.utcnow()
        await self._persist_plan(plan)
        return plan

    # ----- Incident Fetch -----

    async def _fetch_incident(self, incident_id: str) -> Optional[Dict]:
        """Fetch incident details from the correlation engine."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.settings.correlation_engine_url}/incidents/{incident_id}",
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    logger.warning(f"Incident {incident_id} not found")
                    return None
                else:
                    logger.error(f"Fetch incident failed: {resp.status_code}")
                    return None
        except Exception as e:
            logger.error(f"Failed to fetch incident {incident_id}: {e}")
            return None

    # ----- Simulation -----

    async def _run_simulation(
        self,
        incident: Dict,
        environment_json: Optional[Dict],
    ) -> Optional[Dict]:
        """Run a simulation against the environment."""
        try:
            async with httpx.AsyncClient() as client:
                params = {
                    "timesteps": self.settings.simulation_timesteps,
                }
                resp = await client.post(
                    f"{self.settings.simulation_url}/simulate",
                    params=params,
                    json=environment_json,
                    timeout=self.settings.simulation_timeout_seconds,
                )
                if resp.status_code == 200:
                    result = resp.json()
                    logger.info(
                        f"Simulation complete: {result.get('simulation_id', 'unknown')}"
                    )
                    return result
                else:
                    logger.error(f"Simulation failed: {resp.status_code}")
        except Exception as e:
            logger.error(f"Simulation request failed: {e}")

        return None

    # ----- Action Execution -----

    async def _execute_auto_actions(self, plan: DefensePlan) -> None:
        """Execute all actions that don't require human approval."""
        auto_count = 0
        for action in plan.actions:
            if action.requires_approval:
                continue
            if action.status != ActionStatus.PENDING:
                continue

            # Enforce rate limit
            if auto_count >= self.settings.max_auto_actions_per_incident:
                logger.warning(
                    f"Max auto-actions ({self.settings.max_auto_actions_per_incident}) "
                    f"reached for plan {plan.plan_id}. Remaining actions need approval."
                )
                action.requires_approval = True
                continue

            await self._execute_action(plan, action)
            auto_count += 1

            # Cooldown between actions
            if self.settings.cooldown_between_actions_seconds > 0:
                await asyncio.sleep(self.settings.cooldown_between_actions_seconds)

        plan.auto_executed_count = auto_count

    async def _execute_action(
        self, plan: DefensePlan, action: PlannedAction
    ) -> AdapterResult:
        """Execute a single defense action via its adapter."""
        adapter = self._adapters.get(action.adapter.value)
        if not adapter:
            action.status = ActionStatus.FAILED
            action.error_message = f"No adapter found for {action.adapter.value}"
            return AdapterResult(
                success=False,
                action_type=action.action_type.value,
                target=action.target,
                adapter=action.adapter.value,
                detail=action.error_message,
                error=action.error_message,
            )

        action.status = ActionStatus.EXECUTING
        action.executed_at = datetime.utcnow()

        logger.info(
            f"Executing: {action.action_type.value} on {action.target} "
            f"via {action.adapter.value} (plan {plan.plan_id})"
        )

        if plan.dry_run:
            result = await adapter.dry_run(action.action_type.value, action.target)
        else:
            result = await adapter.execute(action.action_type.value, action.target)

        if result.success:
            action.status = ActionStatus.COMPLETED
            action.completed_at = datetime.utcnow()
            action.adapter_response = result.to_dict()
        else:
            action.status = ActionStatus.FAILED
            action.error_message = result.error or result.detail
            action.adapter_response = result.to_dict()

        plan.updated_at = datetime.utcnow()
        return result

    # ----- Approval Handling -----

    async def approve_action(
        self,
        plan_id: str,
        action_id: str,
        approved: bool,
        analyst_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> PlannedAction:
        """Approve or reject a pending action."""
        plan = await self._load_plan_from_db(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")

        action = next(
            (a for a in plan.actions if a.action_id == action_id), None
        )
        if not action:
            raise ValueError(f"Action {action_id} not found in plan {plan_id}")

        if action.status != ActionStatus.PENDING:
            raise ValueError(
                f"Action {action_id} is {action.status.value}, not pending"
            )

        action.approved_by = analyst_id
        action.approval_notes = notes

        if approved:
            plan.human_approved_count += 1
            result = await self._execute_action(plan, action)
            if not result.success:
                logger.error(
                    f"Approved action {action_id} failed: {result.error}"
                )
        else:
            action.status = ActionStatus.VETOED
            logger.info(f"Action {action_id} vetoed by {analyst_id}")

        # Check if all actions are now resolved
        all_resolved = all(
            a.status in (
                ActionStatus.COMPLETED, ActionStatus.FAILED,
                ActionStatus.SKIPPED, ActionStatus.VETOED,
            )
            for a in plan.actions
        )

        if all_resolved:
            plan.status = PlanStatus.VERIFYING
            asyncio.create_task(self._verify_and_complete(plan))

        plan.updated_at = datetime.utcnow()
        await self._persist_plan(plan)
        return action

    # ----- Verification & Completion -----

    async def _verify_and_complete(self, plan: DefensePlan) -> None:
        """Run verification and finalize the plan."""
        try:
            verification = await self.verifier.verify_plan(plan)
            plan.verification = verification
            plan.post_defense_risk = verification.post_attack_success_rate

            if verification.verification_passed:
                plan.status = PlanStatus.COMPLETED
                plan.completed_at = datetime.utcnow()
                logger.info(
                    f"Plan {plan.plan_id} COMPLETED — "
                    f"risk reduced by {verification.risk_reduction_pct*100:.1f}%"
                )
            else:
                # Check if auto-rollback is enabled
                if self.settings.auto_rollback_on_verification_failure:
                    rollback_ok = await self._rollback_plan(plan)
                    if rollback_ok:
                        plan.status = PlanStatus.ROLLED_BACK
                        logger.warning(
                            f"Plan {plan.plan_id} ROLLED BACK — "
                            f"verification failed: {verification.verdict_reason[:100]}"
                        )
                    else:
                        plan.status = PlanStatus.FAILED
                        logger.error(
                            f"Plan {plan.plan_id} rollback incomplete — "
                            f"verification failed: {verification.verdict_reason[:100]}"
                        )
                else:
                    plan.status = PlanStatus.COMPLETED
                    plan.completed_at = datetime.utcnow()
                    logger.warning(
                        f"Plan {plan.plan_id} completed with verification failure: "
                        f"{verification.verdict_reason[:100]}"
                    )

            # Record outcome in feedback service
            await self._record_outcome(plan)

        except Exception as e:
            logger.error(f"Verification failed for plan {plan.plan_id}: {e}")
            plan.status = PlanStatus.FAILED
            plan.completed_at = datetime.utcnow()

        plan.updated_at = datetime.utcnow()
        await self._persist_plan(plan)

    async def _rollback_plan(self, plan: DefensePlan) -> bool:
        """Rollback all completed actions in reverse order."""
        reversed_actions = [
            a for a in reversed(plan.actions)
            if a.status == ActionStatus.COMPLETED
        ]

        if not reversed_actions:
            return True

        rollback_ok = True

        for action in reversed_actions:
            if plan.dry_run:
                action.status = ActionStatus.ROLLED_BACK
                action.rolled_back_at = datetime.utcnow()
                logger.info(
                    f"[DRY RUN] Rolled back: {action.action_type.value} on {action.target}"
                )
                continue

            adapter = self._adapters.get(action.adapter.value)
            if not adapter:
                rollback_ok = False
                logger.error(
                    f"Rollback failed for {action.action_id}: no adapter for {action.adapter.value}"
                )
                continue

            try:
                result = await adapter.rollback(
                    action.action_type.value, action.target
                )
                if result.success:
                    action.status = ActionStatus.ROLLED_BACK
                    action.rolled_back_at = datetime.utcnow()
                    logger.info(
                        f"Rolled back: {action.action_type.value} on {action.target}"
                    )
                else:
                    rollback_ok = False
                    logger.error(
                        f"Rollback failed for {action.action_id}: {result.error}"
                    )
            except Exception as e:
                rollback_ok = False
                logger.error(f"Rollback error for {action.action_id}: {e}")

        return rollback_ok

    # ----- Feedback Recording -----

    async def _record_outcome(self, plan: DefensePlan) -> None:
        """Record defense outcome in the feedback service for learning."""
        if not plan.verification:
            return

        try:
            async with httpx.AsyncClient() as client:
                outcome = {
                    "plan_id": plan.plan_id,
                    "incident_id": plan.incident_id,
                    "total_actions": plan.total_actions,
                    "auto_executed": plan.auto_executed_count,
                    "human_approved": plan.human_approved_count,
                    "pre_risk": plan.pre_defense_risk,
                    "post_risk": plan.post_defense_risk,
                    "verification_passed": plan.verification.verification_passed,
                    "risk_reduction_pct": plan.verification.risk_reduction_pct,
                    "actions": [
                        {
                            "action_type": a.action_type.value,
                            "target": a.target,
                            "status": a.status.value,
                            "d3fend_technique": a.d3fend_technique,
                            "counters_techniques": a.counters_techniques,
                            "impact_score": a.impact_score,
                        }
                        for a in plan.actions
                    ],
                }

                await client.post(
                    f"{self.settings.feedback_service_url}/alerts",
                    json={
                        "alert_id": f"defense-{plan.plan_id}",
                        "source": "response-orchestrator",
                        "data": outcome,
                    },
                    timeout=10.0,
                )
        except Exception as e:
            logger.warning(f"Failed to record defense outcome: {e}")

    # ----- Plan Management -----

    async def get_plan(self, plan_id: str) -> Optional[DefensePlan]:
        """Get a plan from PostgreSQL so reads survive restarts and workers."""
        return await self._load_plan_from_db(plan_id)

    async def get_all_plans(
        self,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[DefensePlan]:
        """Get plans from PostgreSQL, optionally filtered by status."""
        return await self._load_plans_from_db(status=status, limit=limit)

    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approvals from PostgreSQL."""
        plans = await self._load_plans_from_db(
            status=PlanStatus.AWAITING_APPROVAL.value,
            limit=200,
        )
        pending = []
        for plan in plans:
            for action in plan.actions:
                if action.requires_approval and action.status == ActionStatus.PENDING:
                    pending.append({
                        "plan_id": plan.plan_id,
                        "incident_id": plan.incident_id,
                        "action_id": action.action_id,
                        "action_type": action.action_type.value,
                        "target": action.target,
                        "target_hostname": action.target_hostname,
                        "d3fend_label": action.d3fend_label,
                        "impact_score": action.impact_score,
                        "safety_score": action.safety_score,
                        "blast_radius": action.blast_radius.value,
                        "rationale": action.rationale,
                        "counters_techniques": action.counters_techniques,
                        "approved_by": action.approved_by,
                        "approval_notes": action.approval_notes,
                    })
        return pending
