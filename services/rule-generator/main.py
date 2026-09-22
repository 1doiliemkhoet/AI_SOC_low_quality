"""
LLM Rule Generator - FastAPI Application
AI-Augmented SOC

Phase 8: The system writes its own detection rules.

Analyzes uncategorized or novel attacks, uses the LLM to generate
Sigma detection rules, back-tests against historical alert data,
calculates false positive rates, and queues rules for analyst approval.
"""

import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from prometheus_client import Counter, generate_latest
from sigma.rule import SigmaRule
from starlette.responses import Response

logging.basicConfig(
    level="INFO",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Config
OLLAMA_HOST = "http://ollama:11434"
OLLAMA_MODEL = "llama3.2:3b"
FEEDBACK_SERVICE_URL = "http://feedback-service:8000"

# In-memory rule store (would be PostgreSQL in production)
rules_store: Dict[str, Dict[str, Any]] = {}

RULES_GENERATED = Counter("rules_generated_total", "Total rules generated")


# --- Models ---

class RuleGenerationRequest(BaseModel):
    alert_id: str = Field(..., description="Alert that triggered rule generation")
    alert_description: str = Field(..., description="Description of the attack pattern")
    raw_log: Optional[str] = Field(None, description="Raw log sample")
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    severity: str = "high"


class GeneratedRule(BaseModel):
    rule_id: str
    title: str
    rule_text: str
    rule_format: str = "sigma"
    source_alert_id: str
    mitre_techniques: List[str] = []
    severity: str = "high"
    false_positive_rate: Optional[float] = None
    tested_against: int = 0
    status: str = "pending"  # pending, approved, rejected, testing
    created_at: str
    analyst_notes: Optional[str] = None


# --- Lifespan ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Rule Generator Service")
    yield
    logger.info("Shutting down Rule Generator Service")


app = FastAPI(
    title="LLM Rule Generator",
    description="AI-generated Sigma detection rules from novel attack patterns",
    version="1.0.0",
    lifespan=lifespan,
)


# --- LLM Rule Generation ---

SIGMA_PROMPT = """You are a detection engineering expert. Generate a Sigma detection rule for the following attack pattern.

The rule must be in valid Sigma YAML format. Include:
- title: A descriptive title
- status: experimental
- description: What the rule detects
- logsource: category, product, service
- detection: one or more named selections; each selection MUST be a YAML mapping of log field names to values (for example 'selection: {{user: kali, event_type: login}}'). Put fields that must ALL match into the same mapping (AND semantics). Do NOT use a list of mappings for a single selection unless you intentionally need OR semantics. Do NOT use expressions such as 'field == value' and do NOT make selection a list of strings.
- evidence: Use only log fields and values explicitly present in the supplied raw log or network context. Do not invent fields, field values, time ranges, usernames, ports, or other facts that are not present. If the alert description mentions a concept such as non-business hours but the raw evidence does not contain a time field/value, do not fabricate one.
- condition: MUST reference only named detection selections that actually exist. Prefer the simple form 'condition: selection'. Use 'selection and filter' only when a separate filter selection is actually defined; never use values such as 'any' by themselves.
- falsepositives: Known false positive scenarios
- level: {severity}
- tags: Include ONLY the MITRE ATT&CK techniques supplied in the 'MITRE Techniques' input, converted to lowercase 'attack.<technique_id>' tags. Do not add other ATT&CK techniques.

Attack Pattern:
{description}

{raw_log_section}

{network_section}

MITRE Techniques: {mitre}

Generate ONLY the Sigma YAML rule. No explanation, no markdown fencing. Just the raw YAML."""


def _clean_rule_text(rule_text: str) -> str:
    """Remove optional Markdown code fences around an LLM-generated rule."""
    rule_text = (rule_text or "").strip()
    # Models may wrap YAML in Markdown fences, sometimes with leading text.
    fenced = re.search(r"```(?:ya?ml)?\s*\n?(.*?)```", rule_text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        return fenced.group(1).strip()
    return rule_text


def _ensure_sigma_condition(rule_text: str) -> str:
    """Add an unambiguous condition when a rule has exactly one selection."""
    try:
        raw_evidence = (request.raw_log or "").lower()
        rule_text = _strip_unsupported_temporal_lines(rule_text, raw_evidence)
        document = yaml.safe_load(rule_text)
        if not isinstance(document, dict):
            return rule_text

        detection = document.get("detection")
        if not isinstance(detection, dict):
            return rule_text

        selection_names = [name for name in detection if name != "condition"]
        if len(selection_names) == 1 and "condition" not in detection:
            detection["condition"] = selection_names[0]
            return yaml.safe_dump(document, sort_keys=False)
    except Exception:
        pass

    return rule_text


def _strip_unsupported_temporal_lines(rule_text: str, raw_evidence: str) -> str:
    """Remove invented temporal fields before YAML parsing when evidence lacks them."""
    temporal_fields = {
        "hour", "hours", "day", "days", "weekday", "timestamp",
        "time", "event_time",
    }
    lines = []
    for line in rule_text.splitlines():
        match = re.match(r"^(?P<indent>\\s*)(?:-\\s*)?(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\\s*:", line)
        if match and match.group("field").lower() in temporal_fields:
            field = match.group("field")
            field_pattern = rf'(?i)(?:"{re.escape(field)}"\\s*[:=]|\\b{re.escape(field)}\\b\\s*[:=])'
            if re.search(field_pattern, raw_evidence) is None:
                continue
        lines.append(line)
    return "\n".join(lines)


def _normalize_generated_sigma(rule_text: str, request: RuleGenerationRequest) -> str:
    """Normalize model output so stored Sigma stays aligned with supplied evidence."""
    try:
        document = yaml.safe_load(rule_text)
        if not isinstance(document, dict):
            return rule_text

        # The model may invent extra top-level metadata. Keep the generated
        # rule focused on standard Sigma fields.
        document.pop("evidence", None)
        document.pop("condition", None)

        falsepositives = document.get("falsepositives")
        if isinstance(falsepositives, str):
            document["falsepositives"] = [falsepositives]
        elif falsepositives is None:
            document["falsepositives"] = []

        # MITRE tags must come only from the request, using canonical lowercase
        # ATT&CK tag names.
        requested_tags = [
            f"attack.{technique.lower()}"
            for technique in request.mitre_techniques
            if technique
        ]
        if requested_tags:
            document["tags"] = requested_tags

        detection = document.get("detection")
        if not isinstance(detection, dict):
            return yaml.safe_dump(document, sort_keys=False)

        # If temporal fields are not present in the supplied raw log, remove
        # hallucinated hour/day/time predicates rather than storing a rule
        # that claims evidence we do not have.
        unsupported_temporal_fields = {
            "hour", "hours", "day", "days", "weekday", "timestamp",
            "time", "event_time",
        }
        for name, selection in detection.items():
            if name == "condition":
                continue
            if isinstance(selection, dict):
                for field in list(selection):
                    if field.lower() in unsupported_temporal_fields:
                        # Treat a temporal field as supported only when the raw
                        # evidence contains it as a structured field, not merely
                        # as prose such as "non-business hours".
                        field_pattern = rf'(?i)(?:"{re.escape(field)}"\\s*[:=]|\\b{re.escape(field)}\\b\\s*[:=])'
                        field_present = re.search(field_pattern, raw_evidence) is not None
                        if not field_present:
                            selection.pop(field)

        selection_names = [name for name in detection if name != "condition"]
        if len(selection_names) == 1:
            detection["condition"] = selection_names[0]

        return yaml.safe_dump(document, sort_keys=False)
    except Exception:
        return rule_text


def _validate_sigma_rule(rule_text: str) -> tuple[bool, str]:
    """Validate YAML and Sigma detection semantics before storing a rule."""
    try:
        document = yaml.safe_load(rule_text)
        if not isinstance(document, dict):
            return False, "Sigma rule must be a YAML mapping"

        detection = document.get("detection")
        if not isinstance(detection, dict):
            return False, "Sigma rule must contain a detection mapping"

        selections = {name: value for name, value in detection.items() if name != "condition"}
        if not selections:
            return False, "Sigma detection must contain at least one named selection"

        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            return False, "Sigma detection must contain a condition"

        # Every non-operator identifier in the condition must resolve to a
        # detection selection. Support Sigma patterns such as "selection_*",
        # "1 of selection_*", and "all of them".
        condition_tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_-]*\\*?", condition)
        operators = {"and", "or", "not", "all", "any", "of", "them"}
        references = [token for token in condition_tokens if token.lower() not in operators]

        if not references:
            return False, "Sigma condition must reference a named detection selection"

        for reference in references:
            if reference.endswith("*"):
                prefix = reference[:-1]
                resolved = any(name.startswith(prefix) for name in selections)
            else:
                resolved = reference in selections
            if not resolved:
                return False, f"Sigma condition references undefined detection selection '{reference}'"

        for name, selection in selections.items():
            if isinstance(selection, list):
                if not selection or any(not isinstance(item, dict) for item in selection):
                    return False, f"Sigma selection '{name}' must contain field/value mappings, not expression strings"
            elif not isinstance(selection, dict):
                return False, f"Sigma selection '{name}' must be a field/value mapping"

        tags = document.get("tags", [])
        if not isinstance(tags, list):
            return False, "Sigma tags must be a list"
        for tag in tags:
            if not isinstance(tag, str) or "." not in tag:
                return False, f"Sigma tag '{tag}' must use a namespace such as attack.t1078"

        SigmaRule.from_yaml(rule_text)
        return True, ""
    except Exception as exc:
        return False, str(exc)


async def _ollama_generate(prompt: str) -> Optional[str]:
    """Generate one Sigma rule candidate through Ollama."""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 1024},
                },
            )
            if response.status_code != 200:
                logger.error(f"Ollama returned {response.status_code}")
                return None
            return _clean_rule_text(response.json().get("response", ""))
    except Exception as e:
        logger.error(f"LLM rule generation failed: {e}")
        return None


async def generate_sigma_rule(request: RuleGenerationRequest) -> Optional[str]:
    """Generate and validate a Sigma detection rule through the LLM."""
    raw_log_section = f"Raw Log Sample:\n{request.raw_log}" if request.raw_log else ""
    network_section = ""
    if request.source_ip or request.dest_ip:
        parts = []
        if request.source_ip:
            parts.append(f"Source IP: {request.source_ip}")
        if request.dest_ip:
            parts.append(f"Destination IP: {request.dest_ip}")
        if request.dest_port:
            parts.append(f"Destination Port: {request.dest_port}")
        network_section = "Network Context:\n" + "\n".join(parts)

    prompt = SIGMA_PROMPT.format(
        severity=request.severity,
        description=request.alert_description,
        raw_log_section=raw_log_section,
        network_section=network_section,
        mitre=", ".join(request.mitre_techniques) if request.mitre_techniques else "Unknown",
    )

    rule_text = await _ollama_generate(prompt)
    if rule_text:
        rule_text = _normalize_generated_sigma(rule_text, request)
        rule_text = _ensure_sigma_condition(rule_text)
        valid, error = _validate_sigma_rule(rule_text)
        if valid:
            return rule_text

        logger.warning(f"Generated Sigma rule failed validation: {error}")
        repair_prompt = "\n".join([
            "Repair the following invalid Sigma rule.",
            "",
            "Validation error:",
            error,
            "",
            "Requirements:",
            "- Return ONLY valid Sigma YAML.",
            "- Every detection selection MUST be a mapping of log field names to values.",
            "- The condition MUST reference a named selection such as selection.",
            "- Every tag MUST use a namespace such as attack.t1078.",
            "- Do not use field == value expressions.",
            "- Do not return Markdown fences.",
            "",
            "Invalid rule:",
            rule_text,
        ])
        repaired = await _ollama_generate(repair_prompt)
        if repaired:
            repaired = _normalize_generated_sigma(repaired, request)
            repaired = _ensure_sigma_condition(repaired)
            valid, error = _validate_sigma_rule(repaired)
            if valid:
                return repaired
            logger.error(f"Repaired Sigma rule failed validation: {error}")

    return None


async def backtest_rule(rule_text: str) -> Dict[str, Any]:
    """
    Back-test a generated rule against historical alert data.
    Queries the feedback service for recent alerts and checks if the rule
    would have matched.
    """
    matches = 0
    false_positives = 0
    total_tested = 0

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{FEEDBACK_SERVICE_URL}/alerts",
                params={"limit": 100},
            )
            if response.status_code == 200:
                data = response.json()
                alerts = data.get("alerts", [])
                total_tested = len(alerts)

                # Simple keyword matching against rule detection fields
                # In production, this would parse the Sigma rule and match fields
                for alert in alerts:
                    desc = (alert.get("rule_description") or "").lower()
                    rule_lower = rule_text.lower()

                    # Check if rule keywords appear in alert
                    if any(
                        keyword in desc
                        for keyword in _extract_rule_keywords(rule_lower)
                    ):
                        matches += 1
                        # If the alert was marked as false positive, count it
                        if alert.get("feedback_count", 0) > 0:
                            false_positives += 1

    except Exception as e:
        logger.warning(f"Backtest failed: {e}")

    fp_rate = false_positives / matches if matches > 0 else 0.0

    return {
        "total_tested": total_tested,
        "matches": matches,
        "false_positives": false_positives,
        "false_positive_rate": round(fp_rate, 4),
    }


def _extract_rule_keywords(rule_text: str) -> List[str]:
    """Extract detection keywords from a Sigma rule for basic matching."""
    keywords = []
    in_detection = False
    for line in rule_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("detection:"):
            in_detection = True
            continue
        if in_detection:
            if stripped and not stripped.startswith("#"):
                # Extract values from key: value pairs
                if ":" in stripped:
                    value = stripped.split(":", 1)[1].strip().strip("'\"")
                    if value and len(value) > 3:
                        keywords.append(value.lower())
            if stripped and not stripped.startswith(" ") and not stripped.startswith("-"):
                if not stripped.startswith("selection") and not stripped.startswith("condition"):
                    in_detection = False
    return keywords[:10]  # Limit to 10 keywords


# --- Endpoints ---

@app.post("/generate")
async def generate_rule(request: RuleGenerationRequest):
    """
    Generate a Sigma detection rule from an attack pattern using the LLM.
    Back-tests against historical data and queues for analyst approval.
    """
    start = time.time()

    # Generate rule via LLM
    rule_text = await generate_sigma_rule(request)
    if not rule_text:
        raise HTTPException(status_code=503, detail="LLM rule generation failed")

    # Extract title from rule
    title = "Generated Detection Rule"
    for line in rule_text.split("\n"):
        if line.strip().startswith("title:"):
            title = line.split(":", 1)[1].strip()
            break

    # Back-test against historical alerts
    backtest = await backtest_rule(rule_text)

    # Store rule
    rule_id = f"RULE-{uuid.uuid4().hex[:8]}"
    rule = GeneratedRule(
        rule_id=rule_id,
        title=title,
        rule_text=rule_text,
        rule_format="sigma",
        source_alert_id=request.alert_id,
        mitre_techniques=request.mitre_techniques,
        severity=request.severity,
        false_positive_rate=backtest["false_positive_rate"],
        tested_against=backtest["total_tested"],
        status="pending",
        created_at=datetime.utcnow().isoformat(),
    )

    rules_store[rule_id] = rule.model_dump()
    RULES_GENERATED.inc()

    elapsed = int((time.time() - start) * 1000)
    logger.info(
        f"Generated rule {rule_id}: {title} "
        f"(FP rate={backtest['false_positive_rate']:.2%}, {elapsed}ms)"
    )

    return {
        "rule": rule.model_dump(),
        "backtest": backtest,
        "processing_time_ms": elapsed,
    }


@app.get("/rules")
async def list_rules(
    status: Optional[str] = Query(None, description="Filter by status"),
):
    """List all generated rules, optionally filtered by status."""
    rules = list(rules_store.values())
    if status:
        rules = [r for r in rules if r.get("status") == status]
    return {"total": len(rules), "rules": rules}


@app.get("/rules/pending")
async def pending_rules():
    """Get rules pending analyst approval."""
    pending = [r for r in rules_store.values() if r.get("status") == "pending"]
    return {"total": len(pending), "rules": pending}


@app.put("/rules/{rule_id}/approve")
async def approve_rule(rule_id: str, notes: Optional[str] = None):
    """Approve a generated rule for deployment."""
    if rule_id not in rules_store:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    rules_store[rule_id]["status"] = "approved"
    rules_store[rule_id]["analyst_notes"] = notes
    logger.info(f"Rule {rule_id} approved")
    return rules_store[rule_id]


@app.put("/rules/{rule_id}/reject")
async def reject_rule(rule_id: str, notes: Optional[str] = None):
    """Reject a generated rule."""
    if rule_id not in rules_store:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    rules_store[rule_id]["status"] = "rejected"
    rules_store[rule_id]["analyst_notes"] = notes
    logger.info(f"Rule {rule_id} rejected")
    return rules_store[rule_id]


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "rule-generator",
        "version": "1.0.0",
        "rules_count": len(rules_store),
        "pending_count": sum(1 for r in rules_store.values() if r.get("status") == "pending"),
    }


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type="text/plain; charset=utf-8")


@app.get("/")
async def root():
    return {
        "service": "rule-generator",
        "version": "1.0.0",
        "description": "AI-generated Sigma detection rules from novel attack patterns",
        "endpoints": {
            "generate": "POST /generate",
            "list_rules": "GET /rules",
            "pending": "GET /rules/pending",
            "approve": "PUT /rules/{rule_id}/approve",
            "reject": "PUT /rules/{rule_id}/reject",
            "health": "GET /health",
        },
    }
