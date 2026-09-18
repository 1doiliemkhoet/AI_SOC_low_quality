"""
Ollama LLM Client - Alert Triage Service
AI-Augmented SOC

Handles communication with Ollama API for security alert analysis.
Includes:
- Structured alert evidence extraction
- Multi-event aggregation
- Prompt engineering
- ML enrichment
- Context enrichment
- Structured JSON output parsing
- Model fallback logic
"""

import json
import logging
import re
from typing import Optional, Dict, Any

import httpx

from config import settings
from models import (
    SecurityAlert,
    TriageResponse,
    SeverityLevel,
    AlertCategory,
    IOC,
    TriageRecommendation,
)
from ml_client import (
    MLInferenceClient,
    MLPrediction,
    enrich_llm_prompt_with_ml,
)
from context_manager import ContextManager


logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# CATEGORY NORMALIZATION
# ---------------------------------------------------------

CATEGORY_ALIASES = {
    "exfiltration": "data_exfiltration",
    "data_theft": "data_exfiltration",

    "privilege_elevation": "privilege_escalation",
    "privesc": "privilege_escalation",

    "lateral": "lateral_movement",

    "c2": "command_and_control",
    "c&c": "command_and_control",

    "recon": "reconnaissance",
    "scanning": "reconnaissance",

    "intrusion": "intrusion_attempt",
    "attack": "intrusion_attempt",

    "policy": "policy_violation",
    "compliance": "policy_violation",
}


def normalize_category(category: str) -> str:
    """Normalize LLM category responses to valid AlertCategory values."""

    if not category:
        return "other"

    category = str(category).lower().strip()

    if category in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[category]

    valid_categories = [c.value for c in AlertCategory]

    if category in valid_categories:
        return category

    logger.warning(
        f"Unknown category '{category}', defaulting to 'other'"
    )

    return "other"


# ---------------------------------------------------------
# OLLAMA CLIENT
# ---------------------------------------------------------

class OllamaClient:
    """
    Client for interacting with Ollama LLM API.

    Workflow:
        SecurityAlert
            ↓
        Evidence extraction
            ↓
        Multi-event aggregation
            ↓
        Context enrichment
            ↓
        ML enrichment
            ↓
        Ollama
            ↓
        JSON parsing
            ↓
        TriageResponse
    """

    def __init__(self):

        self.base_url = settings.ollama_host
        self.primary_model = settings.primary_model
        self.fallback_model = settings.fallback_model
        self.timeout = settings.llm_timeout

        # ML inference client
        self.ml_client = MLInferenceClient(
            ml_api_url=settings.ml_api_url,
            timeout=settings.ml_timeout,
            enabled=settings.ml_enabled,
        )

        # Context manager
        self.context_manager = ContextManager(
            feedback_service_url=settings.feedback_service_url,
            enabled=settings.context_enabled,
            timeout=settings.context_timeout,
            history_limit=settings.context_history_limit,
            environment_context=settings.environment_context,
        )

    # -----------------------------------------------------
    # HEALTH CHECK
    # -----------------------------------------------------

    async def check_health(self) -> bool:
        """
        Check if Ollama service is reachable.
        """

        try:

            async with httpx.AsyncClient(timeout=5.0) as client:

                response = await client.get(
                    f"{self.base_url}/api/tags"
                )

                return response.status_code == 200

        except Exception as e:

            logger.error(
                f"Ollama health check failed: {e}"
            )

            return False

    # -----------------------------------------------------
    # GENERIC NESTED VALUE WALKER
    # -----------------------------------------------------

    def _walk_values(
        self,
        value: Any,
        parent_key: str = "",
    ):
        """
        Recursively walk dictionaries/lists and return
        key/value pairs.

        This allows the extractor to find fields inside:

            full_log
              ├── data
              ├── agent
              ├── events[]
              │     ├── data
              │     └── message
              └── other nested objects
        """

        if isinstance(value, dict):

            for key, child in value.items():

                key_lower = str(key).lower()

                yield key_lower, child

                yield from self._walk_values(
                    child,
                    key_lower,
                )

        elif isinstance(value, list):

            for item in value:

                yield from self._walk_values(
                    item,
                    parent_key,
                )

    # -----------------------------------------------------
    # ADD UNIQUE VALUE
    # -----------------------------------------------------

    @staticmethod
    def _append_unique(
        target: list,
        value: Any,
    ):
        """Append a value only if it is non-empty and unique."""

        if value is None:
            return

        if isinstance(value, str):

            value = value.strip()

            if not value:
                return

        if value not in target:
            target.append(value)

    # -----------------------------------------------------
    # EXTRACT EVIDENCE
    # -----------------------------------------------------

    def _extract_evidence(
        self,
        alert: SecurityAlert,
    ) -> Dict[str, Any]:
        """
        Extract normalized evidence from SecurityAlert.

        IMPORTANT:
        The real structured event data may be stored inside
        alert.full_log rather than top-level SecurityAlert fields.

        This function therefore:
        - Uses top-level fields when present
        - Uses full_log as the main structured source
        - Walks nested dictionaries/lists
        - Aggregates multi-event data
        - Counts repeated authentication failures
        - Tracks source-IP frequency
        - Detects repeated event patterns
        """

        evidence: Dict[str, Any] = {
            "alert_id": alert.alert_id,
            "rule_description": alert.rule_description,
            "rule_level": alert.rule_level,
            "timestamp": str(alert.timestamp),

            "source_ip": alert.source_ip,
            "destination_ip": alert.dest_ip,

            "source_port": alert.source_port,
            "destination_port": alert.dest_port,

            "user": alert.user,
            "process": alert.process,
            "command": alert.command,
            "file_path": alert.file_path,

            "protocol": None,
            "action": None,
            "source_hostname": alert.source_hostname,

            "message": alert.raw_log,

            # Multi-event information
            "event_count": 1,
            "failed_authentication_count": 0,
            "source_ip_event_counts": {},
            "event_messages": [],
            "event_pattern": "NONE",
        }

        # -------------------------------------------------
        # TOP-LEVEL RAW LOG
        # -------------------------------------------------

        if alert.raw_log:
            self._append_unique(
                evidence["event_messages"],
                str(alert.raw_log),
            )

        # -------------------------------------------------
        # FULL STRUCTURED LOG
        # -------------------------------------------------

        full_log = alert.full_log

        if not isinstance(full_log, dict):
            full_log = {}

        # -------------------------------------------------
        # TOP-LEVEL EVENT COUNT
        # -------------------------------------------------

        explicit_event_count = full_log.get("event_count")

        if explicit_event_count is not None:

            try:
                evidence["event_count"] = int(
                    explicit_event_count
                )

            except (TypeError, ValueError):
                pass

        # -------------------------------------------------
        # EVENTS ARRAY
        # -------------------------------------------------

        events = full_log.get("events")

        if isinstance(events, list):

            evidence["event_count"] = len(events)

            for event in events:

                if not isinstance(event, dict):
                    continue

                # -----------------------------------------
                # EVENT DATA
                # -----------------------------------------

                event_data = event.get("data", {})

                if not isinstance(event_data, dict):
                    event_data = {}

                # -----------------------------------------
                # SOURCE IP
                # -----------------------------------------

                srcip = (
                    event_data.get("srcip")
                    or event_data.get("source_ip")
                    or event.get("srcip")
                    or event.get("source_ip")
                )

                if srcip:

                    srcip = str(srcip)

                    evidence["source_ip_event_counts"][
                        srcip
                    ] = (
                        evidence["source_ip_event_counts"].get(
                            srcip,
                            0,
                        )
                        + 1
                    )

                    if not evidence["source_ip"]:
                        evidence["source_ip"] = srcip

                # -----------------------------------------
                # SOURCE PORT
                # -----------------------------------------

                srcport = (
                    event_data.get("srcport")
                    or event_data.get("source_port")
                    or event.get("srcport")
                    or event.get("source_port")
                )

                if srcport and not evidence["source_port"]:

                    try:
                        evidence["source_port"] = int(srcport)

                    except (TypeError, ValueError):
                        evidence["source_port"] = srcport

                # -----------------------------------------
                # DESTINATION IP
                # -----------------------------------------

                dstip = (
                    event_data.get("dstip")
                    or event_data.get("destination_ip")
                    or event.get("dstip")
                    or event.get("destination_ip")
                )

                if dstip and not evidence["destination_ip"]:
                    evidence["destination_ip"] = str(dstip)

                # -----------------------------------------
                # DESTINATION PORT
                # -----------------------------------------

                dstport = (
                    event_data.get("dstport")
                    or event_data.get("destination_port")
                    or event.get("dstport")
                    or event.get("destination_port")
                )

                if dstport and not evidence["destination_port"]:

                    try:
                        evidence["destination_port"] = int(dstport)

                    except (TypeError, ValueError):
                        evidence["destination_port"] = dstport

                # -----------------------------------------
                # USER
                # -----------------------------------------

                event_user = (
                    event_data.get("srcuser")
                    or event_data.get("dstuser")
                    or event_data.get("user")
                    or event_data.get("username")
                    or event_data.get("account")
                    or event.get("user")
                    or event.get("username")
                )

                if event_user and not evidence["user"]:
                    evidence["user"] = str(event_user)

                # -----------------------------------------
                # PROTOCOL
                # -----------------------------------------

                protocol = (
                    event_data.get("protocol")
                    or event_data.get("transport")
                    or event_data.get("proto")
                    or event.get("protocol")
                    or event.get("transport")
                    or event.get("proto")
                )

                if protocol and not evidence["protocol"]:
                    evidence["protocol"] = str(protocol)

                # -----------------------------------------
                # ACTION
                # -----------------------------------------

                action = (
                    event_data.get("action")
                    or event_data.get("event_action")
                    or event_data.get("status")
                    or event.get("action")
                    or event.get("event_action")
                    or event.get("status")
                )

                if action and not evidence["action"]:
                    evidence["action"] = str(action)

                # -----------------------------------------
                # PROCESS
                # -----------------------------------------

                process = (
                    event_data.get("process")
                    or event_data.get("process_name")
                    or event_data.get("exe")
                    or event.get("process")
                    or event.get("process_name")
                    or event.get("exe")
                )

                if process and not evidence["process"]:
                    evidence["process"] = str(process)

                # -----------------------------------------
                # COMMAND
                # -----------------------------------------

                command = (
                    event_data.get("command")
                    or event_data.get("cmd")
                    or event.get("command")
                    or event.get("cmd")
                )

                if command and not evidence["command"]:
                    evidence["command"] = str(command)

                # -----------------------------------------
                # FILE PATH
                # -----------------------------------------

                file_path = (
                    event_data.get("file_path")
                    or event_data.get("path")
                    or event.get("file_path")
                    or event.get("path")
                )

                if file_path and not evidence["file_path"]:
                    evidence["file_path"] = str(file_path)

                # -----------------------------------------
                # MESSAGE
                # -----------------------------------------

                message = (
                    event.get("message")
                    or event.get("msg")
                    or event_data.get("message")
                    or event_data.get("msg")
                )

                if message:

                    message = str(message)

                    self._append_unique(
                        evidence["event_messages"],
                        message,
                    )

                    if not evidence["message"]:
                        evidence["message"] = message

                # -----------------------------------------
                # FAILED AUTH DETECTION
                # -----------------------------------------

                combined_action = str(
                    action or ""
                ).lower()

                combined_message = str(
                    message or ""
                ).lower()

                if (
                    "authentication_failed"
                    in combined_action
                    or "authentication failure"
                    in combined_action
                    or "failed password"
                    in combined_message
                    or "authentication failed"
                    in combined_message
                    or "failed login"
                    in combined_message
                    or "login failed"
                    in combined_message
                ):

                    evidence[
                        "failed_authentication_count"
                    ] += 1

        # -------------------------------------------------
        # FALLBACK: SEARCH ALL NESTED VALUES
        # -------------------------------------------------

        # This is useful when the alert does not use an
        # "events" array but still contains nested Wazuh data.

        for key, value in self._walk_values(full_log):

            if value is None:
                continue

            # ---------------------------------------------
            # SOURCE IP
            # ---------------------------------------------

            if key in (
                "srcip",
                "source_ip",
                "sourceip",
            ):

                if not evidence["source_ip"]:
                    evidence["source_ip"] = str(value)

            # ---------------------------------------------
            # DEST IP
            # ---------------------------------------------

            elif key in (
                "dstip",
                "destination_ip",
                "dest_ip",
            ):

                if not evidence["destination_ip"]:
                    evidence["destination_ip"] = str(value)

            # ---------------------------------------------
            # SOURCE PORT
            # ---------------------------------------------

            elif key in (
                "srcport",
                "source_port",
            ):

                if not evidence["source_port"]:
                    try:
                        evidence["source_port"] = int(value)
                    except (TypeError, ValueError):
                        evidence["source_port"] = value

            # ---------------------------------------------
            # DESTINATION PORT
            # ---------------------------------------------

            elif key in (
                "dstport",
                "destination_port",
                "dest_port",
            ):

                if not evidence["destination_port"]:
                    try:
                        evidence["destination_port"] = int(value)
                    except (TypeError, ValueError):
                        evidence["destination_port"] = value

            # ---------------------------------------------
            # USER
            # ---------------------------------------------

            elif key in (
                "srcuser",
                "dstuser",
                "user",
                "username",
                "account",
            ):

                if not evidence["user"]:
                    evidence["user"] = str(value)

            # ---------------------------------------------
            # PROTOCOL
            # ---------------------------------------------

            elif key in (
                "protocol",
                "transport",
                "proto",
            ):

                if not evidence["protocol"]:
                    evidence["protocol"] = str(value)

            # ---------------------------------------------
            # ACTION
            # ---------------------------------------------

            elif key in (
                "action",
                "event_action",
                "status",
            ):

                if not evidence["action"]:
                    evidence["action"] = str(value)

            # ---------------------------------------------
            # PROCESS
            # ---------------------------------------------

            elif key in (
                "process",
                "process_name",
                "exe",
            ):

                if not evidence["process"]:
                    evidence["process"] = str(value)

            # ---------------------------------------------
            # COMMAND
            # ---------------------------------------------

            elif key in (
                "command",
                "cmd",
            ):

                if not evidence["command"]:
                    evidence["command"] = str(value)

            # ---------------------------------------------
            # FILE PATH
            # ---------------------------------------------

            elif key in (
                "file_path",
                "path",
            ):

                if not evidence["file_path"]:
                    evidence["file_path"] = str(value)

            # ---------------------------------------------
            # MESSAGE
            # ---------------------------------------------

            elif key in (
                "message",
                "msg",
            ):

                self._append_unique(
                    evidence["event_messages"],
                    str(value),
                )

                if not evidence["message"]:
                    evidence["message"] = str(value)

        # -------------------------------------------------
        # REGEX PARSE SSH MESSAGE
        # -------------------------------------------------

        ssh_messages = list(
            evidence["event_messages"]
        )

        for message in ssh_messages:

            # Example:
            # Failed password for root from
            # 203.0.113.42 port 54321 ssh2

            ssh_match = re.search(
                r"Failed password for\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)\s+port\s+(\d+)",
                message,
                re.IGNORECASE,
            )

            if ssh_match:

                username = ssh_match.group(1)
                ip = ssh_match.group(2)
                port = int(ssh_match.group(3))

                if not evidence["user"]:
                    evidence["user"] = username

                if not evidence["source_ip"]:
                    evidence["source_ip"] = ip

                if not evidence["source_port"]:
                    evidence["source_port"] = port

                if not evidence["protocol"]:
                    evidence["protocol"] = "ssh"

                if not evidence["action"]:
                    evidence["action"] = (
                        "authentication_failed"
                    )

        # -------------------------------------------------
        # FALLBACK SINGLE-EVENT FAILED AUTH COUNT
        # -------------------------------------------------

        if (
            evidence["failed_authentication_count"] == 0
            and (
                "authentication_failed"
                in str(evidence["action"]).lower()
                or "failed password"
                in str(evidence["message"]).lower()
            )
        ):
            evidence[
                "failed_authentication_count"
            ] = 1

        # -------------------------------------------------
        # GENERATE SOURCE IP COUNTS FOR SINGLE EVENT
        # -------------------------------------------------

        if evidence["source_ip"]:

            source_ip = str(
                evidence["source_ip"]
            )

            if source_ip not in evidence[
                "source_ip_event_counts"
            ]:

                evidence["source_ip_event_counts"][
                    source_ip
                ] = evidence["event_count"]

        # -------------------------------------------------
        # DETERMINE EVENT PATTERN
        # -------------------------------------------------

        failed_count = evidence[
            "failed_authentication_count"
        ]

        source_counts = evidence[
            "source_ip_event_counts"
        ]

        protocol = str(
            evidence["protocol"] or ""
        ).lower()

        user = str(
            evidence["user"] or ""
        )

        if failed_count >= 3:

            dominant_source = None
            dominant_count = 0

            for ip, count in source_counts.items():

                if count > dominant_count:

                    dominant_source = ip
                    dominant_count = count

            if (
                dominant_source
                and dominant_count >= 3
            ):

                evidence["event_pattern"] = (
                    f"{failed_count} failed authentication "
                    f"attempts detected"
                )

                if protocol:
                    evidence["event_pattern"] += (
                        f" over {protocol}"
                    )

                if user:
                    evidence["event_pattern"] += (
                        f" against user {user}"
                    )

                evidence["event_pattern"] += (
                    f" from the same source IP "
                    f"{dominant_source}"
                )

            else:

                evidence["event_pattern"] = (
                    f"{failed_count} failed authentication "
                    f"attempts detected"
                )

        elif evidence["event_count"] > 1:

            evidence["event_pattern"] = (
                f"{evidence['event_count']} events "
                f"were provided in this alert"
            )

        else:

            evidence["event_pattern"] = (
                "Single event"
            )

        # -------------------------------------------------
        # LOG NORMALIZED EVIDENCE
        # -------------------------------------------------

        logger.debug(
            "normalized_alert_evidence=%s",
            json.dumps(
                evidence,
                default=str,
                ensure_ascii=False,
            ),
        )

        return evidence

    # -----------------------------------------------------
    # BUILD TRIAGE PROMPT
    # -----------------------------------------------------

    def _build_triage_prompt(
        self,
        alert: SecurityAlert,
        context: str = "",
    ) -> str:
        """
        Build the security triage prompt.

        The normalized evidence generated by
        _extract_evidence() is the primary source of truth.
        """

        # -------------------------------------------------
        # CONTEXT
        # -------------------------------------------------

        context_section = ""

        if context:

            context_section = (
                "\n\n"
                "================ ANALYST CONTEXT ================\n"
                f"{context}\n"
                "===================================================\n"
            )

        # -------------------------------------------------
        # NORMALIZED EVIDENCE
        # -------------------------------------------------

        evidence = self._extract_evidence(
            alert
        )

        normalized_evidence = f"""
ALERT ID:
{evidence["alert_id"]}

WAZUH RULE:
{evidence["rule_description"]}

WAZUH RULE LEVEL:
{evidence["rule_level"]}

TIMESTAMP:
{evidence["timestamp"]}

SOURCE IP:
{evidence["source_ip"] or "UNKNOWN"}

DESTINATION IP:
{evidence["destination_ip"] or "UNKNOWN"}

SOURCE PORT:
{evidence["source_port"] or "UNKNOWN"}

DESTINATION PORT:
{evidence["destination_port"] or "UNKNOWN"}

USER:
{evidence["user"] or "UNKNOWN"}

PROCESS:
{evidence["process"] or "UNKNOWN"}

COMMAND:
{evidence["command"] or "UNKNOWN"}

FILE PATH:
{evidence["file_path"] or "UNKNOWN"}

PROTOCOL:
{evidence["protocol"] or "UNKNOWN"}

ACTION:
{evidence["action"] or "UNKNOWN"}

SOURCE HOSTNAME:
{evidence["source_hostname"] or "UNKNOWN"}

MESSAGE:
{evidence["message"] or "NONE"}

EVENT COUNT:
{evidence.get("event_count", 1)}

FAILED AUTHENTICATION COUNT:
{evidence.get("failed_authentication_count", 0)}

SOURCE IP EVENT COUNTS:
{json.dumps(
    evidence.get("source_ip_event_counts", {}),
    indent=2,
    ensure_ascii=False,
)}

EVENT PATTERN:
{evidence.get("event_pattern", "NONE")}

ALL EVENT MESSAGES:
{json.dumps(
    evidence.get("event_messages", []),
    indent=2,
    ensure_ascii=False,
)}
"""

        # -------------------------------------------------
        # PROMPT
        # -------------------------------------------------

        prompt = f"""
You are a cybersecurity analyst performing SOC alert triage.

Analyze exactly ONE security alert.

Use the NORMALIZED EVIDENCE section as the primary source
of truth.

Do not invent facts.

{context_section}

================ NORMALIZED EVIDENCE ================

{normalized_evidence}

======================================================

ANALYSIS RULES:

1. Report only facts supported by the evidence.

2. Do not claim information is missing when it is present
   in NORMALIZED EVIDENCE.

3. Review ALL EVENTS and EVENT COUNT before deciding whether
   this is a repeated pattern.

4. Do not reduce a multi-event alert to a single event.

5. If multiple failed authentication events share the same
   source IP, target account, and protocol, recognize the
   repeated pattern as evidence consistent with a possible
   brute-force attack.

6. A single authentication failure is NOT sufficient by
   itself to classify an event as brute force.

7. Do not treat an IP address as malicious merely because
   it appears in the log.

8. Do not invent IOCs, usernames, domains, hashes,
   processes, files, or MITRE techniques.

9. If evidence is insufficient, explicitly use:
   "INSUFFICIENT_DATA"

10. Confidence must be between 0.0 and 1.0.

11. For MITRE ATT&CK mapping, use only techniques directly
    supported by the observed behavior.

12. Recommendations must be based on the evidence.

13. When the normalized evidence shows repeated SSH authentication
    failures against an account from the same source IP, the behavior
    is consistent with MITRE ATT&CK T1110.001 (Password Guessing).

14. Do not assign T1110.001 for a single failed authentication event.

15. When T1110.001 is supported by the evidence, return:
    - mitre_techniques: ["T1110.001"]
    - mitre_tactics: ["TA0006"]

================ OUTPUT REQUIREMENTS ================

Return ONLY valid JSON.

The JSON must contain:

{{
    "severity": "high",
    "category": "intrusion_attempt",
    "confidence": 0.92,
    "summary": "Brief one-sentence summary",
    "detailed_analysis": "Technical analysis based on evidence",
    "potential_impact": "Potential security impact",
    "is_true_positive": true,
    "false_positive_reason": null,
    "iocs": [
        {{
            "ioc_type": "ip",
            "value": "203.0.113.42",
            "confidence": 0.90
        }}
    ],
    "mitre_techniques": [],
    "mitre_tactics": [],
    "recommendations": [
        {{
            "action": "Investigate repeated authentication failures",
            "priority": 1,
            "rationale": "Repeated authentication failures were observed"
        }}
    ],
    "investigation_priority": 2,
    "estimated_analyst_time": 15
}}

================ IMPORTANT ===========================

For a multi-event authentication alert:

- Mention the number of failed attempts.
- Mention whether they come from the same source IP.
- Mention the target user when supported.
- Mention the protocol when supported.
- Distinguish repeated authentication failures from a
  confirmed successful compromise.
- Do not claim that access was successfully obtained unless
  there is evidence of successful authentication.

Begin analysis now.
"""

        return prompt

    # -----------------------------------------------------
    # CALL OLLAMA
    # -----------------------------------------------------

    async def _call_ollama(
        self,
        prompt: str,
        model: str,
        temperature: float = 0.1,
    ) -> Optional[str]:

        try:

            async with httpx.AsyncClient(
                timeout=self.timeout
            ) as client:

                payload = {
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": settings.max_tokens,
                    },
                    "format": "json",
                }

                logger.info(
                    f"Calling Ollama model: {model}"
                )

                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )

                if response.status_code == 200:

                    result = response.json()

                    return result.get("response")

                else:

                    logger.error(
                        "Ollama API error: "
                        f"{response.status_code} - "
                        f"{response.text}"
                    )

                    return None

        except httpx.TimeoutException:

            logger.error(
                f"Ollama request timeout "
                f"after {self.timeout}s"
            )

            return None

        except Exception as e:

            logger.error(
                f"Ollama API call failed: {e}"
            )

            return None

    # -----------------------------------------------------
    # PARSE LLM RESPONSE
    # -----------------------------------------------------

    def _parse_llm_response(
        self,
        alert: SecurityAlert,
        llm_output: str,
        model_used: str,
    ) -> Optional[TriageResponse]:

        try:

            json_text = llm_output.strip()

            # Remove markdown code block
            if json_text.startswith("```"):

                lines = json_text.split("\n")

                json_text = "\n".join(
                    lines[1:-1]
                )

            # Remove inline code
            if (
                json_text.startswith("`")
                and json_text.endswith("`")
            ):

                json_text = json_text[1:-1]

            parsed = json.loads(
                json_text
            )

            response = TriageResponse(

                alert_id=alert.alert_id,

                severity=SeverityLevel(
                    parsed.get(
                        "severity",
                        "medium",
                    )
                ),

                category=AlertCategory(
                    normalize_category(
                        parsed.get(
                            "category",
                            "other",
                        )
                    )
                ),

                confidence=float(
                    parsed.get(
                        "confidence",
                        0.5,
                    )
                ),

                summary=parsed.get(
                    "summary",
                    "No summary provided",
                ),

                detailed_analysis=parsed.get(
                    "detailed_analysis",
                    "",
                ),

                potential_impact=parsed.get(
                    "potential_impact",
                    "",
                ),

                is_true_positive=parsed.get(
                    "is_true_positive",
                    True,
                ),

                false_positive_reason=parsed.get(
                    "false_positive_reason"
                ),

                iocs=[
                    IOC(**ioc)
                    for ioc in parsed.get(
                        "iocs",
                        [],
                    )
                ],

                mitre_techniques=parsed.get(
                    "mitre_techniques",
                    [],
                ),

                mitre_tactics=parsed.get(
                    "mitre_tactics",
                    [],
                ),

                recommendations=[
                    TriageRecommendation(**rec)
                    for rec in parsed.get(
                        "recommendations",
                        [],
                    )
                ],

                investigation_priority=int(
                    parsed.get(
                        "investigation_priority",
                        3,
                    )
                ),

                estimated_analyst_time=parsed.get(
                    "estimated_analyst_time"
                ),

                model_used=model_used,
            )

            return response

        except json.JSONDecodeError as e:

            logger.error(
                f"Failed to parse LLM JSON output: {e}"
            )

            logger.debug(
                f"Raw output: {llm_output[:1000]}"
            )

            return None

        except Exception as e:

            logger.error(
                f"Error constructing "
                f"TriageResponse: {e}"
            )

            return None

    # -----------------------------------------------------
    # ANALYZE ALERT
    # -----------------------------------------------------

    async def analyze_alert(
        self,
        alert: SecurityAlert,
    ) -> Optional[TriageResponse]:

        # -------------------------------------------------
        # STEP 1: ML PREDICTION
        # -------------------------------------------------

        ml_prediction = None

        if settings.ml_enabled:

            logger.debug(
                "Attempting ML prediction..."
            )

            ml_prediction = (
                await self.ml_client.predict_with_fallback(
                    alert
                )
            )

            if ml_prediction:

                logger.info(
                    "ML prediction: "
                    f"{ml_prediction.prediction} "
                    f"(confidence="
                    f"{ml_prediction.confidence:.2f})"
                )

        # -------------------------------------------------
        # STEP 2: CONTEXT
        # -------------------------------------------------

        context_block = (
            await self.context_manager.build_context(
                alert
            )
        )

        # -------------------------------------------------
        # STEP 3: BUILD PROMPT
        # -------------------------------------------------

        base_prompt = (
            self._build_triage_prompt(
                alert,
                context=context_block,
            )
        )

        # -------------------------------------------------
        # STEP 4: ML ENRICHMENT
        # -------------------------------------------------

        enriched_prompt = (
            enrich_llm_prompt_with_ml(
                base_prompt,
                ml_prediction,
            )
        )

        # -------------------------------------------------
        # STEP 5: PRIMARY MODEL
        # -------------------------------------------------

        logger.info(
            f"Analyzing alert "
            f"{alert.alert_id} "
            f"with {self.primary_model}"
        )

        llm_output = await self._call_ollama(
            enriched_prompt,
            self.primary_model,
            settings.llm_temperature,
        )

        if llm_output:

            response = self._parse_llm_response(
                alert,
                llm_output,
                self.primary_model,
            )

            if response:

                if ml_prediction:

                    response.ml_prediction = (
                        ml_prediction.prediction
                    )

                    response.ml_confidence = (
                        ml_prediction.confidence
                    )

                logger.info(
                    f"Alert {alert.alert_id} "
                    f"analyzed successfully"
                )

                return response

        # -------------------------------------------------
        # STEP 6: FALLBACK MODEL
        # -------------------------------------------------

        logger.warning(
            "Primary model failed, "
            f"trying fallback: "
            f"{self.fallback_model}"
        )

        llm_output = await self._call_ollama(
            enriched_prompt,
            self.fallback_model,
            settings.llm_temperature,
        )

        if llm_output:

            response = self._parse_llm_response(
                alert,
                llm_output,
                self.fallback_model,
            )

            if response:

                if ml_prediction:

                    response.ml_prediction = (
                        ml_prediction.prediction
                    )

                    response.ml_confidence = (
                        ml_prediction.confidence
                    )

                logger.info(
                    f"Alert {alert.alert_id} "
                    f"analyzed with fallback model"
                )

                return response

        # -------------------------------------------------
        # BOTH MODELS FAILED
        # -------------------------------------------------

        logger.error(
            f"Failed to analyze alert "
            f"{alert.alert_id} "
            f"with all models"
        )

        return None