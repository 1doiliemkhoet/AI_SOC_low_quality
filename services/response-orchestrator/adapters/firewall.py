"""Firewall Adapter - Action Execution Layer
AI-Augmented SOC

Placeholder adapter for firewall integrations. No concrete firewall API is
implemented yet, so execution, verification, and rollback fail closed.
Dry-run remains available for planning/demo purposes.
"""

from typing import Dict, Optional

from adapters.base import BaseAdapter, AdapterResult


class FirewallAdapter(BaseAdapter):
    """Placeholder for pfSense, Palo Alto, or AWS Security Group integration."""

    def __init__(self, firewall_type: str = "stub", api_url: str = "", api_key: str = ""):
        super().__init__(name="firewall")
        self.firewall_type = firewall_type
        self.api_url = api_url
        self.api_key = api_key

    def _not_implemented(self, action_type: str, target: str, detail: str) -> AdapterResult:
        return AdapterResult(
            success=False, action_type=action_type, target=target, adapter=self.name,
            detail=detail, error="Action not implemented", rollback_capable=False,
        )

    async def execute(self, action_type: str, target: str, params: Optional[Dict] = None) -> AdapterResult:
        if action_type not in {"block_ip", "network_segment", "sinkhole_domain"}:
            return self._not_implemented(
                action_type, target, f"Unsupported action for firewall adapter: {action_type}"
            )
        return self._not_implemented(
            action_type, target,
            f"Firewall adapter is not implemented for {self.firewall_type}; no firewall change was made.",
        )

    async def dry_run(self, action_type: str, target: str, params: Optional[Dict] = None) -> AdapterResult:
        params = params or {}
        api_calls = {
            "block_ip": {
                "method": "POST",
                "endpoint": f"{self.api_url}/api/v1/firewall/rules" if self.api_url else "/api/v1/firewall/rules",
                "body": {
                    "action": "block", "source": target,
                    "direction": params.get("direction", "both"),
                    "ttl_hours": params.get("duration_hours", 24),
                },
                "description": f"Add {self.firewall_type} rule to block {target}",
            },
            "network_segment": {
                "method": "POST",
                "endpoint": "/api/v1/firewall/rules",
                "body": {
                    "action": "deny",
                    "source_zone": params.get("source_segment", ""),
                    "dest_zone": params.get("dest_segment", ""),
                },
                "description": f"Add inter-segment deny rule via {self.firewall_type}",
            },
            "sinkhole_domain": {
                "method": "POST",
                "endpoint": "/api/v1/dns/overrides",
                "body": {"domain": params.get("domain", target), "target": "0.0.0.0"},
                "description": f"Sinkhole DNS for {params.get('domain', target)}",
            },
        }
        call = api_calls.get(action_type, {
            "description": f"Unknown action {action_type}",
            "method": "N/A", "endpoint": "N/A", "body": {},
        })
        return AdapterResult(
            success=True, action_type=action_type, target=target, adapter=self.name,
            detail=f"[DRY RUN] {call['description']}",
            raw_response={"would_call": call, "firewall_type": self.firewall_type},
            rollback_capable=True,
        )

    async def verify(self, action_type: str, target: str, params: Optional[Dict] = None) -> AdapterResult:
        return self._not_implemented(
            action_type, target,
            f"Firewall verification is not implemented for {self.firewall_type}; the adapter cannot confirm an active rule.",
        )

    async def rollback(self, action_type: str, target: str, params: Optional[Dict] = None) -> AdapterResult:
        return self._not_implemented(
            action_type, target,
            f"Firewall rollback is not implemented for {self.firewall_type}; the adapter cannot confirm rule removal.",
        )

    async def health_check(self) -> bool:
        return False
