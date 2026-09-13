"""Outbound alert notification — currently a generic webhook (Slack/Discord/
custom SIEM ingestion all just want a POST of JSON). Deliberately minimal:
add new channels (email, PagerDuty, SNS) behind this same `notify` interface
rather than sprinkling notification logic through the pipeline.
"""

from __future__ import annotations

import httpx

from nids.common import Severity
from nids.logging_config import get_logger

logger = get_logger(__name__)

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class AlertNotifier:
    def __init__(self, webhook_url: str | None, min_severity: Severity = Severity.LOW) -> None:
        self.webhook_url = webhook_url
        self.min_severity = min_severity

    def _passes_threshold(self, severity: Severity) -> bool:
        return severity.rank >= self.min_severity.rank

    async def notify(
        self,
        *,
        rule_id: str,
        name: str,
        severity: Severity,
        description: str,
        src_ip: str,
        dst_ip: str,
    ) -> None:
        if not self.webhook_url or not self._passes_threshold(severity):
            return

        payload = {
            "rule_id": rule_id,
            "name": name,
            "severity": severity.value,
            "description": description,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(self.webhook_url, json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            # Notification failure must never take detection down with it.
            logger.warning("notifier.webhook_failed", error=str(exc), rule_id=rule_id)
