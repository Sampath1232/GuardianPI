"""Guardian Pi — AWS Security Hub Integration"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from backend.app.core.config import settings

logger = logging.getLogger("guardian.aws.securityhub")


class SecurityHubClient:
    """Exports Guardian Pi findings to AWS Security Hub."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        if not self._client:
            import boto3
            self._client = boto3.client(
                "securityhub", region_name=settings.AWS_REGION,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )
        return self._client

    async def export_finding(self, alert: dict, account_id: str = "000000000000") -> bool:
        """Export a Guardian Pi alert as an ASFF finding to Security Hub."""
        severity_map = {"critical": 90, "high": 70, "medium": 40, "low": 20, "info": 0}
        try:
            client = self._get_client()
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"guardian-pi/{alert['id']}",
                "ProductArn": f"arn:aws:securityhub:{settings.AWS_REGION}:{account_id}:product/{account_id}/default",
                "GeneratorId": "guardian-pi-agent",
                "AwsAccountId": account_id,
                "Types": ["Software and Configuration Checks"],
                "CreatedAt": datetime.now(timezone.utc).isoformat(),
                "UpdatedAt": datetime.now(timezone.utc).isoformat(),
                "Severity": {"Normalized": severity_map.get(alert.get("severity", "info"), 0)},
                "Title": alert.get("title", "Guardian Pi Alert"),
                "Description": alert.get("description", "Security alert from Guardian Pi agent"),
                "Resources": [{"Type": "Other", "Id": alert.get("device_id", "unknown")}],
            }
            client.batch_import_findings(Findings=[finding])
            logger.info(f"Exported finding to Security Hub: {alert['id']}")
            return True
        except Exception as e:
            logger.error(f"Security Hub export error: {e}")
            return False


securityhub_client = SecurityHubClient()
