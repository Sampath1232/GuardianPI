"""Guardian Pi — AWS GuardDuty Integration"""
from __future__ import annotations
import logging
from typing import Optional
from backend.app.core.config import settings

logger = logging.getLogger("guardian.aws.guardduty")


class GuardDutyClient:
    """Ingests findings from AWS GuardDuty and correlates with device alerts."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        if not self._client:
            import boto3
            self._client = boto3.client(
                "guardduty", region_name=settings.AWS_REGION,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )
        return self._client

    async def get_findings(self, max_results: int = 50) -> list[dict]:
        """Fetch recent GuardDuty findings."""
        if not settings.AWS_GUARDDUTY_DETECTOR_ID:
            logger.warning("GuardDuty detector ID not configured")
            return []
        try:
            client = self._get_client()
            response = client.list_findings(
                DetectorId=settings.AWS_GUARDDUTY_DETECTOR_ID,
                MaxResults=max_results,
                SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
            )
            finding_ids = response.get("FindingIds", [])
            if not finding_ids:
                return []
            details = client.get_findings(
                DetectorId=settings.AWS_GUARDDUTY_DETECTOR_ID,
                FindingIds=finding_ids,
            )
            return [
                {
                    "id": f["Id"],
                    "severity": f["Severity"],
                    "title": f["Title"],
                    "description": f["Description"],
                    "type": f["Type"],
                    "resource": f.get("Resource", {}),
                    "updated_at": str(f.get("UpdatedAt", "")),
                }
                for f in details.get("Findings", [])
            ]
        except Exception as e:
            logger.error(f"GuardDuty fetch error: {e}")
            return []


guardduty_client = GuardDutyClient()
