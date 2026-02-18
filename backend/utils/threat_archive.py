"""Threat intelligence archival for historical correlation via JSONL persistence."""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ThreatIntelArchive:
    """JSONL-based threat intelligence archival for historical correlation.
    Inspired by Autonomous SOC Analyst's threats.jsonl persistence pattern."""

    def __init__(self):
        from config import get_settings
        settings = get_settings()
        self.archive_dir = settings.threat_intel_archive_dir
        os.makedirs(self.archive_dir, exist_ok=True)

    def _get_archive_path(self, record_type: str) -> str:
        """Get archive file path, organized by type and month."""
        month = datetime.utcnow().strftime("%Y-%m")
        return os.path.join(self.archive_dir, f"{record_type}_{month}.jsonl")

    async def archive_record(self, record_type: str, data: Dict,
                              submission_id: Optional[int] = None,
                              severity: Optional[str] = None) -> Dict:
        """
        Append an immutable timestamped record to the JSONL archive.

        Args:
            record_type: Type of record (finding, ioc, technique, submission_summary)
            data: Record data to archive
            submission_id: Associated submission ID
            severity: Severity level if applicable

        Returns:
            Dictionary confirming archival
        """
        import aiofiles

        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "record_type": record_type,
            "submission_id": submission_id,
            "severity": severity,
            "data": data
        }

        archive_path = self._get_archive_path(record_type)
        try:
            async with aiofiles.open(archive_path, "a") as f:
                await f.write(json.dumps(record, default=str) + "\n")
            return {"archived": True, "path": archive_path}
        except Exception as e:
            logger.error(f"Failed to archive record: {e}")
            return {"archived": False, "error": str(e)}

    async def archive_submission_results(self, submission_id: int,
                                          submission_data: Dict,
                                          analysis_results: List[Dict],
                                          iocs: List[Dict],
                                          enrichment_data: Dict,
                                          findings: List[Dict]) -> Dict:
        """
        Archive complete submission analysis for longitudinal correlation.

        Args:
            submission_id: Submission identifier
            submission_data: Basic submission info
            analysis_results: List of analysis result dicts
            iocs: List of IOC dicts
            enrichment_data: Enrichment data
            findings: Threat hunt findings

        Returns:
            Dictionary with archival summary
        """
        records_written = 0

        # Archive each IOC
        for ioc in iocs:
            await self.archive_record("ioc", ioc, submission_id)
            records_written += 1

        # Archive each finding
        for finding in findings:
            await self.archive_record(
                "finding", finding, submission_id,
                finding.get("severity")
            )
            records_written += 1

        # Archive submission summary
        summary = {
            "submission": submission_data,
            "ioc_count": len(iocs),
            "finding_count": len(findings),
            "analyzers_used": [
                r.get("analyzer") if isinstance(r, dict) else str(r)
                for r in analysis_results
            ]
        }
        await self.archive_record("submission_summary", summary, submission_id)
        records_written += 1

        return {"archived": True, "records_written": records_written}

    async def correlate_ioc(self, ioc_value: str, months_back: int = 6) -> Dict:
        """
        Find all historical appearances of an IOC across archives.

        Args:
            ioc_value: The IOC value to search for
            months_back: How many months of archives to search

        Returns:
            Dictionary with correlation results
        """
        import aiofiles
        from datetime import timedelta

        matches = []
        now = datetime.utcnow()

        for i in range(months_back):
            month = (now - timedelta(days=30 * i)).strftime("%Y-%m")
            archive_path = os.path.join(self.archive_dir, f"ioc_{month}.jsonl")

            if not os.path.exists(archive_path):
                continue

            try:
                async with aiofiles.open(archive_path, "r") as f:
                    async for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            data = record.get("data", {})
                            if data.get("value") == ioc_value:
                                matches.append(record)
                        except json.JSONDecodeError:
                            logger.debug("Skipping malformed JSONL line in archive %s", archive_path)
                            continue
            except Exception as e:
                logger.warning(f"Error reading archive {archive_path}: {e}")

        return {
            "ioc": ioc_value,
            "appearances": len(matches),
            "first_seen": matches[0]["timestamp"] if matches else None,
            "last_seen": matches[-1]["timestamp"] if matches else None,
            "submissions": list({
                m.get("submission_id") for m in matches
                if m.get("submission_id")
            })
        }
