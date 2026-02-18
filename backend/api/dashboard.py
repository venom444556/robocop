"""Dashboard statistics endpoints for the malware analysis platform."""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, distinct, case, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    get_db, async_session, Submission, SubmissionStatus, SubmissionType,
    AnalysisResult, IOC, MITRETechniqueValidation, SeverityLevel
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get comprehensive dashboard statistics for the platform overview."""

    # ── Submission status counts ──────────────────────────────────────
    status_query = select(
        func.count(Submission.id).label("total"),
        func.count(case((Submission.status == SubmissionStatus.COMPLETE, 1))).label("complete"),
        func.count(case((Submission.status == SubmissionStatus.FAILED, 1))).label("failed"),
        func.count(case((Submission.status == SubmissionStatus.ANALYZING, 1))).label("analyzing"),
    )
    status_result = await db.execute(status_query)
    status_row = status_result.one()
    total_submissions = status_row.total
    total_complete = status_row.complete
    total_failed = status_row.failed
    total_analyzing = status_row.analyzing

    # ── Submissions by type ───────────────────────────────────────────
    type_query = select(
        Submission.type, func.count(Submission.id)
    ).group_by(Submission.type)
    type_result = await db.execute(type_query)
    type_rows = type_result.all()
    submissions_by_type = {
        "file": 0,
        "url": 0,
        "sandbox_report": 0,
    }
    for row in type_rows:
        key = row[0].value if hasattr(row[0], "value") else str(row[0])
        if key in submissions_by_type:
            submissions_by_type[key] = row[1]

    # ── Submissions by severity ───────────────────────────────────────
    severity_query = select(
        Submission.severity, func.count(Submission.id)
    ).where(Submission.severity.isnot(None)).group_by(Submission.severity)
    severity_result = await db.execute(severity_query)
    severity_rows = severity_result.all()
    submissions_by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    for row in severity_rows:
        key = row[0].value if hasattr(row[0], "value") else str(row[0])
        if key in submissions_by_severity:
            submissions_by_severity[key] = row[1]

    # ── IOC counts ────────────────────────────────────────────────────
    total_iocs_query = select(func.count(IOC.id))
    total_iocs_result = await db.execute(total_iocs_query)
    total_iocs = total_iocs_result.scalar() or 0

    unique_iocs_query = select(func.count(distinct(IOC.value)))
    unique_iocs_result = await db.execute(unique_iocs_query)
    total_unique_iocs = unique_iocs_result.scalar() or 0

    # ── Average IOCs per submission ───────────────────────────────────
    if total_submissions > 0:
        avg_iocs_per_submission = round(total_iocs / total_submissions, 2)
    else:
        avg_iocs_per_submission = 0.0

    # ── Submissions last 7 days ───────────────────────────────────────
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)

    daily_query = (
        select(
            func.date(Submission.created_at).label("day"),
            func.count(Submission.id).label("count"),
        )
        .where(func.date(Submission.created_at) >= seven_days_ago)
        .group_by(func.date(Submission.created_at))
    )
    daily_result = await db.execute(daily_query)
    daily_rows = daily_result.all()
    daily_map = {str(row.day): row.count for row in daily_rows}

    submissions_last_7_days = []
    for i in range(7):
        day = seven_days_ago + timedelta(days=i)
        day_str = str(day)
        submissions_last_7_days.append({
            "date": day_str,
            "count": daily_map.get(day_str, 0),
        })

    # ── Top IOCs (top 10 by frequency across submissions) ─────────────
    top_iocs_query = (
        select(
            IOC.value,
            IOC.type,
            func.count(distinct(IOC.submission_id)).label("count"),
            func.max(IOC.created_at).label("last_seen"),
        )
        .group_by(IOC.value, IOC.type)
        .order_by(func.count(distinct(IOC.submission_id)).desc())
        .limit(10)
    )
    top_iocs_result = await db.execute(top_iocs_query)
    top_iocs_rows = top_iocs_result.all()
    top_iocs = [
        {
            "value": row.value,
            "type": row.type.value if hasattr(row.type, "value") else str(row.type),
            "count": row.count,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        }
        for row in top_iocs_rows
    ]

    # ── MITRE ATT&CK heatmap (validated techniques) ──────────────────
    mitre_query = (
        select(
            MITRETechniqueValidation.technique_id,
            MITRETechniqueValidation.technique_name,
            MITRETechniqueValidation.tactic,
            func.count(MITRETechniqueValidation.id).label("count"),
        )
        .where(MITRETechniqueValidation.is_validated == True)  # noqa: E712
        .group_by(
            MITRETechniqueValidation.technique_id,
            MITRETechniqueValidation.technique_name,
            MITRETechniqueValidation.tactic,
        )
        .order_by(func.count(MITRETechniqueValidation.id).desc())
    )
    mitre_result = await db.execute(mitre_query)
    mitre_rows = mitre_result.all()
    mitre_heatmap = [
        {
            "technique_id": row.technique_id,
            "technique_name": row.technique_name,
            "tactic": row.tactic,
            "count": row.count,
        }
        for row in mitre_rows
    ]

    # ── Recent threat hunt findings (latest 10) ──────────────────────
    findings_query = (
        select(AnalysisResult)
        .where(AnalysisResult.analyzer == "threat_hunter")
        .order_by(AnalysisResult.created_at.desc())
        .limit(20)  # fetch extra rows so we can gather at least 10 individual findings
    )
    findings_result = await db.execute(findings_query)
    findings_rows = findings_result.scalars().all()

    recent_findings = []
    for ar in findings_rows:
        results = ar.results_json or {}
        threat_hunt = results.get("threat_hunt", results)
        items = threat_hunt.get("findings", [])
        for finding in items:
            recent_findings.append({
                "submission_id": ar.submission_id,
                "title": finding.get("title", finding.get("description", "Untitled finding")),
                "severity": finding.get("severity", "informational").lower(),
                "confidence": finding.get("confidence", "low").lower(),
                "created_at": ar.created_at.isoformat() if ar.created_at else None,
            })
            if len(recent_findings) >= 10:
                break
        if len(recent_findings) >= 10:
            break

    # ── Assemble response ─────────────────────────────────────────────
    return {
        "total_submissions": total_submissions,
        "total_complete": total_complete,
        "total_failed": total_failed,
        "total_analyzing": total_analyzing,
        "submissions_by_type": submissions_by_type,
        "submissions_by_severity": submissions_by_severity,
        "total_iocs": total_iocs,
        "total_unique_iocs": total_unique_iocs,
        "avg_iocs_per_submission": avg_iocs_per_submission,
        "submissions_last_7_days": submissions_last_7_days,
        "top_iocs": top_iocs,
        "mitre_heatmap": mitre_heatmap,
        "recent_findings": recent_findings,
    }
