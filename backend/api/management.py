"""Management endpoints for administration, health checks, and data cleanup."""

import os
import logging
import shutil
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy import select, func, delete, text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from config import get_settings
from database import (
    get_db, async_session, Submission, SubmissionStatus, AnalysisResult,
    IOC, Enrichment, Report, MITRETechniqueValidation, InvestigationPlan
)

router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)

# Track process start time for uptime calculation
_process_start_time = datetime.utcnow()


class CleanupRequest(BaseModel):
    """Request model for cleanup endpoint."""
    older_than_days: int = 90


@router.delete("/submissions/{submission_id}")
async def delete_submission(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a submission and all associated data (cascade)."""
    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    deleted_counts = {}

    # Delete enrichment data (linked through IOCs)
    ioc_result = await db.execute(
        select(IOC.id).filter(IOC.submission_id == submission_id)
    )
    ioc_ids = [row[0] for row in ioc_result.all()]

    if ioc_ids:
        enrichment_delete = await db.execute(
            delete(Enrichment).where(Enrichment.ioc_id.in_(ioc_ids))
        )
        deleted_counts["enrichment"] = enrichment_delete.rowcount
    else:
        deleted_counts["enrichment"] = 0

    # Delete IOCs
    ioc_delete = await db.execute(
        delete(IOC).where(IOC.submission_id == submission_id)
    )
    deleted_counts["iocs"] = ioc_delete.rowcount

    # Delete analysis results
    analysis_delete = await db.execute(
        delete(AnalysisResult).where(AnalysisResult.submission_id == submission_id)
    )
    deleted_counts["analysis_results"] = analysis_delete.rowcount

    # Delete reports
    report_delete = await db.execute(
        delete(Report).where(Report.submission_id == submission_id)
    )
    deleted_counts["reports"] = report_delete.rowcount

    # Delete MITRE validations
    mitre_delete = await db.execute(
        delete(MITRETechniqueValidation).where(
            MITRETechniqueValidation.submission_id == submission_id
        )
    )
    deleted_counts["mitre_validations"] = mitre_delete.rowcount

    # Delete investigation plans
    plan_delete = await db.execute(
        delete(InvestigationPlan).where(
            InvestigationPlan.submission_id == submission_id
        )
    )
    deleted_counts["investigation_plans"] = plan_delete.rowcount

    # Delete the submission itself
    await db.execute(
        delete(Submission).where(Submission.id == submission_id)
    )
    deleted_counts["submission"] = 1

    await db.commit()

    logger.info(f"Deleted submission {submission_id} and associated data: {deleted_counts}")

    return {
        "message": f"Submission {submission_id} deleted",
        "deleted_counts": deleted_counts
    }


@router.post("/submissions/{submission_id}/reanalyze")
async def reanalyze_submission(
    submission_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Reset a submission to PENDING status and trigger re-analysis."""
    from api.analysis import run_analysis

    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.status not in [SubmissionStatus.COMPLETE, SubmissionStatus.FAILED]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reanalyze submission in status: {submission.status.value}. "
                   f"Only COMPLETE or FAILED submissions can be reanalyzed."
        )

    # Reset submission fields
    submission.status = SubmissionStatus.PENDING
    submission.error_message = None
    submission.severity = None
    submission.confidence_score = None
    submission.completed_at = None
    await db.commit()

    # Trigger re-analysis in background
    background_tasks.add_task(run_analysis, submission_id)

    logger.info(f"Reanalysis triggered for submission {submission_id}")

    return {
        "message": "Reanalysis triggered",
        "submission_id": submission_id
    }


@router.get("/health/detailed")
async def detailed_health_check(
    db: AsyncSession = Depends(get_db)
):
    """Detailed health check with DB connectivity, submission stats, disk usage, and uptime."""
    checks = {}
    overall_status = "healthy"

    # Check DB connectivity
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = {"status": "connected"}
    except Exception as e:
        checks["database"] = {"status": "disconnected", "error": str(e)}
        overall_status = "degraded"

    # Total submissions count
    try:
        total_result = await db.execute(select(func.count(Submission.id)))
        total_submissions = total_result.scalar() or 0
        checks["total_submissions"] = total_submissions
    except Exception as e:
        checks["total_submissions"] = {"error": str(e)}
        overall_status = "degraded"

    # Submissions by status breakdown
    try:
        status_query = select(
            Submission.status, func.count(Submission.id)
        ).group_by(Submission.status)
        status_result = await db.execute(status_query)
        status_rows = status_result.all()
        submissions_by_status = {}
        for row in status_rows:
            key = row[0].value if hasattr(row[0], "value") else str(row[0])
            submissions_by_status[key] = row[1]
        checks["submissions_by_status"] = submissions_by_status
    except Exception as e:
        checks["submissions_by_status"] = {"error": str(e)}
        overall_status = "degraded"

    # Disk usage of upload_dir
    try:
        upload_path = os.path.abspath(settings.upload_dir)
        if os.path.exists(upload_path):
            disk_usage = shutil.disk_usage(upload_path)
            total_dir_size = 0
            for dirpath, dirnames, filenames in os.walk(upload_path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        total_dir_size += os.path.getsize(fp)
            checks["disk_usage"] = {
                "upload_dir": upload_path,
                "upload_dir_size_bytes": total_dir_size,
                "upload_dir_size_mb": round(total_dir_size / (1024 * 1024), 2),
                "disk_total_bytes": disk_usage.total,
                "disk_used_bytes": disk_usage.used,
                "disk_free_bytes": disk_usage.free,
                "disk_usage_percent": round(disk_usage.used / disk_usage.total * 100, 1)
            }
        else:
            checks["disk_usage"] = {
                "upload_dir": upload_path,
                "status": "directory not found"
            }
            overall_status = "degraded"
    except Exception as e:
        checks["disk_usage"] = {"error": str(e)}
        overall_status = "degraded"

    # Uptime
    now = datetime.utcnow()
    uptime_seconds = (now - _process_start_time).total_seconds()
    checks["uptime"] = {
        "started_at": _process_start_time.isoformat(),
        "uptime_seconds": round(uptime_seconds, 1),
        "uptime_human": _format_uptime(uptime_seconds)
    }

    return {
        "status": overall_status,
        "checks": checks
    }


@router.post("/cleanup")
async def cleanup_old_data(
    request: Optional[CleanupRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """Cleanup old failed submissions and orphaned analysis results."""
    older_than_days = request.older_than_days if request else 90
    cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)

    # Find failed submissions older than cutoff
    old_failed_query = select(Submission.id).filter(
        Submission.status == SubmissionStatus.FAILED,
        Submission.created_at < cutoff_date
    )
    old_failed_result = await db.execute(old_failed_query)
    old_failed_ids = [row[0] for row in old_failed_result.all()]

    deleted_submissions = 0

    if old_failed_ids:
        # Delete associated data for each old failed submission
        # Get IOC ids for enrichment deletion
        ioc_result = await db.execute(
            select(IOC.id).filter(IOC.submission_id.in_(old_failed_ids))
        )
        ioc_ids = [row[0] for row in ioc_result.all()]

        if ioc_ids:
            await db.execute(
                delete(Enrichment).where(Enrichment.ioc_id.in_(ioc_ids))
            )

        await db.execute(
            delete(IOC).where(IOC.submission_id.in_(old_failed_ids))
        )
        await db.execute(
            delete(AnalysisResult).where(AnalysisResult.submission_id.in_(old_failed_ids))
        )
        await db.execute(
            delete(Report).where(Report.submission_id.in_(old_failed_ids))
        )
        await db.execute(
            delete(MITRETechniqueValidation).where(
                MITRETechniqueValidation.submission_id.in_(old_failed_ids)
            )
        )
        await db.execute(
            delete(InvestigationPlan).where(
                InvestigationPlan.submission_id.in_(old_failed_ids)
            )
        )

        result = await db.execute(
            delete(Submission).where(Submission.id.in_(old_failed_ids))
        )
        deleted_submissions = result.rowcount

    # Delete orphaned analysis results (no matching submission)
    orphan_query = delete(AnalysisResult).where(
        ~AnalysisResult.submission_id.in_(
            select(Submission.id)
        )
    )
    orphan_result = await db.execute(orphan_query)
    deleted_orphans = orphan_result.rowcount

    await db.commit()

    logger.info(
        f"Cleanup complete: {deleted_submissions} old failed submissions deleted, "
        f"{deleted_orphans} orphaned analysis results deleted"
    )

    return {
        "message": "Cleanup complete",
        "deleted_submissions": deleted_submissions,
        "deleted_orphans": deleted_orphans
    }


def _format_uptime(seconds: float) -> str:
    """Format uptime seconds into a human-readable string."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)
