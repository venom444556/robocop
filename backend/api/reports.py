"""Report generation and retrieval endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from config import get_settings
from database import get_db, Submission, Report, SubmissionStatus

router = APIRouter()
settings = get_settings()


class ReportResponse(BaseModel):
    """Response model for reports."""
    id: int
    submission_id: int
    format: str
    created_at: datetime

    class Config:
        from_attributes = True


class GenerateReportRequest(BaseModel):
    """Request model for report generation."""
    format: str = "json"  # "json", "html", "pdf"


async def generate_report_task(submission_id: int, format: str, db: AsyncSession):
    """Background task to generate a report."""
    from utils.report_generator import ReportGenerator
    from agents.report_writer import ReportWriterAgent

    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        return

    try:
        # Get analysis results and IOCs
        from database import AnalysisResult, IOC, Enrichment

        results = await db.execute(
            select(AnalysisResult).filter(AnalysisResult.submission_id == submission_id)
        )
        analysis_results = results.scalars().all()

        ioc_results = await db.execute(
            select(IOC).filter(IOC.submission_id == submission_id)
        )
        iocs = ioc_results.scalars().all()

        # Get enrichment data for IOCs
        enrichment_data = {}
        for ioc in iocs:
            enrichments = await db.execute(
                select(Enrichment).filter(Enrichment.ioc_id == ioc.id)
            )
            enrichment_data[ioc.id] = [e.data_json for e in enrichments.scalars().all()]

        # Use Claude agent to generate narrative
        report_writer = ReportWriterAgent()
        narrative = await report_writer.generate_narrative(
            submission=submission,
            analysis_results=[r.results_json for r in analysis_results],
            iocs=[{"type": i.type.value, "value": i.value, "context": i.context} for i in iocs],
            enrichment_data=enrichment_data
        )

        # Generate formatted report
        generator = ReportGenerator()
        report_content = generator.generate(
            format=format,
            submission=submission,
            analysis_results=analysis_results,
            iocs=iocs,
            enrichment_data=enrichment_data,
            narrative=narrative
        )

        # Save report
        report = Report(
            submission_id=submission_id,
            format=format,
            content=report_content
        )
        db.add(report)

        submission.status = SubmissionStatus.COMPLETE
        submission.completed_at = datetime.utcnow()
        await db.commit()

    except Exception as e:
        submission.status = SubmissionStatus.FAILED
        submission.error_message = f"Report generation failed: {str(e)}"
        await db.commit()


@router.post("/{submission_id}/generate", response_model=ReportResponse)
async def generate_report(
    submission_id: int,
    request: GenerateReportRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Generate a report for a completed analysis."""
    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if request.format not in ["json", "html", "pdf"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: json, html, pdf")

    # Check if enrichment is complete
    if submission.status not in [SubmissionStatus.ENRICHING, SubmissionStatus.REASONING, SubmissionStatus.COMPLETE]:
        raise HTTPException(
            status_code=400,
            detail="Analysis not complete. Wait for enrichment to finish."
        )

    submission.status = SubmissionStatus.REASONING
    await db.commit()

    background_tasks.add_task(generate_report_task, submission_id, request.format, db)

    return {
        "id": 0,  # Will be assigned after generation
        "submission_id": submission_id,
        "format": request.format,
        "created_at": datetime.utcnow()
    }


@router.get("/{submission_id}", response_model=list[ReportResponse])
async def list_reports(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """List all reports for a submission."""
    result = await db.execute(
        select(Report).filter(Report.submission_id == submission_id)
    )
    reports = result.scalars().all()

    return [
        ReportResponse(
            id=r.id,
            submission_id=r.submission_id,
            format=r.format,
            created_at=r.created_at
        )
        for r in reports
    ]


@router.get("/{submission_id}/{format}")
async def get_report(
    submission_id: int,
    format: str,
    db: AsyncSession = Depends(get_db)
):
    """Get the latest report in a specific format."""
    result = await db.execute(
        select(Report)
        .filter(Report.submission_id == submission_id, Report.format == format)
        .order_by(Report.created_at.desc())
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if format == "html":
        return HTMLResponse(content=report.content)
    elif format == "pdf":
        return Response(
            content=report.content.encode() if isinstance(report.content, str) else report.content,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{submission_id}.pdf"}
        )
    else:
        import json
        return json.loads(report.content) if isinstance(report.content, str) else report.content


@router.get("/")
async def list_all_reports(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """List all reports with pagination."""
    result = await db.execute(
        select(Report)
        .order_by(Report.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    reports = result.scalars().all()

    return [
        ReportResponse(
            id=r.id,
            submission_id=r.submission_id,
            format=r.format,
            created_at=r.created_at
        )
        for r in reports
    ]
