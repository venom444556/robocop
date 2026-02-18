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


def _determine_highest_severity(hunt_results: dict) -> str:
    """Extract the highest severity from threat hunt findings."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    findings = hunt_results.get("threat_hunt", {}).get("findings", [])
    highest = "informational"
    for f in findings:
        sev = f.get("severity", "informational").lower()
        if severity_order.get(sev, 5) < severity_order.get(highest, 5):
            highest = sev
    return highest


def _calculate_confidence(hunt_results: dict) -> int:
    """Calculate an average confidence score from hunt findings (0-100)."""
    confidence_map = {"high": 90, "medium": 60, "low": 30}
    findings = hunt_results.get("threat_hunt", {}).get("findings", [])
    if not findings:
        return 0
    scores = [confidence_map.get(f.get("confidence", "low").lower(), 30) for f in findings]
    return round(sum(scores) / len(scores))


async def generate_report_task(submission_id: int, format: str, db: AsyncSession):
    """Background task to generate an enriched report with threat hunt, MITRE validation,
    investigation plan, and threat intelligence archival."""
    import logging
    from utils.report_generator import ReportGenerator
    from agents.report_writer import ReportWriterAgent
    from utils.mitre_validator import MITREATTACKValidator
    from agents.threat_hunter import ThreatHuntAgent
    from agents.investigation import InvestigationAgent
    from utils.threat_archive import ThreatIntelArchive

    logger = logging.getLogger(__name__)

    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        return

    try:
        # Get analysis results and IOCs
        from database import (
            AnalysisResult, IOC, Enrichment,
            MITRETechniqueValidation, InvestigationPlan,
            SeverityLevel, TLPMarking
        )

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

        # Prepare common data structures
        ioc_dicts = [{"type": i.type.value, "value": i.value, "context": i.context} for i in iocs]
        analysis_dicts = [r.results_json for r in analysis_results]

        # --- MITRE ATT&CK Validation ---
        mitre_validation = {}
        try:
            mitre_validator = MITREATTACKValidator()
            all_techniques = []
            for r in analysis_results:
                if isinstance(r.results_json, dict) and r.results_json.get("mitre_techniques"):
                    all_techniques.extend(r.results_json["mitre_techniques"])
            if all_techniques:
                mitre_validation = await mitre_validator.validate_techniques(all_techniques)
                # Store validations in DB
                for t in mitre_validation.get("validated", []):
                    db.add(MITRETechniqueValidation(
                        submission_id=submission_id,
                        technique_id=t.get("id", ""),
                        technique_name=t.get("official_name"),
                        tactic=t.get("official_tactic"),
                        is_validated=True,
                        confidence=t.get("confidence"),
                        evidence=t.get("evidence")
                    ))
                for t in mitre_validation.get("supposition", []) + mitre_validation.get("invalid", []):
                    db.add(MITRETechniqueValidation(
                        submission_id=submission_id,
                        technique_id=t.get("id", "unknown"),
                        technique_name=t.get("name"),
                        is_validated=False,
                        evidence=t.get("reason")
                    ))
        except Exception as e:
            logger.warning(f"MITRE validation failed: {e}")

        # --- Threat Hunt Analysis ---
        hunt_results = {}
        try:
            threat_hunter = ThreatHuntAgent()
            hunt_results = await threat_hunter.hunt(
                submission_type=submission.type.value,
                analysis_data=analysis_dicts,
                iocs=ioc_dicts,
                enrichment_data=enrichment_data
            )
        except Exception as e:
            logger.warning(f"Threat hunt failed: {e}")

        # --- Investigation Plan ---
        investigation_plan = {}
        try:
            investigator = InvestigationAgent()
            investigation_plan = await investigator.generate_investigation_plan(
                analysis_data=analysis_dicts,
                iocs=ioc_dicts,
                mitre_techniques=mitre_validation.get("validated", []),
                enrichment_data=enrichment_data
            )
            # Store in DB
            if investigation_plan.get("investigation_plan"):
                db.add(InvestigationPlan(
                    submission_id=submission_id,
                    plan_json=investigation_plan
                ))
        except Exception as e:
            logger.warning(f"Investigation plan generation failed: {e}")

        # --- Update Submission with Severity/Confidence ---
        if hunt_results:
            highest_severity = _determine_highest_severity(hunt_results)
            confidence = _calculate_confidence(hunt_results)
            try:
                submission.severity = SeverityLevel(highest_severity)
            except ValueError:
                pass
            submission.confidence_score = confidence
            if not submission.tlp_marking:
                try:
                    submission.tlp_marking = TLPMarking(settings.default_tlp_marking)
                except ValueError:
                    pass

        # --- Generate Narrative with Enhanced Data ---
        report_writer = ReportWriterAgent()
        full_report = await report_writer.generate_full_report(
            submission=submission,
            analysis_results=analysis_dicts,
            iocs=ioc_dicts,
            enrichment_data=enrichment_data,
            reasoning_analysis={},
            investigation_plan=investigation_plan,
            threat_hunt_results=hunt_results,
            mitre_validation=mitre_validation,
            severity=highest_severity if hunt_results else None,
            tlp=submission.tlp_marking.value if submission.tlp_marking and hasattr(submission.tlp_marking, 'value') else settings.default_tlp_marking,
        )

        narrative = full_report.get("full_report", "")

        # Build extra data for report generator
        extra_data = {
            "mitre_validation": mitre_validation,
            "investigation_plan": investigation_plan,
            "threat_hunt_findings": hunt_results.get("threat_hunt", {}),
        }

        # Generate formatted report
        generator = ReportGenerator()
        report_content = generator.generate(
            format=format,
            submission=submission,
            analysis_results=analysis_results,
            iocs=iocs,
            enrichment_data=enrichment_data,
            narrative=narrative,
            extra_data=extra_data
        )

        # Save report
        report = Report(
            submission_id=submission_id,
            format=format,
            content=report_content
        )
        db.add(report)

        # --- Archive Threat Intelligence ---
        try:
            archiver = ThreatIntelArchive()
            await archiver.archive_submission_results(
                submission_id=submission_id,
                submission_data={
                    "id": submission.id,
                    "type": submission.type.value,
                    "filename": submission.filename,
                },
                analysis_results=analysis_dicts,
                iocs=ioc_dicts,
                enrichment_data=enrichment_data,
                findings=hunt_results.get("threat_hunt", {}).get("findings", [])
            )
        except Exception as e:
            logger.warning(f"Threat intel archival failed: {e}")

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
