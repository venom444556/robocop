"""Analysis endpoints for triggering and retrieving analysis results."""

import os
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from config import get_settings
from database import (
    get_db, async_session, Submission, SubmissionStatus, AnalysisResult,
    IOC, IOCType, SubmissionType
)

router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)


class AnalysisResultResponse(BaseModel):
    """Response model for analysis results."""
    id: int
    submission_id: int
    analyzer: str
    results_json: dict
    created_at: datetime

    class Config:
        from_attributes = True


class IOCResponse(BaseModel):
    """Response model for IOCs."""
    id: int
    type: str
    value: str
    context: Optional[str]

    class Config:
        from_attributes = True


class FullAnalysisResponse(BaseModel):
    """Complete analysis response including IOCs and results."""
    submission_id: int
    status: str
    analysis_results: list[AnalysisResultResponse]
    iocs: list[IOCResponse]


async def run_analysis(submission_id: int):
    """
    Run the full analysis pipeline for a submission.
    This is typically triggered by n8n but can also be called directly.

    Note: This function creates its own database session since it runs
    in a background task after the request has completed.
    """
    from analyzers.ioc_extractor import IOCExtractor
    from analyzers.script_analyzer import ScriptAnalyzer
    from analyzers.script_decoder import ScriptDecoder
    from analyzers.url_analyzer import URLAnalyzer
    from analyzers.sandbox_parser import SandboxParser

    # Create a new session for background task
    async with async_session() as db:
        result = await db.execute(
            select(Submission).filter(Submission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        if not submission:
            logger.warning(f"Submission {submission_id} not found for analysis")
            return

        # Update status
        submission.status = SubmissionStatus.ANALYZING
        await db.commit()

        try:
            if submission.type == SubmissionType.FILE:
                file_path = os.path.join(
                    settings.upload_dir,
                    f"{submission.file_hash_sha256}_{submission.filename}"
                )
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Decode any encoded content first
                decoder = ScriptDecoder()
                decoded_result = decoder.decode(content, submission.filename)
                if decoded_result["decoded"]:
                    analysis_result = AnalysisResult(
                        submission_id=submission_id,
                        analyzer="script_decoder",
                        results_json=decoded_result
                    )
                    db.add(analysis_result)
                    content = decoded_result["decoded_content"]

                # Run script analysis
                analyzer = ScriptAnalyzer()
                script_result = analyzer.analyze(content, submission.filename)
                analysis_result = AnalysisResult(
                    submission_id=submission_id,
                    analyzer="script_analyzer",
                    results_json=script_result
                )
                db.add(analysis_result)

                # Extract IOCs
                ioc_extractor = IOCExtractor()
                iocs = ioc_extractor.extract(content)
                for ioc_type, values in iocs.items():
                    for value in values:
                        ioc = IOC(
                            submission_id=submission_id,
                            type=IOCType(ioc_type),
                            value=value,
                            context="Extracted from script content"
                        )
                        db.add(ioc)

            elif submission.type == SubmissionType.URL:
                url_analyzer = URLAnalyzer()
                url_result = await url_analyzer.analyze(submission.original_url)
                analysis_result = AnalysisResult(
                    submission_id=submission_id,
                    analyzer="url_analyzer",
                    results_json=url_result
                )
                db.add(analysis_result)

                # If URL points to a script, analyze it
                if url_result.get("fetched_script"):
                    decoder = ScriptDecoder()
                    decoded_result = decoder.decode(
                        url_result["fetched_script"],
                        url_result.get("content_filename", "script.txt")
                    )
                    if decoded_result["decoded"]:
                        content = decoded_result["decoded_content"]
                        db.add(AnalysisResult(
                            submission_id=submission_id,
                            analyzer="script_decoder",
                            results_json=decoded_result
                        ))
                    else:
                        content = url_result["fetched_script"]

                    analyzer = ScriptAnalyzer()
                    script_result = analyzer.analyze(
                        content,
                        url_result.get("content_filename", "script.txt")
                    )
                    db.add(AnalysisResult(
                        submission_id=submission_id,
                        analyzer="script_analyzer",
                        results_json=script_result
                    ))

                    ioc_extractor = IOCExtractor()
                    iocs = ioc_extractor.extract(content)
                    for ioc_type, values in iocs.items():
                        for value in values:
                            db.add(IOC(
                                submission_id=submission_id,
                                type=IOCType(ioc_type),
                                value=value,
                                context="Extracted from fetched script"
                            ))

                # Extract IOCs from URL analysis
                ioc_extractor = IOCExtractor()
                url_iocs = ioc_extractor.extract(submission.original_url)
                for ioc_type, values in url_iocs.items():
                    for value in values:
                        db.add(IOC(
                            submission_id=submission_id,
                            type=IOCType(ioc_type),
                            value=value,
                            context="Extracted from submitted URL"
                        ))

            elif submission.type == SubmissionType.SANDBOX_REPORT:
                file_path = os.path.join(settings.upload_dir, submission.filename)
                parser = SandboxParser()
                sandbox_result = parser.parse(file_path)
                analysis_result = AnalysisResult(
                    submission_id=submission_id,
                    analyzer="sandbox_parser",
                    results_json=sandbox_result
                )
                db.add(analysis_result)

                # Extract IOCs from sandbox report
                for ioc_data in sandbox_result.get("iocs", []):
                    db.add(IOC(
                        submission_id=submission_id,
                        type=IOCType(ioc_data["type"]),
                        value=ioc_data["value"],
                        context=ioc_data.get("context", "Extracted from sandbox report")
                    ))

            submission.status = SubmissionStatus.ENRICHING
            await db.commit()

        except Exception as e:
            submission.status = SubmissionStatus.FAILED
            submission.error_message = str(e)
            await db.commit()
            logger.error(f"Analysis failed for submission {submission_id}: {e}")
            raise


@router.post("/{submission_id}/trigger")
async def trigger_analysis(
    submission_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Manually trigger analysis for a submission."""
    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.status not in [SubmissionStatus.PENDING, SubmissionStatus.FAILED]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot trigger analysis for submission in status: {submission.status}"
        )

    background_tasks.add_task(run_analysis, submission_id)
    return {"message": "Analysis triggered", "submission_id": submission_id}


@router.get("/{submission_id}/results", response_model=FullAnalysisResponse)
async def get_analysis_results(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get all analysis results for a submission."""
    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Get analysis results
    results = await db.execute(
        select(AnalysisResult).filter(AnalysisResult.submission_id == submission_id)
    )
    analysis_results = results.scalars().all()

    # Get IOCs
    ioc_results = await db.execute(
        select(IOC).filter(IOC.submission_id == submission_id)
    )
    iocs = ioc_results.scalars().all()

    return FullAnalysisResponse(
        submission_id=submission_id,
        status=submission.status.value,
        analysis_results=[
            AnalysisResultResponse(
                id=r.id,
                submission_id=r.submission_id,
                analyzer=r.analyzer,
                results_json=r.results_json,
                created_at=r.created_at
            )
            for r in analysis_results
        ],
        iocs=[
            IOCResponse(
                id=i.id,
                type=i.type.value,
                value=i.value,
                context=i.context
            )
            for i in iocs
        ]
    )


@router.get("/{submission_id}/status")
async def get_analysis_status(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get the current analysis status for a submission."""
    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    return {
        "submission_id": submission_id,
        "status": submission.status.value,
        "error_message": submission.error_message,
        "created_at": submission.created_at,
        "completed_at": submission.completed_at
    }
