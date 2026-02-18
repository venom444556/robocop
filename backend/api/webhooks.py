"""Webhook endpoints for n8n integration."""

import secrets
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, field_validator

from config import get_settings
from database import get_db, Submission, SubmissionStatus, AnalysisResult, IOC, IOCType, Enrichment

router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)

# Valid IOC types for validation
VALID_IOC_TYPES = {t.value for t in IOCType}


class AnalysisCompleteWebhook(BaseModel):
    """Webhook payload when analysis is complete."""
    submission_id: int
    analyzer: str
    results: dict
    iocs: Optional[list[dict]] = None


class EnrichmentCompleteWebhook(BaseModel):
    """Webhook payload when enrichment is complete."""
    submission_id: int
    ioc_id: int
    source: str
    data: dict


class StatusUpdateWebhook(BaseModel):
    """Webhook payload for status updates."""
    submission_id: int
    status: str
    error_message: Optional[str] = None


def verify_api_key(x_api_key: str = Header(None)):
    """Verify the API key for webhook authentication using timing-safe comparison."""
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="API key required")
    # Use timing-safe comparison to prevent timing attacks
    if not secrets.compare_digest(x_api_key, settings.api_key):
        logger.warning("Invalid API key attempt")
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


@router.post("/analysis-complete")
async def analysis_complete(
    payload: AnalysisCompleteWebhook,
    db: AsyncSession = Depends(get_db),
    _: bool = Depends(verify_api_key)
):
    """
    Webhook called by n8n when an analysis step completes.
    Stores the analysis results and any extracted IOCs.
    """
    result = await db.execute(
        select(Submission).filter(Submission.id == payload.submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Store analysis result
    analysis_result = AnalysisResult(
        submission_id=payload.submission_id,
        analyzer=payload.analyzer,
        results_json=payload.results
    )
    db.add(analysis_result)

    # Store IOCs if provided
    if payload.iocs:
        for ioc_data in payload.iocs:
            ioc_type = ioc_data.get("type")
            ioc_value = ioc_data.get("value")

            # Validate IOC type
            if ioc_type not in VALID_IOC_TYPES:
                logger.warning(f"Invalid IOC type: {ioc_type}, skipping")
                continue

            if not ioc_value:
                continue

            ioc = IOC(
                submission_id=payload.submission_id,
                type=IOCType(ioc_type),
                value=ioc_value,
                context=ioc_data.get("context")
            )
            db.add(ioc)

    await db.commit()
    return {"status": "success", "message": "Analysis results stored"}


@router.post("/enrichment-complete")
async def enrichment_complete(
    payload: EnrichmentCompleteWebhook,
    db: AsyncSession = Depends(get_db),
    _: bool = Depends(verify_api_key)
):
    """
    Webhook called by n8n when enrichment data is retrieved.
    Stores the enrichment data linked to the IOC.
    """
    # Verify IOC exists
    result = await db.execute(
        select(IOC).filter(IOC.id == payload.ioc_id)
    )
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Store enrichment data
    enrichment = Enrichment(
        ioc_id=payload.ioc_id,
        source=payload.source,
        data_json=payload.data
    )
    db.add(enrichment)
    await db.commit()

    return {"status": "success", "message": "Enrichment data stored"}


@router.post("/status-update")
async def status_update(
    payload: StatusUpdateWebhook,
    db: AsyncSession = Depends(get_db),
    _: bool = Depends(verify_api_key)
):
    """
    Webhook called by n8n to update submission status.
    """
    result = await db.execute(
        select(Submission).filter(Submission.id == payload.submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    try:
        submission.status = SubmissionStatus(payload.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {payload.status}")

    if payload.error_message:
        submission.error_message = payload.error_message

    if payload.status == "complete":
        submission.completed_at = datetime.utcnow()

    await db.commit()
    return {"status": "success", "message": "Status updated"}


class NVDEnrichmentWebhook(BaseModel):
    """Webhook payload for NVD/CVE enrichment results."""
    submission_id: int
    cve_data: list[dict]
    keywords_searched: list[str] = []


@router.post("/nvd-enrichment-complete")
async def nvd_enrichment_complete(
    payload: NVDEnrichmentWebhook,
    db: AsyncSession = Depends(get_db),
    _: bool = Depends(verify_api_key)
):
    """Store NVD/CVE enrichment results."""
    result = await db.execute(
        select(Submission).filter(Submission.id == payload.submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Store as AnalysisResult
    analysis_result = AnalysisResult(
        submission_id=payload.submission_id,
        analyzer="nvd_enrichment",
        results_json={
            "cve_data": payload.cve_data,
            "keywords_searched": payload.keywords_searched,
            "total_cves": len(payload.cve_data),
            "source": "nvd"
        }
    )
    db.add(analysis_result)
    await db.commit()

    return {"status": "success", "message": f"NVD enrichment stored: {len(payload.cve_data)} CVEs"}


@router.get("/submission/{submission_id}/data")
async def get_submission_data(
    submission_id: int,
    db: AsyncSession = Depends(get_db),
    _: bool = Depends(verify_api_key)
):
    """
    Get all data for a submission (used by n8n workflows).
    Returns submission details, analysis results, IOCs, and enrichment data.
    """
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

    # Get IOCs with enrichment
    iocs = await db.execute(
        select(IOC).filter(IOC.submission_id == submission_id)
    )
    ioc_list = iocs.scalars().all()

    iocs_with_enrichment = []
    for ioc in ioc_list:
        enrichments = await db.execute(
            select(Enrichment).filter(Enrichment.ioc_id == ioc.id)
        )
        enrichment_list = enrichments.scalars().all()
        iocs_with_enrichment.append({
            "id": ioc.id,
            "type": ioc.type.value,
            "value": ioc.value,
            "context": ioc.context,
            "enrichment": [
                {"source": e.source, "data": e.data_json}
                for e in enrichment_list
            ]
        })

    return {
        "submission": {
            "id": submission.id,
            "type": submission.type.value,
            "filename": submission.filename,
            "original_url": submission.original_url,
            "file_hash_sha256": submission.file_hash_sha256,
            "status": submission.status.value,
            "created_at": submission.created_at.isoformat(),
            "completed_at": submission.completed_at.isoformat() if submission.completed_at else None
        },
        "analysis_results": [
            {"analyzer": r.analyzer, "results": r.results_json}
            for r in analysis_results
        ],
        "iocs": iocs_with_enrichment
    }
