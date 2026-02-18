"""IOC cross-correlation search and submission comparison APIs."""

import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy import select, func, distinct, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from database import (
    get_db, Submission, SubmissionStatus, AnalysisResult,
    IOC, IOCType, Enrichment, MITRETechniqueValidation
)

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class IOCSearchItem(BaseModel):
    id: int
    type: str
    value: str
    context: Optional[str]
    submission_id: int
    submission_type: str
    submission_filename: Optional[str]
    first_seen: datetime
    enrichment_count: int

    class Config:
        from_attributes = True


class IOCSearchResponse(BaseModel):
    total_count: int
    results: list[IOCSearchItem]


class CorrelatedSubmission(BaseModel):
    id: int
    type: str
    filename: Optional[str]
    status: str
    severity: Optional[str]
    created_at: datetime


class RelatedIOC(BaseModel):
    value: str
    type: str
    co_occurrence_count: int


class IOCCorrelationResponse(BaseModel):
    ioc_value: str
    ioc_type: Optional[str]
    total_appearances: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    submissions: list[CorrelatedSubmission]
    related_iocs: list[RelatedIOC]


class IOCBrief(BaseModel):
    type: str
    value: str


class TechniqueBrief(BaseModel):
    technique_id: str
    name: Optional[str]


class EnrichmentMatch(BaseModel):
    source: str
    matching_field: str
    value: str


class SubmissionSummary(BaseModel):
    id: int
    type: str
    filename: Optional[str]
    original_url: Optional[str]
    file_hash_sha256: Optional[str]
    status: str
    severity: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]


class CompareResponse(BaseModel):
    submission1: SubmissionSummary
    submission2: SubmissionSummary
    shared_iocs: list[IOCBrief]
    unique_to_1: list[IOCBrief]
    unique_to_2: list[IOCBrief]
    shared_techniques: list[TechniqueBrief]
    similarity_score: float
    shared_enrichment: list[EnrichmentMatch]


class GlobalSubmissionMatch(BaseModel):
    id: int
    type: str
    filename: Optional[str]
    url: Optional[str]
    hash: Optional[str]
    status: str
    severity: Optional[str]
    match_field: str


class GlobalIOCMatch(BaseModel):
    id: int
    value: str
    type: str
    submission_id: int
    context: Optional[str]


class GlobalSearchResponse(BaseModel):
    submissions: list[GlobalSubmissionMatch]
    iocs: list[GlobalIOCMatch]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _submission_summary(s: Submission) -> SubmissionSummary:
    return SubmissionSummary(
        id=s.id,
        type=s.type.value if hasattr(s.type, "value") else str(s.type),
        filename=s.filename,
        original_url=s.original_url,
        file_hash_sha256=s.file_hash_sha256,
        status=s.status.value if hasattr(s.status, "value") else str(s.status),
        severity=s.severity.value if s.severity and hasattr(s.severity, "value") else (str(s.severity) if s.severity else None),
        created_at=s.created_at,
        completed_at=s.completed_at,
    )


# ---------------------------------------------------------------------------
# 1. GET /iocs  -  Search IOCs by value across all submissions
# ---------------------------------------------------------------------------

@router.get("/iocs", response_model=IOCSearchResponse)
async def search_iocs(
    q: str = Query(..., min_length=1, description="Search query for IOC value"),
    type: Optional[str] = Query(None, description="Filter by IOC type"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    Search IOCs by value (LIKE match) across all submissions.
    Optionally filter by IOC type.  Returns paginated results with total count.
    """
    like_pattern = f"%{q}%"

    # Base filter conditions
    conditions = [IOC.value.ilike(like_pattern)]
    if type is not None:
        try:
            ioc_type_enum = IOCType(type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid IOC type. Must be one of: {[t.value for t in IOCType]}",
            )
        conditions.append(IOC.type == ioc_type_enum)

    # Total count ----------------------------------------------------------
    count_stmt = select(func.count(IOC.id)).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Items ----------------------------------------------------------------
    # Join with Submission for context, sub-query for enrichment count
    enrichment_count_sub = (
        select(func.count(Enrichment.id))
        .where(Enrichment.ioc_id == IOC.id)
        .correlate(IOC)
        .scalar_subquery()
        .label("enrichment_count")
    )

    stmt = (
        select(
            IOC.id,
            IOC.type,
            IOC.value,
            IOC.context,
            IOC.submission_id,
            IOC.created_at.label("first_seen"),
            Submission.type.label("submission_type"),
            Submission.filename.label("submission_filename"),
            enrichment_count_sub,
        )
        .join(Submission, Submission.id == IOC.submission_id)
        .where(and_(*conditions))
        .order_by(IOC.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    rows = await db.execute(stmt)
    items = []
    for row in rows:
        sub_type_val = row.submission_type
        if hasattr(sub_type_val, "value"):
            sub_type_val = sub_type_val.value
        ioc_type_val = row.type
        if hasattr(ioc_type_val, "value"):
            ioc_type_val = ioc_type_val.value

        items.append(
            IOCSearchItem(
                id=row.id,
                type=ioc_type_val,
                value=row.value,
                context=row.context,
                submission_id=row.submission_id,
                submission_type=str(sub_type_val),
                submission_filename=row.submission_filename,
                first_seen=row.first_seen,
                enrichment_count=row.enrichment_count or 0,
            )
        )

    return IOCSearchResponse(total_count=total_count, results=items)


# ---------------------------------------------------------------------------
# 2. GET /iocs/{ioc_value}/correlate  -  Cross-correlation for a given IOC
# ---------------------------------------------------------------------------

@router.get("/iocs/{ioc_value}/correlate", response_model=IOCCorrelationResponse)
async def correlate_ioc(
    ioc_value: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Find all submissions containing the given IOC value.
    Also returns related IOCs that co-occur in the same submissions, ranked by
    co-occurrence count (top 20).
    """
    # Fetch all IOC rows matching exact value
    ioc_stmt = select(IOC).where(IOC.value == ioc_value)
    ioc_result = await db.execute(ioc_stmt)
    ioc_rows = ioc_result.scalars().all()

    if not ioc_rows:
        raise HTTPException(status_code=404, detail="IOC value not found")

    # Determine canonical type (take the first occurrence)
    ioc_type_val = ioc_rows[0].type
    if hasattr(ioc_type_val, "value"):
        ioc_type_val = ioc_type_val.value

    # Aggregate statistics
    total_appearances = len(ioc_rows)
    dates = [r.created_at for r in ioc_rows if r.created_at]
    first_seen = min(dates) if dates else None
    last_seen = max(dates) if dates else None

    # Collect unique submission IDs
    submission_ids = list({r.submission_id for r in ioc_rows})

    # Fetch associated submissions
    sub_stmt = (
        select(Submission)
        .where(Submission.id.in_(submission_ids))
        .order_by(Submission.created_at.desc())
    )
    sub_result = await db.execute(sub_stmt)
    submissions_list = sub_result.scalars().all()

    correlated_submissions = []
    for s in submissions_list:
        correlated_submissions.append(
            CorrelatedSubmission(
                id=s.id,
                type=s.type.value if hasattr(s.type, "value") else str(s.type),
                filename=s.filename,
                status=s.status.value if hasattr(s.status, "value") else str(s.status),
                severity=s.severity.value if s.severity and hasattr(s.severity, "value") else (str(s.severity) if s.severity else None),
                created_at=s.created_at,
            )
        )

    # Related IOCs: other IOCs that appear in the same submissions, ranked by
    # how many of *these* submissions they appear in (co-occurrence count).
    related_stmt = (
        select(
            IOC.value,
            IOC.type,
            func.count(distinct(IOC.submission_id)).label("co_occurrence_count"),
        )
        .where(
            and_(
                IOC.submission_id.in_(submission_ids),
                IOC.value != ioc_value,
            )
        )
        .group_by(IOC.value, IOC.type)
        .order_by(func.count(distinct(IOC.submission_id)).desc())
        .limit(20)
    )
    related_result = await db.execute(related_stmt)
    related_iocs = []
    for row in related_result:
        rel_type = row.type
        if hasattr(rel_type, "value"):
            rel_type = rel_type.value
        related_iocs.append(
            RelatedIOC(
                value=row.value,
                type=str(rel_type),
                co_occurrence_count=row.co_occurrence_count,
            )
        )

    return IOCCorrelationResponse(
        ioc_value=ioc_value,
        ioc_type=str(ioc_type_val),
        total_appearances=total_appearances,
        first_seen=first_seen,
        last_seen=last_seen,
        submissions=correlated_submissions,
        related_iocs=related_iocs,
    )


# ---------------------------------------------------------------------------
# 3. GET /submissions/compare  -  Side-by-side submission comparison
# ---------------------------------------------------------------------------

@router.get("/submissions/compare", response_model=CompareResponse)
async def compare_submissions(
    id1: int = Query(..., description="First submission ID"),
    id2: int = Query(..., description="Second submission ID"),
    db: AsyncSession = Depends(get_db),
):
    """
    Compare two submissions side by side.  Returns shared/unique IOCs, shared
    MITRE techniques, Jaccard similarity on IOC sets, and shared enrichment
    sources.
    """
    # Fetch both submissions
    result1 = await db.execute(select(Submission).where(Submission.id == id1))
    sub1 = result1.scalar_one_or_none()
    if not sub1:
        raise HTTPException(status_code=404, detail=f"Submission {id1} not found")

    result2 = await db.execute(select(Submission).where(Submission.id == id2))
    sub2 = result2.scalar_one_or_none()
    if not sub2:
        raise HTTPException(status_code=404, detail=f"Submission {id2} not found")

    # Fetch IOCs for each submission
    iocs1_result = await db.execute(select(IOC).where(IOC.submission_id == id1))
    iocs1_rows = iocs1_result.scalars().all()

    iocs2_result = await db.execute(select(IOC).where(IOC.submission_id == id2))
    iocs2_rows = iocs2_result.scalars().all()

    # Build sets keyed by (type_value, value)
    def _ioc_key(ioc):
        t = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        return (t, ioc.value)

    set1 = {_ioc_key(i) for i in iocs1_rows}
    set2 = {_ioc_key(i) for i in iocs2_rows}

    shared = set1 & set2
    only1 = set1 - set2
    only2 = set2 - set1

    shared_iocs = [IOCBrief(type=t, value=v) for t, v in sorted(shared)]
    unique_to_1 = [IOCBrief(type=t, value=v) for t, v in sorted(only1)]
    unique_to_2 = [IOCBrief(type=t, value=v) for t, v in sorted(only2)]

    # Jaccard similarity
    union_size = len(set1 | set2)
    similarity_score = round(len(shared) / union_size, 4) if union_size > 0 else 0.0

    # MITRE technique comparison
    tech1_result = await db.execute(
        select(MITRETechniqueValidation).where(
            MITRETechniqueValidation.submission_id == id1
        )
    )
    tech1_rows = tech1_result.scalars().all()

    tech2_result = await db.execute(
        select(MITRETechniqueValidation).where(
            MITRETechniqueValidation.submission_id == id2
        )
    )
    tech2_rows = tech2_result.scalars().all()

    tech_set1 = {(t.technique_id, t.technique_name) for t in tech1_rows}
    tech_set2 = {(t.technique_id, t.technique_name) for t in tech2_rows}
    shared_tech = tech_set1 & tech_set2

    shared_techniques = [
        TechniqueBrief(technique_id=tid, name=tname)
        for tid, tname in sorted(shared_tech)
    ]

    # Shared enrichment: enrichment sources that appear for IOCs in both
    # submissions where the source name matches.
    ioc_ids_1 = [i.id for i in iocs1_rows]
    ioc_ids_2 = [i.id for i in iocs2_rows]

    shared_enrichment: list[EnrichmentMatch] = []
    if ioc_ids_1 and ioc_ids_2:
        enrich1_result = await db.execute(
            select(Enrichment).where(Enrichment.ioc_id.in_(ioc_ids_1))
        )
        enrich1_rows = enrich1_result.scalars().all()

        enrich2_result = await db.execute(
            select(Enrichment).where(Enrichment.ioc_id.in_(ioc_ids_2))
        )
        enrich2_rows = enrich2_result.scalars().all()

        # Index enrichment by source for comparison
        sources1 = {e.source for e in enrich1_rows}
        sources2 = {e.source for e in enrich2_rows}
        common_sources = sources1 & sources2

        for source in sorted(common_sources):
            shared_enrichment.append(
                EnrichmentMatch(
                    source=source,
                    matching_field="source",
                    value=source,
                )
            )

    return CompareResponse(
        submission1=_submission_summary(sub1),
        submission2=_submission_summary(sub2),
        shared_iocs=shared_iocs,
        unique_to_1=unique_to_1,
        unique_to_2=unique_to_2,
        shared_techniques=shared_techniques,
        similarity_score=similarity_score,
        shared_enrichment=shared_enrichment,
    )


# ---------------------------------------------------------------------------
# 4. GET /global-search  -  Search across submissions and IOCs
# ---------------------------------------------------------------------------

@router.get("/global-search", response_model=GlobalSearchResponse)
async def global_search(
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Search across submissions (filename, url, hash) and IOCs (value).
    Returns matching submissions with the field that matched and matching IOCs.
    """
    like_pattern = f"%{q}%"

    # --- Submissions ------------------------------------------------------
    # We search across filename, original_url, and file_hash_sha256.
    # For each hit we want to indicate *which* field matched.
    sub_stmt = (
        select(Submission)
        .where(
            or_(
                Submission.filename.ilike(like_pattern),
                Submission.original_url.ilike(like_pattern),
                Submission.file_hash_sha256.ilike(like_pattern),
            )
        )
        .order_by(Submission.created_at.desc())
        .limit(limit)
    )
    sub_result = await db.execute(sub_stmt)
    sub_rows = sub_result.scalars().all()

    submission_matches: list[GlobalSubmissionMatch] = []
    for s in sub_rows:
        # Determine which field matched
        match_field = "filename"
        if s.filename and q.lower() in s.filename.lower():
            match_field = "filename"
        elif s.original_url and q.lower() in s.original_url.lower():
            match_field = "url"
        elif s.file_hash_sha256 and q.lower() in s.file_hash_sha256.lower():
            match_field = "hash"

        submission_matches.append(
            GlobalSubmissionMatch(
                id=s.id,
                type=s.type.value if hasattr(s.type, "value") else str(s.type),
                filename=s.filename,
                url=s.original_url,
                hash=s.file_hash_sha256,
                status=s.status.value if hasattr(s.status, "value") else str(s.status),
                severity=s.severity.value if s.severity and hasattr(s.severity, "value") else (str(s.severity) if s.severity else None),
                match_field=match_field,
            )
        )

    # --- IOCs -------------------------------------------------------------
    ioc_stmt = (
        select(IOC)
        .where(IOC.value.ilike(like_pattern))
        .order_by(IOC.created_at.desc())
        .limit(limit)
    )
    ioc_result = await db.execute(ioc_stmt)
    ioc_rows = ioc_result.scalars().all()

    ioc_matches: list[GlobalIOCMatch] = []
    for i in ioc_rows:
        ioc_matches.append(
            GlobalIOCMatch(
                id=i.id,
                value=i.value,
                type=i.type.value if hasattr(i.type, "value") else str(i.type),
                submission_id=i.submission_id,
                context=i.context,
            )
        )

    return GlobalSearchResponse(
        submissions=submission_matches,
        iocs=ioc_matches,
    )
