"""Submission endpoints for file upload, URL submission, and sandbox report upload."""

import os
import hashlib
import logging
import re
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, HttpUrl, field_validator

from config import get_settings
from database import get_db, Submission, SubmissionType, SubmissionStatus

router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)

# Allowed file extensions for security
ALLOWED_EXTENSIONS = {
    '.ps1', '.psm1', '.psd1', '.js', '.mjs', '.vbs', '.vbe', '.wsf', '.wsh',
    '.bat', '.cmd', '.py', '.pyw', '.sh', '.bash', '.hta', '.php',
    '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm',
    '.pdf', '.rtf', '.exe', '.dll', '.scr', '.sys', '.msi', '.msp',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.lnk', '.iso', '.img',
    '.json', '.xml', '.html', '.htm', '.txt'
}

# Valid sandbox report sources
VALID_SANDBOX_SOURCES = {'anyrun', 'joesandbox', 'generic'}


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and other issues."""
    # Remove path components
    filename = os.path.basename(filename)
    # Replace potentially dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\x00', '..']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    # Remove any remaining path separators
    filename = re.sub(r'[/\\]', '_', filename)
    # Limit length
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200-len(ext)] + ext
    return filename


def is_allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_EXTENSIONS


class URLSubmissionRequest(BaseModel):
    """Request model for URL submission."""
    url: HttpUrl


class SandboxReportSubmission(BaseModel):
    """Request model for sandbox report submission."""
    report_source: str  # "anyrun", "joesandbox", "generic"
    report_data: dict

    @field_validator('report_source')
    @classmethod
    def validate_source(cls, v):
        if v not in VALID_SANDBOX_SOURCES:
            raise ValueError(f'Invalid report source. Must be one of: {VALID_SANDBOX_SOURCES}')
        return v


class SubmissionResponse(BaseModel):
    """Response model for submissions."""
    id: int
    type: str
    filename: Optional[str]
    original_url: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


def calculate_sha256(file_content: bytes) -> str:
    """Calculate SHA256 hash of file content."""
    return hashlib.sha256(file_content).hexdigest()


async def trigger_analysis_workflow(submission_id: int):
    """Trigger the n8n analysis workflow for a submission."""
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{settings.n8n_webhook_base_url}/analysis-trigger",
                json={"submission_id": submission_id},
                timeout=10.0
            )
    except Exception as e:
        logger.error("Failed to trigger n8n workflow", exc_info=True)


@router.post("/file", response_model=SubmissionResponse)
async def submit_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a file for malware analysis.

    Supported file types: scripts (PS1, JS, VBS, BAT, PY, SH), executables, documents.
    """
    # Validate filename
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    # Sanitize filename to prevent path traversal
    safe_filename = sanitize_filename(file.filename)

    # Validate file extension
    if not is_allowed_file(safe_filename):
        raise HTTPException(
            status_code=400,
            detail=f"File type not allowed. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # Validate file size
    content = await file.read()
    if len(content) > settings.max_file_size:
        raise HTTPException(status_code=413, detail="File too large")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file not allowed")

    # Calculate hash
    file_hash = calculate_sha256(content)

    # Save file to upload directory with sanitized filename
    file_path = os.path.join(settings.upload_dir, f"{file_hash}_{safe_filename}")
    with open(file_path, "wb") as f:
        f.write(content)

    logger.info(f"File uploaded: {safe_filename} (hash: {file_hash[:16]}...)")

    # Create submission record with sanitized filename
    submission = Submission(
        type=SubmissionType.FILE,
        filename=safe_filename,
        file_hash_sha256=file_hash,
        status=SubmissionStatus.PENDING
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    # Trigger analysis workflow in background
    background_tasks.add_task(trigger_analysis_workflow, submission.id)

    return SubmissionResponse(
        id=submission.id,
        type=submission.type.value,
        filename=submission.filename,
        original_url=None,
        status=submission.status.value,
        created_at=submission.created_at
    )


@router.post("/url", response_model=SubmissionResponse)
async def submit_url(
    request: URLSubmissionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a URL for analysis.

    The URL will be expanded (if shortened), categorized, and any scripts will be fetched and analyzed.
    """
    submission = Submission(
        type=SubmissionType.URL,
        original_url=str(request.url),
        status=SubmissionStatus.PENDING
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    # Trigger analysis workflow in background
    background_tasks.add_task(trigger_analysis_workflow, submission.id)

    return SubmissionResponse(
        id=submission.id,
        type=submission.type.value,
        filename=None,
        original_url=submission.original_url,
        status=submission.status.value,
        created_at=submission.created_at
    )


@router.post("/sandbox-report", response_model=SubmissionResponse)
async def submit_sandbox_report(
    request: SandboxReportSubmission,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a sandbox report for analysis.

    Supported formats: Any.Run JSON, Joe Sandbox JSON, generic JSON format.
    """
    # Save report data
    report_hash = calculate_sha256(str(request.report_data).encode())
    filename = f"sandbox_report_{request.report_source}_{report_hash[:16]}.json"

    file_path = os.path.join(settings.upload_dir, filename)
    import json
    with open(file_path, "w") as f:
        json.dump(request.report_data, f)

    submission = Submission(
        type=SubmissionType.SANDBOX_REPORT,
        filename=filename,
        file_hash_sha256=report_hash,
        status=SubmissionStatus.PENDING
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    # Trigger analysis workflow in background
    background_tasks.add_task(trigger_analysis_workflow, submission.id)

    return SubmissionResponse(
        id=submission.id,
        type=submission.type.value,
        filename=filename,
        original_url=None,
        status=submission.status.value,
        created_at=submission.created_at
    )


@router.get("/", response_model=list[SubmissionResponse])
async def list_submissions(
    status: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """List all submissions with optional filtering."""
    query = select(Submission).order_by(Submission.created_at.desc())

    if status:
        query = query.filter(Submission.status == status)
    if type:
        query = query.filter(Submission.type == type)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    submissions = result.scalars().all()

    return [
        SubmissionResponse(
            id=s.id,
            type=s.type.value,
            filename=s.filename,
            original_url=s.original_url,
            status=s.status.value,
            created_at=s.created_at
        )
        for s in submissions
    ]


@router.get("/{submission_id}", response_model=SubmissionResponse)
async def get_submission(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific submission by ID."""
    result = await db.execute(
        select(Submission).filter(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    return SubmissionResponse(
        id=submission.id,
        type=submission.type.value,
        filename=submission.filename,
        original_url=submission.original_url,
        status=submission.status.value,
        created_at=submission.created_at
    )
