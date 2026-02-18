"""YARA rules library CRUD endpoints for threat detection rule management."""

import re
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, field_validator

from database import get_db, YaraRule

router = APIRouter()
logger = logging.getLogger(__name__)


# --- Pydantic Models ---

class YaraRuleCreate(BaseModel):
    """Request model for creating a YARA rule."""
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    rule_content: str
    author: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[list[str]] = None
    enabled: bool = True

    @field_validator('rule_content')
    @classmethod
    def validate_rule_content(cls, v):
        if 'rule' not in v:
            raise ValueError('rule_content must contain at least the "rule" keyword')
        return v

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('name must not be empty')
        return v.strip()


class YaraRuleUpdate(BaseModel):
    """Request model for updating a YARA rule (partial updates)."""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    rule_content: Optional[str] = None
    author: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[list[str]] = None
    enabled: Optional[bool] = None

    @field_validator('rule_content')
    @classmethod
    def validate_rule_content(cls, v):
        if v is not None and 'rule' not in v:
            raise ValueError('rule_content must contain at least the "rule" keyword')
        return v


class YaraRuleResponse(BaseModel):
    """Response model for a YARA rule."""
    id: int
    name: str
    description: Optional[str]
    category: Optional[str]
    rule_content: str
    author: Optional[str]
    source: Optional[str]
    tags: Optional[list[str]]
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class YaraRuleListResponse(BaseModel):
    """Response model for listing YARA rules."""
    total_count: int
    rules: list[YaraRuleResponse]


class BulkImportRequest(BaseModel):
    """Request model for bulk importing YARA rules."""
    content: str
    source: Optional[str] = "import"


class BulkImportResponse(BaseModel):
    """Response model for bulk import results."""
    imported: int
    errors: list[str]


# --- Helper Functions ---

def _rule_to_response(rule: YaraRule) -> YaraRuleResponse:
    """Convert a YaraRule ORM object to a response model."""
    return YaraRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        rule_content=rule.rule_content,
        author=rule.author,
        source=rule.source,
        tags=rule.tags,
        enabled=rule.enabled,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def _parse_yara_rules(content: str) -> list[dict]:
    """Parse multiple YARA rules from a text blob.

    Splits on 'rule ' keyword at the start of a line and extracts
    the rule name and full rule content for each parsed rule.
    """
    # Split on 'rule ' at the beginning of a line
    parts = re.split(r'^(?=rule\s)', content, flags=re.MULTILINE)
    rules = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Extract rule name from the first line: "rule rule_name {"
        match = re.match(r'rule\s+(\w+)', part)
        if match:
            rule_name = match.group(1)
            rules.append({
                "name": rule_name,
                "rule_content": part,
            })
    return rules


# --- Endpoints ---

@router.get("/export", response_class=PlainTextResponse)
async def export_rules(
    db: AsyncSession = Depends(get_db)
):
    """
    Export all enabled YARA rules as a single text file.

    Returns plain text containing all enabled rules concatenated together.
    """
    result = await db.execute(
        select(YaraRule)
        .filter(YaraRule.enabled == True)
        .order_by(YaraRule.name)
    )
    rules = result.scalars().all()

    if not rules:
        return PlainTextResponse(content="// No enabled YARA rules found.", status_code=200)

    exported_parts = []
    for rule in rules:
        exported_parts.append(rule.rule_content)

    exported_content = "\n\n".join(exported_parts)
    return PlainTextResponse(content=exported_content, status_code=200)


@router.post("/import", response_model=BulkImportResponse)
async def bulk_import_rules(
    request: BulkImportRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Bulk import YARA rules from a text blob.

    Parses multiple YARA rules from the provided content (splitting by 'rule '
    keyword at the start of a line) and creates individual database records
    for each parsed rule.
    """
    parsed_rules = _parse_yara_rules(request.content)

    if not parsed_rules:
        raise HTTPException(
            status_code=400,
            detail="No valid YARA rules found in the provided content."
        )

    imported_count = 0
    errors = []

    for parsed in parsed_rules:
        try:
            # Check if a rule with this name already exists
            existing = await db.execute(
                select(YaraRule).filter(YaraRule.name == parsed["name"])
            )
            if existing.scalar_one_or_none():
                errors.append(f"Rule '{parsed['name']}' already exists, skipped.")
                continue

            rule = YaraRule(
                name=parsed["name"],
                rule_content=parsed["rule_content"],
                source=request.source,
            )
            db.add(rule)
            imported_count += 1
        except Exception as e:
            errors.append(f"Failed to import rule '{parsed.get('name', 'unknown')}': {str(e)}")

    if imported_count > 0:
        await db.flush()

    logger.info(f"Bulk import: {imported_count} rules imported, {len(errors)} errors")

    return BulkImportResponse(imported=imported_count, errors=errors)


@router.get("/", response_model=YaraRuleListResponse)
async def list_rules(
    category: Optional[str] = None,
    enabled: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    List all YARA rules with optional filtering.

    Supports filtering by category, enabled status, and free-text search
    across name and description fields. Supports pagination via limit/offset.
    """
    query = select(YaraRule).order_by(YaraRule.created_at.desc())
    count_query = select(func.count(YaraRule.id))

    if category:
        query = query.filter(YaraRule.category == category)
        count_query = count_query.filter(YaraRule.category == category)
    if enabled is not None:
        query = query.filter(YaraRule.enabled == enabled)
        count_query = count_query.filter(YaraRule.enabled == enabled)
    if search:
        search_pattern = f"%{search}%"
        search_filter = or_(
            YaraRule.name.ilike(search_pattern),
            YaraRule.description.ilike(search_pattern),
        )
        query = query.filter(search_filter)
        count_query = count_query.filter(search_filter)

    # Get total count
    total_result = await db.execute(count_query)
    total_count = total_result.scalar()

    # Get paginated results
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    rules = result.scalars().all()

    return YaraRuleListResponse(
        total_count=total_count,
        rules=[_rule_to_response(r) for r in rules],
    )


@router.post("/", response_model=YaraRuleResponse, status_code=201)
async def create_rule(
    request: YaraRuleCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new YARA rule.

    The rule_content must contain at least the 'rule' keyword.
    Rule names must be unique.
    """
    # Check for duplicate name
    existing = await db.execute(
        select(YaraRule).filter(YaraRule.name == request.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A YARA rule with the name '{request.name}' already exists."
        )

    rule = YaraRule(
        name=request.name,
        description=request.description,
        category=request.category,
        rule_content=request.rule_content,
        author=request.author,
        source=request.source,
        tags=request.tags,
        enabled=request.enabled,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)

    logger.info(f"YARA rule created: {rule.name} (id={rule.id})")

    return _rule_to_response(rule)


@router.get("/{rule_id}", response_model=YaraRuleResponse)
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a single YARA rule by ID."""
    result = await db.execute(
        select(YaraRule).filter(YaraRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")

    return _rule_to_response(rule)


@router.put("/{rule_id}", response_model=YaraRuleResponse)
async def update_rule(
    rule_id: int,
    request: YaraRuleUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update a YARA rule.

    Accepts partial updates - only provided fields will be modified.
    """
    result = await db.execute(
        select(YaraRule).filter(YaraRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")

    # Apply partial updates
    update_data = request.model_dump(exclude_unset=True)

    # If name is being changed, check for duplicates
    if "name" in update_data and update_data["name"] != rule.name:
        existing = await db.execute(
            select(YaraRule).filter(YaraRule.name == update_data["name"])
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=409,
                detail=f"A YARA rule with the name '{update_data['name']}' already exists."
            )

    for field, value in update_data.items():
        setattr(rule, field, value)

    rule.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(rule)

    logger.info(f"YARA rule updated: {rule.name} (id={rule.id})")

    return _rule_to_response(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a YARA rule."""
    result = await db.execute(
        select(YaraRule).filter(YaraRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")

    await db.delete(rule)
    await db.flush()

    logger.info(f"YARA rule deleted: {rule.name} (id={rule_id})")

    return None
