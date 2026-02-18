"""Database setup and models for the malware analysis platform."""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey,
    JSON, Boolean, Enum as SQLEnum, create_engine
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import enum

from config import get_settings

Base = declarative_base()


class SubmissionType(str, enum.Enum):
    """Types of submissions supported."""
    FILE = "file"
    URL = "url"
    SANDBOX_REPORT = "sandbox_report"


class SubmissionStatus(str, enum.Enum):
    """Status of a submission through the analysis pipeline."""
    PENDING = "pending"
    ANALYZING = "analyzing"
    ENRICHING = "enriching"
    REASONING = "reasoning"
    COMPLETE = "complete"
    FAILED = "failed"


class SeverityLevel(str, enum.Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class TLPMarking(str, enum.Enum):
    """Traffic Light Protocol markings."""
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class ConfidenceLevel(str, enum.Enum):
    """Confidence levels for findings."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IOCType(str, enum.Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"


class Submission(Base):
    """Submissions table - tracks all analysis submissions."""
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(SQLEnum(SubmissionType), nullable=False)
    filename = Column(String(255), nullable=True)
    original_url = Column(Text, nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    status = Column(SQLEnum(SubmissionStatus), default=SubmissionStatus.PENDING)
    error_message = Column(Text, nullable=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=True)
    tlp_marking = Column(SQLEnum(TLPMarking), nullable=True)
    confidence_score = Column(Integer, nullable=True)  # 0-100
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    analysis_results = relationship("AnalysisResult", back_populates="submission")
    iocs = relationship("IOC", back_populates="submission")
    reports = relationship("Report", back_populates="submission")
    mitre_validations = relationship("MITRETechniqueValidation", back_populates="submission")
    investigation_plans = relationship("InvestigationPlan", back_populates="submission")


class AnalysisResult(Base):
    """Analysis results from various analyzers."""
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False)
    analyzer = Column(String(50), nullable=False)  # e.g., "script_analyzer", "ioc_extractor"
    results_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    submission = relationship("Submission", back_populates="analysis_results")


class IOC(Base):
    """Extracted Indicators of Compromise."""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False)
    type = Column(SQLEnum(IOCType), nullable=False)
    value = Column(Text, nullable=False)
    context = Column(Text, nullable=True)  # Where/how it was found
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    submission = relationship("Submission", back_populates="iocs")
    enrichment_data = relationship("Enrichment", back_populates="ioc")


class Enrichment(Base):
    """Enrichment data from external intelligence sources."""
    __tablename__ = "enrichment"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    source = Column(String(50), nullable=False)  # e.g., "virustotal", "shodan"
    data_json = Column(JSON, nullable=False)
    queried_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    ioc = relationship("IOC", back_populates="enrichment_data")


class Report(Base):
    """Generated analysis reports."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False)
    format = Column(String(10), nullable=False)  # "json", "html", "pdf"
    content = Column(Text, nullable=False)
    s3_key = Column(String(255), nullable=True)  # For large reports stored in S3
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    submission = relationship("Submission", back_populates="reports")


class MITRETechniqueValidation(Base):
    """Validated MITRE ATT&CK technique mappings."""
    __tablename__ = "mitre_validations"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False)
    technique_id = Column(String(20), nullable=False)  # e.g., "T1059.001"
    technique_name = Column(String(200), nullable=True)
    tactic = Column(String(100), nullable=True)
    is_validated = Column(Boolean, default=False)  # True = confirmed in official MITRE framework
    confidence = Column(String(20), nullable=True)  # "high", "medium", "low"
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    submission = relationship("Submission", back_populates="mitre_validations")


class InvestigationPlan(Base):
    """DFIR investigation plans generated for submissions."""
    __tablename__ = "investigation_plans"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False)
    plan_json = Column(JSON, nullable=False)  # Structured investigation plan
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    submission = relationship("Submission", back_populates="investigation_plans")


class ThreatIntelRecord(Base):
    """Archived threat intelligence records for historical correlation."""
    __tablename__ = "threat_intel_records"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=True)
    record_type = Column(String(50), nullable=False)  # "finding", "ioc", "technique"
    data_json = Column(JSON, nullable=False)
    severity = Column(SQLEnum(SeverityLevel), nullable=True)
    confidence = Column(SQLEnum(ConfidenceLevel), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class YaraRule(Base):
    """YARA rules library for threat detection."""
    __tablename__ = "yara_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True)  # e.g., "malware", "ransomware", "exploit"
    rule_content = Column(Text, nullable=False)
    author = Column(String(100), nullable=True)
    source = Column(String(200), nullable=True)  # e.g., "community", "custom", "import"
    tags = Column(JSON, nullable=True)  # ["apt", "ransomware", ...]
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Database engine and session setup
settings = get_settings()
engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Initialize the database and create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Dependency to get database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
