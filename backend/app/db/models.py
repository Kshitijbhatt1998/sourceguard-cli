import uuid
from datetime import datetime
from typing import List, Optional
from enum import Enum
from sqlmodel import SQLModel, Field, Relationship

class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    password_hash: str # Required for production auth
    name: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    memberships: List["Membership"] = Relationship(back_populates="user")
    api_keys: List["APIKey"] = Relationship(back_populates="user")

class Organization(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    memberships: List["Membership"] = Relationship(back_populates="organization")
    projects: List["Project"] = Relationship(back_populates="organization")

class Membership(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id")
    organization_id: uuid.UUID = Field(foreign_key="organization.id")
    role: Role = Field(default=Role.MEMBER)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    user: User = Relationship(back_populates="memberships")
    organization: Organization = Relationship(back_populates="memberships")

class Project(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    organization_id: uuid.UUID = Field(foreign_key="organization.id", index=True)
    name: str
    repo_url: Optional[str] = None
    is_private: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    organization: Organization = Relationship(back_populates="projects")
    scans: List["Scan"] = Relationship(back_populates="project")
    findings: List["Finding"] = Relationship(back_populates="project")
    risk_snapshots: List["ProjectRiskSnapshot"] = Relationship(back_populates="project")
    ignore_rules: List["IgnoreRule"] = Relationship(back_populates="project")

class Scan(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id", index=True)
    triggered_by: Optional[uuid.UUID] = Field(foreign_key="user.id", default=None)
    source: str = Field(default="cli") 
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    total_files: int = Field(default=0)
    total_findings: int = Field(default=0)
    risk_score: int = Field(default=0)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    project: Project = Relationship(back_populates="scans")
    findings: List["Finding"] = Relationship(back_populates="scan")

class Finding(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_id: uuid.UUID = Field(foreign_key="scan.id", index=True)
    project_id: uuid.UUID = Field(foreign_key="project.id", index=True)

    type: str 
    severity: str 

    file_path: str
    line_number: int

    match_masked: str
    hash: str = Field(index=True)

    message: str
    suggestion: str
    entropy: Optional[float] = None

    is_resolved: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    scan: Scan = Relationship(back_populates="findings")
    project: Project = Relationship(back_populates="findings")

class ProjectRiskSnapshot(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id", index=True)

    total_findings: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)

    risk_score: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    project: Project = Relationship(back_populates="risk_snapshots")

class APIKey(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id")
    key_hash: str = Field(unique=True, index=True)
    label: str = Field(default="Default Key")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    user: User = Relationship(back_populates="api_keys")

class IgnoreRule(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")
    pattern: str
    type: str = Field(default="path") 
    created_at: datetime = Field(default_factory=datetime.utcnow)

    project: Project = Relationship(back_populates="ignore_rules")

class Alert(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(foreign_key="project.id")
    scan_id: uuid.UUID = Field(foreign_key="scan.id")
    type: str 
    message: str
    is_sent: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
