import uuid
from datetime import datetime

from pydantic import BaseModel

from models.alert import NotificationChannel, SeverityThreshold


class PageResponse[T](BaseModel):
    items: list[T]
    total: int
    page: int
    per_page: int
    total_pages: int
    has_more: bool


# Projects


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None


class ProjectResponse(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    repo_url: str | None
    platform: str | None
    created_at: datetime
    updated_at: datetime | None

    model_config = {"from_attributes": True}


class ProjectSBOMHistoryItem(BaseModel):
    id: uuid.UUID
    version: str | None
    format: str | None
    dependency_count: int | None
    created_at: datetime | None

    model_config = {"from_attributes": True}


# Alerts


class AlertConfigCreate(BaseModel):
    project_id: str
    severity_threshold: SeverityThreshold = SeverityThreshold.HIGH
    notification_type: NotificationChannel = NotificationChannel.EMAIL
    config: dict = {}
    enabled: bool = True


class AlertConfigUpdate(BaseModel):
    project_id: str | None = None
    severity_threshold: SeverityThreshold | None = None
    notification_type: NotificationChannel | None = None
    enabled: bool | None = None


class AlertConfigResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    severity_threshold: SeverityThreshold
    notification_type: NotificationChannel
    enabled: bool
    created_at: datetime | None

    model_config = {"from_attributes": True}


class ActionResponse(BaseModel):
    status: str


# SBOMs


class SBOMUploadResponse(BaseModel):
    id: uuid.UUID
    format: str | None
    dependency_count: int | None
    sha256: str


class DependencyResponse(BaseModel):
    name: str
    version: str
    purl: str | None
    type: str | None
    license: str | None
    is_direct: bool


class VulnerabilityBriefResponse(BaseModel):
    id: uuid.UUID
    cve_id: str
    severity: str | None
    summary: str | None


class SBOMDetailResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    version: str | None
    format: str | None
    sha256: str
    dependency_count: int | None
    created_at: datetime | None
    dependencies: list[DependencyResponse]
    vulnerabilities: list[VulnerabilityBriefResponse]


class DiffItemResponse(BaseModel):
    name: str
    version: str


class VersionChangeResponse(BaseModel):
    name: str
    from_version: str
    to_version: str


class SBOMDiffResponse(BaseModel):
    added: list[DiffItemResponse]
    removed: list[DiffItemResponse]
    changed: list[VersionChangeResponse]


# Services


class ServiceResponse(BaseModel):
    id: uuid.UUID
    name: str
    project_id: uuid.UUID

    model_config = {"from_attributes": True}


# API keys


class ApiKeyCreate(BaseModel):
    label: str = ""


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    key_prefix: str
    label: str
    created_at: datetime | None
    last_used_at: datetime | None
    expires_at: datetime | None

    model_config = {"from_attributes": True}


class ApiKeyCreatedResponse(ApiKeyResponse):
    key: str


# Vulnerabilities


class VulnerabilityResponse(BaseModel):
    id: uuid.UUID
    cve_id: str
    severity: str | None
    cvss_score: float | None
    summary: str | None
    source: str | None
    published_at: datetime | None
    projects: list[str]
    services: list[str]


class VulnerabilitySummaryResponse(BaseModel):
    counts: dict[str, int]
    total: int
    affected_projects: int
