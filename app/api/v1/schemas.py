import uuid
from datetime import datetime

from pydantic import BaseModel, StrictBool, field_validator, model_validator

from models.alert import NotificationChannel, SeverityThreshold

# Shared response descriptions merged into each route's `responses=`. They make
# the OpenAPI schema document every status code the API actually produces, which
# keeps Schemathesis' status_code_conformance check green. FastAPI adds the 200/
# 201/422 entries automatically; these cover the hand-raised HTTPExceptions.
UNAUTHORIZED_RESPONSE = {401: {"description": "Missing or invalid API key"}}
BAD_REQUEST_RESPONSE = {400: {"description": "Malformed request body"}}
NOT_FOUND_RESPONSE = {404: {"description": "Resource not found"}}
CONFLICT_RESPONSE = {409: {"description": "Resource already exists"}}


def _strip_nul_from_strings(data):
    """Remove NUL bytes from every string value (and dict key) of a payload."""
    if isinstance(data, str):
        return data.replace("\x00", "")
    if isinstance(data, list):
        return [_strip_nul_from_strings(value) for value in data]
    if isinstance(data, dict):
        return {
            (key.replace("\x00", "") if isinstance(key, str) else key): _strip_nul_from_strings(
                value
            )
            for key, value in data.items()
        }
    return data


def _validate_name_has_alphanumeric(value: str | None) -> str | None:
    # Unicode-aware: the slugifier keeps non-ASCII letters (e.g. CJK), so accept
    # anything `str.isalnum()` considers alphanumeric. Raising here produces the
    # standard FastAPI 422 body (detail: array) instead of a hand-raised
    # HTTPException whose payload differs from the documented HTTPValidationError.
    if value is not None and not any(char.isalnum() for char in value):
        raise ValueError("Project name must contain at least one alphanumeric character")
    return value


class PageResponse[T](BaseModel):
    items: list[T]
    total: int
    page: int
    per_page: int
    total_pages: int
    has_more: bool


# Projects
# A project name must contain at least one alphanumeric character so the slug is
# never empty (see _validate_name_has_alphanumeric).


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None

    _name_has_alphanumeric = field_validator("name")(_validate_name_has_alphanumeric)

    @model_validator(mode="before")
    @classmethod
    def _strip_nul_bytes(cls, data):
        # PostgreSQL rejects NUL bytes in text/jsonb columns, so a fuzzed name
        # like "foo\x00bar" would otherwise surface as a 500. Strip them at the
        # request boundary; a name left without any alphanumeric afterwards is
        # rejected by _validate_name_has_alphanumeric.
        return _strip_nul_from_strings(data)


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None

    _name_has_alphanumeric = field_validator("name")(_validate_name_has_alphanumeric)

    @model_validator(mode="before")
    @classmethod
    def _strip_nul_bytes(cls, data):
        return _strip_nul_from_strings(data)


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
    project_id: uuid.UUID
    severity_threshold: SeverityThreshold = SeverityThreshold.HIGH
    notification_type: NotificationChannel = NotificationChannel.EMAIL
    config: dict = {}
    enabled: StrictBool = True

    @model_validator(mode="before")
    @classmethod
    def _strip_nul_bytes(cls, data):
        # `config` is stored as JSONB, which also rejects NUL bytes, so strip
        # recursively (not just top-level strings).
        return _strip_nul_from_strings(data)


class AlertConfigUpdate(BaseModel):
    project_id: uuid.UUID | None = None
    severity_threshold: SeverityThreshold | None = None
    notification_type: NotificationChannel | None = None
    enabled: StrictBool | None = None

    @model_validator(mode="before")
    @classmethod
    def _strip_nul_bytes(cls, data):
        return _strip_nul_from_strings(data)


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
