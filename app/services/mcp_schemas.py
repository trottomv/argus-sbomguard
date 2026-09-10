"""Pydantic response models for the read-only MCP tools.

Declaring these as the tools' return annotations makes the MCP SDK publish an
``outputSchema`` and return validated ``structuredContent`` (plus a JSON text
fallback), the MCP analogue of the REST response schemas. Errors are signalled
by raising ``ToolError`` instead of returning a model.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class McpPage[T](BaseModel):
    """Uniform pagination envelope shared by every list tool."""

    items: list[T]
    total: int
    offset: int
    limit: int
    has_more: bool


class ProjectItem(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    repo_url: str | None
    platform: str | None
    created_at: datetime | None


class ServiceItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    created_at: datetime | None


class SbomItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    service_id: uuid.UUID | None
    service_name: str | None
    version: str | None
    format: str | None
    sha256: str
    dependency_count: int | None
    uploaded_at: datetime | None


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    unknown: int


class VulnerabilityCounts(SeverityCounts):
    total: int


class SbomDetail(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    service_id: uuid.UUID | None
    service_name: str | None
    version: str | None
    format: str | None
    sha256: str
    dependency_count: int | None
    uploaded_at: datetime | None
    vulnerability_counts: VulnerabilityCounts
    open_count: int
    fixed_count: int


class DependencyItem(BaseModel):
    name: str
    version: str
    purl: str | None
    type: str | None
    license: str | None
    is_direct: bool


class SbomDependenciesPage(BaseModel):
    sbom_id: uuid.UUID
    total: int
    offset: int
    limit: int
    has_more: bool
    dependencies: list[DependencyItem]


class SbomVulnerabilityItem(BaseModel):
    cve_id: str
    severity: str | None
    cvss_score: float | None
    summary: str | None
    status: str | None
    dependency_purl: str
    fixed_versions: list[str]
    fix_state: str | None


class SbomVulnerabilitiesPage(BaseModel):
    sbom_id: uuid.UUID
    total: int
    offset: int
    limit: int
    has_more: bool
    vulnerabilities: list[SbomVulnerabilityItem]


class VulnerabilityItem(BaseModel):
    id: uuid.UUID
    cve_id: str
    severity: str | None
    cvss_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    summary: str | None
    source: str | None
    published_at: datetime | None
    projects: list[str]
    services: list[str]
    dependency_purls: list[str]
    fixed_versions: list[str]
    fix_state: str | None


class AlertItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    severity_threshold: str | None
    notification_type: str | None
    enabled: bool
    config: dict | None
    created_at: datetime | None


class RiskAcceptanceItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    service_id: uuid.UUID | None
    service_name: str | None
    vulnerability_id: uuid.UUID
    cve_id: str
    reason: str
    created_at: datetime | None


class SnapshotItem(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int
    fixed: int
    total_dependencies: int


class SnapshotResponse(BaseModel):
    count: int
    snapshots: list[SnapshotItem]


class SummarizeResponse(BaseModel):
    counts: SeverityCounts
    total: int
    affected_projects: int
    affected_services: int
    fixed: int
