import json
import logging
import uuid

import grpc
from sbom_pb2 import UploadRequest, UploadResponse
from sbom_pb2_grpc import SBOMServiceServicer as BaseServicer
from sbom_pb2_grpc import add_SBOMServiceServicer_to_server
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from config import settings
from models.project import Project
from services.auth import validate_api_key
from services.sbom_parser import store_sbom
from services.tasks import scan_sbom

logger = logging.getLogger(__name__)


class AuthInterceptor(grpc.aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata or [])
        api_key = metadata.get("api-key", "")

        if not api_key:
            return _rejecting_handler(grpc.StatusCode.UNAUTHENTICATED, "api-key metadata required")

        engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as db:
            user = await validate_api_key(db, api_key)
            if not user:
                return _rejecting_handler(grpc.StatusCode.UNAUTHENTICATED, "invalid api-key")

        return await continuation(handler_call_details)


def _rejecting_handler(code: grpc.StatusCode, detail: str):
    async def handler(request, context):
        await context.abort(code, detail)

    return handler


class SBOMServiceServicer(BaseServicer):
    def __init__(self, session_factory=None):
        if session_factory is not None:
            self._session_factory = session_factory
        else:
            engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
            self._session_factory = async_sessionmaker(
                engine, class_=AsyncSession, expire_on_commit=False
            )

    async def upload_sbom(
        self, request: UploadRequest, context: grpc.aio.ServicerContext
    ) -> UploadResponse:
        async with self._session_factory() as db:
            if request.HasField("slug") and request.slug:
                result = await db.execute(select(Project).where(Project.slug == request.slug))
                project = result.scalar_one_or_none()
            else:
                try:
                    project_uuid = uuid.UUID(request.project_id)
                except ValueError:
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid project_id UUID")
                    return UploadResponse()
                result = await db.execute(select(Project).where(Project.id == project_uuid))
                project = result.scalar_one_or_none()

            if not project:
                await context.abort(grpc.StatusCode.NOT_FOUND, "project not found")
                return UploadResponse()

            try:
                raw = json.loads(request.sbom_json)
            except json.JSONDecodeError as e:
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"invalid JSON: {e}")
                return UploadResponse()

            version = request.version if request.HasField("version") else None
            sbom = await store_sbom(db, project.id, raw, version)
            await db.commit()

            scan_sbom.delay(str(sbom.id))

            return UploadResponse(
                sbom_id=str(sbom.id),
                format=sbom.format or "",
                dependency_count=sbom.dependency_count or 0,
                sha256=sbom.sha256,
            )

    UploadSBOM = upload_sbom


async def start_grpc_server():
    server = grpc.aio.server(interceptors=[AuthInterceptor()])
    add_SBOMServiceServicer_to_server(SBOMServiceServicer(), server)
    port = settings.grpc_port
    server.add_insecure_port(f"0.0.0.0:{port}")
    await server.start()
    logger.info("gRPC server listening on port %d", port)
    return server
