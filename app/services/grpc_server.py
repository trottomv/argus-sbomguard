import json
import logging
import uuid

import grpc
from sbom_pb2 import UploadRequest, UploadResponse
from sbom_pb2_grpc import SBOMServiceServicer as BaseServicer
from sbom_pb2_grpc import add_SBOMServiceServicer_to_server
from sqlalchemy import select

from config import settings
from database import async_session_factory
from models.project import Project
from services.auth import authenticate_api_key
from services.sbom_parser import store_sbom
from services.tasks import scan_sbom

logger = logging.getLogger(__name__)


class AuthInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, session_factory=None):
        self._session_factory = (
            session_factory if session_factory is not None else async_session_factory
        )

    async def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata or [])
        auth = metadata.get("authorization", "")
        if isinstance(auth, bytes):
            auth = auth.decode()
        scheme, _, token = auth.partition(" ")

        if scheme.lower() != "bearer" or not token:
            return _rejecting_handler(
                grpc.StatusCode.UNAUTHENTICATED, "authorization: bearer metadata required"
            )

        async with self._session_factory() as db:
            result = await authenticate_api_key(db, token)
            if result.expired:
                return _rejecting_handler(grpc.StatusCode.UNAUTHENTICATED, "api key expired")
            if not result.valid:
                return _rejecting_handler(grpc.StatusCode.UNAUTHENTICATED, "invalid api key")
            # Persist last_used_at updated by authenticate_api_key; without the
            # commit the change is rolled back when the session closes.
            await db.commit()

        return await continuation(handler_call_details)


def _rejecting_handler(code: grpc.StatusCode, detail: str):
    async def handler(request, context):
        await context.abort(code, detail)

    return handler


class SBOMServiceServicer(BaseServicer):
    def __init__(self, session_factory=None):
        self._session_factory = (
            session_factory if session_factory is not None else async_session_factory
        )

    async def upload_sbom(
        self, request: UploadRequest, context: grpc.aio.ServicerContext
    ) -> UploadResponse:
        has_slug = request.HasField("slug") and bool(request.slug)
        has_project_id = bool(request.project_id)

        if has_slug and has_project_id:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, "provide only one of project_id or slug"
            )
            return UploadResponse()
        if not has_slug and not has_project_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "project_id or slug is required")
            return UploadResponse()

        async with self._session_factory() as db:
            if has_slug:
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
                format=sbom.format.value if sbom.format else "",
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
