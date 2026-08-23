import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import grpc
import grpc.aio
import pytest
import pytest_asyncio
from sbom_pb2 import UploadRequest
from sbom_pb2_grpc import SBOMServiceStub, add_SBOMServiceServicer_to_server
from sqlalchemy.ext.asyncio import async_sessionmaker

from services.grpc_server import AuthInterceptor, SBOMServiceServicer, _rejecting_handler


class TestUploadSBOMDefensiveReturns:
    """Exercise the defensive ``return UploadResponse()`` after ``abort()``.

    In the real server ``context.abort`` raises and the return is never hit,
    but with a no-op ``abort`` mock the explicit return statement runs, which
    exercises the line coverage without changing the production code.
    """

    @pytest.mark.asyncio
    async def test_both_ids_returns_after_abort(self, db_session):
        from sbom_pb2 import UploadResponse

        from models.project import Project

        project = Project(name="defensive-both")
        db_session.add(project)
        await db_session.commit()

        servicer = SBOMServiceServicer(session_factory=async_sessionmaker(db_session.bind))
        context = AsyncMock()

        request = UploadRequest(
            project_id=str(project.id),
            slug=project.slug or "x",
            sbom_json=b"{}",
        )
        response = await servicer.upload_sbom(request, context)
        assert isinstance(response, UploadResponse)
        context.abort.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_missing_ids_returns_after_abort(self, db_session):
        from sbom_pb2 import UploadResponse

        servicer = SBOMServiceServicer(session_factory=async_sessionmaker(db_session.bind))
        context = AsyncMock()

        response = await servicer.upload_sbom(
            UploadRequest(project_id="", sbom_json=b"{}"), context
        )
        assert isinstance(response, UploadResponse)
        context.abort.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalid_uuid_returns_after_abort(self, db_session):
        from sbom_pb2 import UploadResponse

        servicer = SBOMServiceServicer(session_factory=async_sessionmaker(db_session.bind))
        context = AsyncMock()

        response = await servicer.upload_sbom(
            UploadRequest(project_id="not-a-uuid", sbom_json=b"{}"), context
        )
        assert isinstance(response, UploadResponse)
        context.abort.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_project_not_found_returns_after_abort(self, db_session):
        from sbom_pb2 import UploadResponse

        servicer = SBOMServiceServicer(session_factory=async_sessionmaker(db_session.bind))
        context = AsyncMock()

        response = await servicer.upload_sbom(
            UploadRequest(project_id=str(uuid.uuid4()), sbom_json=b"{}"), context
        )
        assert isinstance(response, UploadResponse)
        context.abort.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalid_json_returns_after_abort(self, db_session):
        from sbom_pb2 import UploadResponse

        from models.project import Project

        project = Project(name="defensive-json")
        db_session.add(project)
        await db_session.commit()

        servicer = SBOMServiceServicer(session_factory=async_sessionmaker(db_session.bind))
        context = AsyncMock()

        response = await servicer.upload_sbom(
            UploadRequest(project_id=str(project.id), sbom_json=b"not json"), context
        )
        assert isinstance(response, UploadResponse)
        context.abort.assert_awaited_once()


class TestUploadSBOM:
    @pytest_asyncio.fixture
    async def grpc_client(self, db_session):
        session_factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
        servicer = SBOMServiceServicer(session_factory=session_factory)

        server = grpc.aio.server()
        add_SBOMServiceServicer_to_server(servicer, server)
        port = server.add_insecure_port("localhost:0")
        await server.start()

        channel = grpc.aio.insecure_channel(f"localhost:{port}")
        try:
            yield SBOMServiceStub(channel)
            await channel.close()
        finally:
            await server.stop(5)

    @pytest.mark.asyncio
    async def test_upload_sbom_success(self, db_session, grpc_client):
        from models.project import Project

        project = Project(name="grpc-test")
        db_session.add(project)
        await db_session.commit()

        sbom_json = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "flask", "version": "2.0.0"}],
            }
        )

        response = await grpc_client.UploadSBOM(
            UploadRequest(
                project_id=str(project.id),
                version="1.0.0",
                sbom_json=sbom_json.encode(),
            )
        )

        assert response.format == "cyclonedx"
        assert response.dependency_count == 1

    @pytest.mark.asyncio
    async def test_upload_sbom_invalid_project(self, db_session, grpc_client):
        fake_id = str(uuid.uuid4())
        with pytest.raises(grpc.aio.AioRpcError) as exc:
            await grpc_client.UploadSBOM(
                UploadRequest(
                    project_id=fake_id,
                    sbom_json=b'{"bomFormat":"CycloneDX","components":[]}',
                )
            )
        assert exc.value.code() == grpc.StatusCode.NOT_FOUND

    @pytest.mark.asyncio
    async def test_upload_sbom_invalid_json(self, db_session, grpc_client):
        from models.project import Project

        project = Project(name="grpc-test-2")
        db_session.add(project)
        await db_session.commit()

        with pytest.raises(grpc.aio.AioRpcError) as exc:
            await grpc_client.UploadSBOM(
                UploadRequest(
                    project_id=str(project.id),
                    sbom_json=b"not json",
                )
            )
        assert exc.value.code() == grpc.StatusCode.INVALID_ARGUMENT

    @pytest.mark.asyncio
    async def test_upload_sbom_invalid_uuid(self, db_session, grpc_client):
        with pytest.raises(grpc.aio.AioRpcError) as exc:
            await grpc_client.UploadSBOM(UploadRequest(project_id="not-a-uuid", sbom_json=b"{}"))
        assert exc.value.code() == grpc.StatusCode.INVALID_ARGUMENT

    @pytest.mark.asyncio
    async def test_upload_sbom_by_slug(self, db_session, grpc_client):
        from models.project import Project

        project = Project(name="grpc-slug")
        db_session.add(project)
        await db_session.commit()
        await db_session.refresh(project)
        assert project.slug == "grpc-slug"

        sbom_json = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "flask", "version": "2.0.0"}],
            }
        )

        response = await grpc_client.UploadSBOM(
            UploadRequest(
                project_id="",
                slug=project.slug,
                sbom_json=sbom_json.encode(),
            )
        )

        assert response.format == "cyclonedx"
        assert response.dependency_count == 1

    @pytest.mark.asyncio
    async def test_upload_sbom_slug_not_found(self, db_session, grpc_client):
        with pytest.raises(grpc.aio.AioRpcError) as exc:
            await grpc_client.UploadSBOM(
                UploadRequest(
                    project_id="",
                    slug="does-not-exist",
                    sbom_json=b'{"bomFormat":"CycloneDX","components":[]}',
                )
            )
        assert exc.value.code() == grpc.StatusCode.NOT_FOUND

    @pytest.mark.asyncio
    async def test_upload_sbom_both_ids_rejected(self, db_session, grpc_client):
        from models.project import Project

        project = Project(name="grpc-both")
        db_session.add(project)
        await db_session.commit()
        await db_session.refresh(project)

        with pytest.raises(grpc.aio.AioRpcError) as exc:
            await grpc_client.UploadSBOM(
                UploadRequest(
                    project_id=str(project.id),
                    slug=project.slug,
                    sbom_json=b'{"bomFormat":"CycloneDX","components":[]}',
                )
            )
        assert exc.value.code() == grpc.StatusCode.INVALID_ARGUMENT

    @pytest.mark.asyncio
    async def test_upload_sbom_missing_ids_rejected(self, db_session, grpc_client):
        with pytest.raises(grpc.aio.AioRpcError) as exc:
            await grpc_client.UploadSBOM(
                UploadRequest(project_id="", sbom_json=b'{"bomFormat":"CycloneDX","components":[]}')
            )
        assert exc.value.code() == grpc.StatusCode.INVALID_ARGUMENT


class TestAuthInterceptor:
    def _details(self, api_key: str = ""):
        class _Details:
            invocation_metadata = [("api-key", api_key)] if api_key else []

        return _Details()

    def _interceptor(self, db_session):
        return AuthInterceptor(session_factory=async_sessionmaker(db_session.bind))

    @pytest.mark.asyncio
    async def test_missing_api_key_rejected(self):
        interceptor = AuthInterceptor()
        continuation = AsyncMock()

        handler = await interceptor.intercept_service(continuation, self._details(""))
        assert handler is not None
        continuation.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self, db_session):
        interceptor = self._interceptor(db_session)
        continuation = AsyncMock()

        with patch(
            "services.grpc_server.validate_api_key",
            new_callable=AsyncMock,
            return_value=None,
        ):
            handler = await interceptor.intercept_service(continuation, self._details("argus_bad"))
        assert handler is not None
        continuation.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_api_key_passes_through(self, db_session):
        from models.auth import User

        user = User(email="grpc-key@example.com", is_admin=True)
        interceptor = self._interceptor(db_session)
        continuation = AsyncMock()
        continuation.return_value = "handled"

        with patch(
            "services.grpc_server.validate_api_key",
            new_callable=AsyncMock,
            return_value=user,
        ):
            result = await interceptor.intercept_service(continuation, self._details("argus_valid"))
        assert result == "handled"
        continuation.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rejecting_handler_aborts(self):
        context = AsyncMock()
        handler = _rejecting_handler(grpc.StatusCode.UNAUTHENTICATED, "nope")
        await handler(None, context)
        context.abort.assert_awaited_once_with(grpc.StatusCode.UNAUTHENTICATED, "nope")


def test_servicer_default_session_factory():
    from database import async_session_factory

    servicer = SBOMServiceServicer()
    assert servicer._session_factory is async_session_factory


@pytest.mark.asyncio
async def test_start_grpc_server():
    server = AsyncMock()
    server.add_insecure_port = MagicMock(return_value=50051)
    server.start = AsyncMock()
    with (
        patch("services.grpc_server.grpc.aio.server", return_value=server) as mock_server,
        patch("services.grpc_server.settings.grpc_port", "5055"),
        patch("services.grpc_server.add_SBOMServiceServicer_to_server") as mock_add,
    ):
        from services.grpc_server import start_grpc_server

        result = await start_grpc_server()

    mock_server.assert_called_once()
    mock_add.assert_called_once()
    server.add_insecure_port.assert_called_once_with("0.0.0.0:5055")
    server.start.assert_awaited_once()
    assert result == server
