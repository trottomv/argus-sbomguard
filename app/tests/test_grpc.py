import json
import uuid

import grpc
import grpc.aio
import pytest
import pytest_asyncio
from sbom_pb2 import UploadRequest
from sbom_pb2_grpc import SBOMServiceStub, add_SBOMServiceServicer_to_server
from sqlalchemy.ext.asyncio import async_sessionmaker

from services.grpc_server import SBOMServiceServicer


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
