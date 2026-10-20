import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    settings = Settings(
        database_path=str(tmp_path / "test.db"),
        cache_path=str(tmp_path / "cache"),
        geoip_city_path=str(tmp_path / "missing-city.mmdb"),
        geoip_asn_path=str(tmp_path / "missing-asn.mmdb"),
        offline_mode=True,
        internetdb_enabled=False,
        tor_exit_list_enabled=False,
        rdap_enabled=False,
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["analyses"] == 0
    assert payload["enrichment"]["offline_mode"] is True
    assert payload["enrichment"]["geoip_ready"] is False


def test_upload_list_and_detail(client, load_fixture):
    response = client.post(
        "/api/analyses",
        files=[
            (
                "files",
                (
                    "phishing_credential.eml",
                    load_fixture("phishing_credential.eml"),
                    "message/rfc822",
                ),
            )
        ],
    )

    assert response.status_code == 201
    payload = response.json()
    assert len(payload["results"]) == 1
    assert payload["errors"] == []

    result = payload["results"][0]
    assert result["email"]["sender"]["domain"] == "micros0ft-verify.com"
    assert result["auth"]["verdict"] == "fail"
    assert result["routing"]["origin_ip"] == "185.220.101.45"
    assert len(result["evidence"]["sha256"]) == 64
    assert result["evidence"]["offline_mode"] is True
    assert result["enrichment"]["offline_mode"] is True
    assert result["enrichment"]["ip"]["185.220.101.45"]["scope"] == "public"
    assert result["enrichment"]["domain"]["micros0ft-verify.com"]["lookalike_of"] == "microsoft.com"
    assert result["enrichment"]["sources"]["dns"]["status"] == "offline"
    assert result["score"]["available"] is True
    assert result["score"]["label"] == "suspicious"
    assert result["score"]["signals"]["auth"] == 21

    listing = client.get("/api/analyses")
    assert listing.status_code == 200
    assert len(listing.json()) == 1
    assert listing.json()[0]["id"] == result["id"]
    assert listing.json()[0]["label"] == "suspicious"
    assert listing.json()[0]["score"] == result["score"]["total"]

    detail = client.get(f"/api/analyses/{result['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == result["id"]


def test_unsupported_file_returns_422(client):
    response = client.post(
        "/api/analyses",
        files=[("files", ("sample.msg", b"not an eml", "application/octet-stream"))],
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["filename"] == "sample.msg"


def test_partial_batch_returns_result_and_error(client, load_fixture):
    response = client.post(
        "/api/analyses",
        files=[
            (
                "files",
                ("legit_business.eml", load_fixture("legit_business.eml"), "message/rfc822"),
            ),
            ("files", ("sample.msg", b"not an eml", "application/octet-stream")),
        ],
    )

    assert response.status_code == 201
    payload = response.json()
    assert len(payload["results"]) == 1
    assert len(payload["errors"]) == 1
    assert payload["errors"][0]["filename"] == "sample.msg"


def test_missing_analysis_returns_404(client):
    response = client.get("/api/analyses/does-not-exist")

    assert response.status_code == 404
