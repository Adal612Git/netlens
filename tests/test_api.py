import sys
from pathlib import Path
from ipaddress import ip_address

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from apps.api.main import app  # noqa: E402


client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_resolve_valid_google(monkeypatch):
    # Avoid real DNS lookups in CI
    monkeypatch.setattr("apps.api.main.resolve_ip", lambda host: "127.0.0.1")
    r = client.post("/resolve", json={"name": "Google", "url": "google.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Google"
    ip_address(data["ip"])  # validates IPv4 format
    assert isinstance(data["port"], int)
    assert isinstance(data["timestamp"], str)
    assert data["port"] in (80, 443) or data["port"] > 0


def test_resolve_invalid_url():
    # Missing host after normalization (e.g., "http://")
    r = client.post("/resolve", json={"name": "X", "url": "http://"})
    assert r.status_code == 400
    assert "invalid url" in r.json()["detail"].lower()


def test_resolve_nonexistent_domain(monkeypatch):
    def fake_resolve(host: str) -> str:
        raise OSError("Name or service not known")

    monkeypatch.setattr("apps.api.main.resolve_ip", fake_resolve)
    r = client.post("/resolve", json={"name": "Bad", "url": "invalid.invalid"})
    assert r.status_code == 400
    assert "name or service not known" in r.json()["detail"].lower()
