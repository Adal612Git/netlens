import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_DIR = ROOT / "packages" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

import types

from enrich import get_whois, get_geoip, get_tls_info, get_dns_records  # noqa: E402


def test_get_whois_google_best_effort():
    res = get_whois("google.com")
    assert isinstance(res, dict)
    if "error" not in res:
        assert any(
            bool(res.get(k)) for k in ("registrar", "creation_date", "expiration_date")
        )


def test_get_geoip_8_8_8_8_best_effort():
    res = get_geoip("8.8.8.8")
    assert isinstance(res, dict)
    if "error" not in res:
        assert bool(res.get("country"))


def test_get_tls_expired_best_effort():
    res = get_tls_info("expired.badssl.com", 443)
    assert isinstance(res, dict)
    # Either we detect expiration or at least return an error/info without crashing
    if "error" in res:
        assert isinstance(res["error"], str)
    else:
        # best effort: should at least have issuer or notAfter
        assert res.get("issuer") or res.get("notAfter")


def test_get_dns_google_best_effort():
    res = get_dns_records("google.com")
    assert isinstance(res, dict)
    if "error" not in res:
        # Best effort: A records may be empty in restricted envs, but keys should exist
        assert set(["A", "AAAA", "MX", "TXT"]).issubset(res.keys())


def test_tls_error_handling_monkeypatch(monkeypatch):
    # Force socket error to ensure error dict is returned
    import socket

    def boom(*args, **kwargs):  # noqa: ANN001, ANN003
        raise OSError("boom")

    monkeypatch.setattr(socket, "create_connection", boom)
    res = get_tls_info("example.com", 443)
    assert isinstance(res, dict)
    assert "error" in res


def test_dns_error_handling_monkeypatch(monkeypatch):
    # Simulate missing dnspython so import fails and function returns error dict
    dummy_dns = types.ModuleType("dns")
    monkeypatch.setitem(sys.modules, "dns", dummy_dns)
    res = get_dns_records("example.com")
    assert isinstance(res, dict)
    assert "error" in res

