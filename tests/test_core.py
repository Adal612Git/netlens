import sys
from pathlib import Path

# Ensure core package is importable without installation
ROOT = Path(__file__).resolve().parents[1]
CORE_DIR = ROOT / "packages" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from core import normalize_url, resolve_ip  # noqa: E402


def test_normalize_url_no_scheme_defaults_http():
    host, port = normalize_url("google.com")
    assert host == "google.com"
    assert port == 80


def test_normalize_url_https_default_port():
    host, port = normalize_url("https://openai.com")
    assert host == "openai.com"
    assert port == 443


def test_normalize_url_with_explicit_port():
    host, port = normalize_url("http://example.com:8080")
    assert host == "example.com"
    assert port == 8080


def test_resolve_ip_localhost():
    assert resolve_ip("localhost") == "127.0.0.1"

