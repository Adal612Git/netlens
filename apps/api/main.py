import json
import sys
from pathlib import Path
from typing import Any, Dict


def _ensure_core_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    core_path = repo_root / "packages" / "core"
    if str(core_path) not in sys.path:
        sys.path.insert(0, str(core_path))


_ensure_core_on_path()

from core import normalize_url, resolve_ip  # noqa: E402

try:
    from flask import Flask, jsonify, request
except Exception:  # noqa: BLE001
    # Lazy import failure handler to avoid breaking environments without Flask
    Flask = None  # type: ignore
    jsonify = None  # type: ignore
    request = None  # type: ignore


def create_app():
    if Flask is None:
        raise RuntimeError("Flask is not installed in this environment")

    app = Flask(__name__)

    @app.post("/resolve")
    def resolve():  # type: ignore[override]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        url = str(data.get("url", "")).strip()
        if not name or not url:
            return jsonify({"error": "name and url are required"}), 400
        host, port = normalize_url(url)
        ip = resolve_ip(host)
        return jsonify({"name": name, "ip": ip, "port": port})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)

