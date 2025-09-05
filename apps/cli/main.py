import argparse
import sys
from pathlib import Path


def _ensure_core_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    core_path = repo_root / "packages" / "core"
    if str(core_path) not in sys.path:
        sys.path.insert(0, str(core_path))


_ensure_core_on_path()

from core import normalize_url, resolve_ip  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="NetLens CLI – IP Resolver")
    parser.add_argument("--name", required=True, help="Name to print")
    parser.add_argument("--url", required=True, help="URL to resolve")
    args = parser.parse_args()

    host, port = normalize_url(args.url)
    ip = resolve_ip(host)
    print(f"{args.name}, {ip}, {port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

