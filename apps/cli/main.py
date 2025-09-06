import argparse
import csv
import io
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, TextIO


def _ensure_core_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    core_path = repo_root / "packages" / "core"
    if str(core_path) not in sys.path:
        sys.path.insert(0, str(core_path))


_ensure_core_on_path()

from core import normalize_url, resolve_ip  # noqa: E402
from enrich import (  # noqa: E402
    get_whois,
    get_geoip,
    get_tls_info,
    get_dns_records,
)


logger = logging.getLogger("netlens")


def _iter_rows(reader: Iterable[list[str]]) -> Iterable[tuple[str, str]]:
    for row in reader:
        if not row:
            continue
        # Allow optional header "Nombre,URL"
        if len(row) >= 2 and row[0].strip().lower() == "nombre" and row[1].strip().lower() == "url":
            continue
        if len(row) < 2:
            logger.error("Fila inválida (se esperaban 2 columnas): %s", row)
            continue
        yield row[0].strip(), row[1].strip()


def run_resolve(input_file: Optional[str], stdin: TextIO, stdout: TextIO) -> int:
    writer = csv.writer(stdout)
    writer.writerow(["nombre", "ip", "puerto", "timestamp"])

    def process(name: str, url: str) -> None:
        try:
            host, port = normalize_url(url)
            ip = resolve_ip(host)
            ts = datetime.now(timezone.utc).isoformat()
            writer.writerow([name, ip, port, ts])

            # Enriquecimiento: imprimir en STDERR como JSON
            import json
            from threading import Thread
            from queue import Queue, Empty

            def _run_with_timeout(func, *args, timeout: float = 3.0, **kwargs):
                q: "Queue[object]" = Queue(maxsize=1)

                def runner():
                    try:
                        q.put(func(*args, **kwargs))
                    except Exception as e:  # noqa: BLE001
                        q.put({"error": str(e)})

                t = Thread(target=runner, daemon=True)
                t.start()
                try:
                    return q.get(timeout=timeout)
                except Empty:
                    return {"error": "timeout"}

            whois_info = _run_with_timeout(get_whois, host, timeout=1.0)
            geoip_info = _run_with_timeout(get_geoip, ip, timeout=1.0)
            tls_info = _run_with_timeout(get_tls_info, host, port=port, timeout=2.0)
            dns_info = _run_with_timeout(get_dns_records, host, timeout=1.0)

            enriched = {
                "whois": whois_info,
                "geoip": geoip_info,
                "tls": tls_info,
                "dns": dns_info,
            }
            print(json.dumps(enriched, ensure_ascii=False), file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            logger.error("Error resolviendo '%s' (%s): %s", name, url, exc)

    if input_file:
        with open(input_file, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for name, url in _iter_rows(reader):
                process(name, url)
    else:
        # Read from STDIN
        data = stdin.read()
        # Support empty input gracefully
        if not data.strip():
            return 0
        reader = csv.reader(io.StringIO(data))
        for name, url in _iter_rows(reader):
            process(name, url)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netlens", description="NetLens CLI")
    parser.add_argument(
        "--debug", action="store_true", help="Habilita logging DEBUG a stderr"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_resolve = subparsers.add_parser("resolve", help="Resolver IPs desde CSV o STDIN")
    p_resolve.add_argument(
        "file",
        nargs="?",
        help="Ruta al CSV (Nombre,URL). Si se omite, lee de STDIN.",
    )

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if args.command == "resolve":
        return run_resolve(getattr(args, "file", None), sys.stdin, sys.stdout)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
