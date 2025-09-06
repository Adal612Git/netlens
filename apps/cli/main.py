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
try:  # noqa: E402
    from db import get_session, Target, Probe, Result  # type: ignore
    _DB_AVAILABLE = True
except Exception:  # noqa: BLE001
    get_session = None  # type: ignore[assignment]
    Target = Probe = Result = None  # type: ignore[assignment]
    _DB_AVAILABLE = False
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

            # Persistencia en DB (best-effort por fila)
            if _DB_AVAILABLE and get_session and Target and Probe and Result:  # type: ignore[truthy-bool]
                try:
                    session = get_session()  # type: ignore[misc]
                    try:
                        target = (
                            session.query(Target)  # type: ignore[union-attr]
                            .filter(Target.name == name, Target.url == url)  # type: ignore[union-attr]
                            .first()
                        )
                        if target is None:
                            target = Target(name=name, url=url)  # type: ignore[call-arg]
                            session.add(target)
                            session.flush()

                        probe = Probe(target_id=target.id)  # type: ignore[call-arg]
                        session.add(probe)
                        session.flush()

                        result = Result(  # type: ignore[call-arg]
                            probe_id=probe.id,
                            ip=ip,
                            port=port,
                            whois=whois_info,
                            geoip=geoip_info,
                            tls=tls_info,
                            dns=dns_info,
                        )
                        session.add(result)
                        session.commit()
                    finally:
                        try:
                            session.close()
                        except Exception:  # noqa: BLE001
                            pass
                except Exception as db_exc:  # noqa: BLE001
                    logger.error("DB persist failed for '%s' (%s): %s", name, url, db_exc)
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


def run_history(limit: int, export_path: Optional[str], stdout: TextIO) -> int:
    if not _DB_AVAILABLE or not get_session or not Target or not Probe or not Result:  # type: ignore[truthy-bool]
        logger.error("DB no disponible. Instala SQLAlchemy y asegúrate de que packages/core/db.py esté accesible.")
        return 1

    # Exportar todo el histórico si se solicita
    if export_path:
        try:
            import pandas as pd  # type: ignore
        except Exception as ie:  # noqa: BLE001
            logger.error("Pandas requerido para exportar: %s", ie)
            return 1

        session = get_session()  # type: ignore[misc]
        try:
            rows = (
                session.query(Target.name, Target.url, Result.ip, Result.port, Probe.timestamp)  # type: ignore[union-attr]
                .join(Probe, Probe.target_id == Target.id)  # type: ignore[union-attr]
                .join(Result, Result.probe_id == Probe.id)  # type: ignore[union-attr]
                .order_by(Probe.timestamp.desc(), Result.id.desc())  # type: ignore[union-attr]
                .all()
            )
            data = [
                {
                    "nombre": r[0],
                    "url": r[1],
                    "ip": r[2],
                    "puerto": r[3],
                    "timestamp": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
                }
                for r in rows
            ]
            df = pd.DataFrame(data)
            if export_path.lower().endswith(".csv"):
                df.to_csv(export_path, index=False)
            elif export_path.lower().endswith(".parquet"):
                try:
                    df.to_parquet(export_path, index=False)
                except Exception as pe:  # noqa: BLE001
                    logger.error("Para Parquet instala 'pyarrow' o 'fastparquet': %s", pe)
                    return 1
            else:
                logger.error("Extensión no soportada para export: usa .csv o .parquet")
                return 1
            logger.info("Histórico exportado a %s (%d filas)", export_path, len(df))
        except Exception as exc:  # noqa: BLE001
            logger.error("Error exportando histórico: %s", exc)
            return 1
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass

    # Imprimir últimos N en CSV a STDOUT
    writer = csv.writer(stdout)
    writer.writerow(["nombre", "url", "ip", "puerto", "timestamp"])
    session = get_session()  # type: ignore[misc]
    try:
        q = (
            session.query(Target.name, Target.url, Result.ip, Result.port, Probe.timestamp)  # type: ignore[union-attr]
            .join(Probe, Probe.target_id == Target.id)  # type: ignore[union-attr]
            .join(Result, Result.probe_id == Probe.id)  # type: ignore[union-attr]
            .order_by(Probe.timestamp.desc(), Result.id.desc())  # type: ignore[union-attr]
        )
        if limit and limit > 0:
            q = q.limit(limit)  # type: ignore[assignment]
        for name, url, ip, port, ts in q.all():
            ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            writer.writerow([name, url, ip, port, ts_str])
    except Exception as exc:  # noqa: BLE001
        logger.error("Error consultando histórico: %s", exc)
        return 1
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
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

    p_history = subparsers.add_parser("history", help="Mostrar/Exportar histórico de resultados")
    p_history.add_argument(
        "-n",
        "--limit",
        type=int,
        default=10,
        help="Número de resultados recientes a imprimir (default 10)",
    )
    p_history.add_argument(
        "--export",
        dest="export_path",
        help="Exporta TODO el histórico a CSV o Parquet (según extensión)",
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
    if args.command == "history":
        return run_history(limit=args.limit, export_path=args.export_path, stdout=sys.stdout)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
