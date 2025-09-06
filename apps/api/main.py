import sys
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
try:  # noqa: E402
    from db import get_session, Target, Probe, Result  # type: ignore
    _DB_AVAILABLE = True
except Exception as _db_import_exc:  # noqa: BLE001
    get_session = None  # type: ignore[assignment]
    Target = Probe = Result = None  # type: ignore[assignment]
    _DB_AVAILABLE = False

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(title="NetLens API")
logger = logging.getLogger("netlens.api")


class ResolveRequest(BaseModel):
    name: str = Field(..., min_length=1)
    url: str = Field(..., min_length=1)


class ResolveResponse(BaseModel):
    name: str
    ip: str
    port: int
    timestamp: str
    whois: dict
    geoip: dict
    tls: dict
    dns: dict


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/resolve", response_model=ResolveResponse)
def resolve(req: ResolveRequest) -> Any:
    try:
        host, port = normalize_url(req.url)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"invalid url: {exc}") from exc

    if not host:
        raise HTTPException(status_code=400, detail="invalid url: missing host")

    try:
        ip = resolve_ip(host)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Best-effort enrichment with short timeouts to avoid blocking
    from threading import Thread
    from queue import Queue, Empty

    def _run_with_timeout(func, *args, timeout: float = 3.0, **kwargs):  # type: ignore[no-redef]
        q: "Queue[Any]" = Queue(maxsize=1)

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

    ts = datetime.now(timezone.utc).isoformat()
    resp = {
        "name": req.name,
        "ip": ip,
        "port": port,
        "timestamp": ts,
        "whois": whois_info,
        "geoip": geoip_info,
        "tls": tls_info,
        "dns": dns_info,
    }

    # Persist best-effort; log and continue on failure
    if _DB_AVAILABLE and get_session and Target and Probe and Result:  # type: ignore[truthy-bool]
        try:
            session = get_session()  # type: ignore[misc]
            try:
                target = (
                    session.query(Target)  # type: ignore[union-attr]
                    .filter(Target.name == req.name, Target.url == req.url)  # type: ignore[union-attr]
                    .first()
                )
                if target is None:
                    target = Target(name=req.name, url=req.url)  # type: ignore[call-arg]
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
            logger.error("DB persist failed: %s", db_exc)
    else:
        if not _DB_AVAILABLE:
            logger.debug("DB not available; skipping persistence")

    return resp
