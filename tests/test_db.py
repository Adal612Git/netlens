import sys
import io
import csv
from pathlib import Path

import types


# Ensure core package and apps are importable
ROOT = Path(__file__).resolve().parents[1]
CORE_DIR = ROOT / "packages" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from db import init_db, get_session, Target, Probe, Result  # type: ignore  # noqa: E402
from apps.cli.main import main as cli_main  # noqa: E402


def test_init_db_creates_tables(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    # Should not raise
    engine = init_db(db_url)
    # Simple sanity: open a session and close
    s = get_session(db_url)
    try:
        assert s.query(Target).count() == 0
        assert s.query(Probe).count() == 0
        assert s.query(Result).count() == 0
    finally:
        s.close()


def test_insert_and_retrieve_models(tmp_path):
    db_url = f"sqlite:///{tmp_path}/models.db"
    init_db(db_url)
    s = get_session(db_url)
    try:
        t = Target(name="Google", url="google.com")
        s.add(t)
        s.flush()
        p = Probe(target_id=t.id)
        s.add(p)
        s.flush()
        r = Result(probe_id=p.id, ip="127.0.0.1", port=80, whois={}, geoip={}, tls={}, dns={})
        s.add(r)
        s.commit()

        assert s.query(Target).count() == 1
        assert s.query(Probe).count() == 1
        assert s.query(Result).count() == 1

        row = (
            s.query(Target.name, Target.url, Result.ip, Result.port, Probe.timestamp)
            .join(Probe, Probe.target_id == Target.id)
            .join(Result, Result.probe_id == Probe.id)
            .first()
        )
        assert row is not None
        assert row[0] == "Google" and row[1] == "google.com"
        assert row[2] == "127.0.0.1" and int(row[3]) == 80
    finally:
        s.close()


def test_cli_resolve_persists_results(tmp_path, monkeypatch, capsys):
    db_url = f"sqlite:///{tmp_path}/cli.db"
    init_db(db_url)

    # Monkeypatch CLI DB session factory to use temp DB URL
    import apps.cli.main as cli

    def get_session_override():
        return get_session(db_url)

    monkeypatch.setattr(cli, "get_session", get_session_override)
    monkeypatch.setattr(cli, "_DB_AVAILABLE", True)

    # Avoid real DNS/enrichment
    monkeypatch.setattr("apps.cli.main.resolve_ip", lambda host: "127.0.0.1")
    monkeypatch.setattr("apps.cli.main.get_whois", lambda host: {})
    monkeypatch.setattr("apps.cli.main.get_geoip", lambda ip: {})
    monkeypatch.setattr("apps.cli.main.get_tls_info", lambda host, port=443: {})
    monkeypatch.setattr("apps.cli.main.get_dns_records", lambda host: {"A": ["127.0.0.1"], "AAAA": [], "MX": [], "TXT": []})

    # Run CLI resolve 3 times via stdin
    csv_input = "Google,google.com\nOpenAI,openai.com\nExample,example.com\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(csv_input))
    rc = cli_main(["resolve"])
    assert rc == 0
    _ = capsys.readouterr()  # drain outputs

    # Check DB has 3 results
    s = get_session(db_url)
    try:
        assert s.query(Result).count() == 3
    finally:
        s.close()


def test_cli_history_outputs_rows(tmp_path, monkeypatch, capsys):
    db_url = f"sqlite:///{tmp_path}/hist.db"
    init_db(db_url)
    s = get_session(db_url)
    try:
        # Seed 3 results
        t = Target(name="N1", url="u1")
        s.add(t); s.flush()
        for i in range(3):
            p = Probe(target_id=t.id); s.add(p); s.flush()
            s.add(Result(probe_id=p.id, ip=f"127.0.0.{i+1}", port=80, whois={}, geoip={}, tls={}, dns={}))
        s.commit()
    finally:
        s.close()

    import apps.cli.main as cli

    def get_session_override():
        return get_session(db_url)

    monkeypatch.setattr(cli, "get_session", get_session_override)
    monkeypatch.setattr(cli, "_DB_AVAILABLE", True)

    rc = cli_main(["history", "-n", "10"])
    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out
    rows = list(csv.reader(io.StringIO(out)))
    # header + 3 rows
    assert len(rows) == 4

