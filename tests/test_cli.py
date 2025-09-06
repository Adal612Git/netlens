import csv
import io
import re
import sys
import socket
from ipaddress import ip_address
from pathlib import Path

# Ensure project root is importable
ROOT = Path(__file__).resolve().parents[1]
CLI_DIR = ROOT / "apps" / "cli"
if str(CLI_DIR.parent) not in sys.path:
    # Add repo root so apps.cli.main can be imported as a module
    sys.path.insert(0, str(ROOT))

from apps.cli.main import main  # noqa: E402


def parse_csv_output(text: str):
    reader = csv.reader(io.StringIO(text))
    return list(reader)


def test_stdin_single_line_google(capsys, monkeypatch):
    # Simulate: echo "Google,google.com" | netlens resolve
    monkeypatch.setattr("sys.stdin", io.StringIO("Google,google.com\n"))
    # Avoid real DNS in CI
    monkeypatch.setattr("apps.cli.main.resolve_ip", lambda host: "127.0.0.1")
    rc = main(["resolve"])  # use module main to simulate entry point
    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out
    rows = parse_csv_output(out)
    # Expect header + 1 data row
    assert len(rows) >= 2
    header = rows[0]
    assert [c.lower() for c in header] == ["nombre", "ip", "puerto", "timestamp"]
    data = rows[1]
    assert "Google" in data[0]
    # Validate IPv4
    ip_address(data[1])
    # Validate port as integer
    assert int(data[2]) in (80, 443) or int(data[2]) > 0
    # Validate ISO-8601 timestamp (very lenient)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T", data[3])


def test_csv_file_multiple_rows(tmp_path, capsys, monkeypatch):
    p = tmp_path / "input.csv"
    p.write_text("Google,google.com\nOpenAI,openai.com\n", encoding="utf-8")
    # Avoid real DNS in CI
    monkeypatch.setattr("apps.cli.main.resolve_ip", lambda host: "127.0.0.1")
    rc = main(["resolve", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    rows = parse_csv_output(out)
    assert len(rows) == 3  # header + 2
    names = [r[0] for r in rows[1:]]
    assert "Google" in names and "OpenAI" in names
    for r in rows[1:]:
        ip_address(r[1])
        assert int(r[2]) in (80, 443) or int(r[2]) > 0
        assert re.match(r"^\d{4}-\d{2}-\d{2}T", r[3])


def test_invalid_domain_logs_error_and_continues(tmp_path, capsys, monkeypatch, caplog):
    p = tmp_path / "input.csv"
    # Include one invalid domain
    p.write_text("Good,openai.com\nBad,invalid.invalid\n", encoding="utf-8")
    def fake_resolve(host: str) -> str:
        if host == "invalid.invalid":
            raise socket.gaierror("Name or service not known")
        return "127.0.0.1"
    monkeypatch.setattr("apps.cli.main.resolve_ip", fake_resolve)
    caplog.clear()
    rc = main(["resolve", str(p)])
    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out
    rows = parse_csv_output(out)
    # Only one successful row in output (header + 1)
    assert len(rows) == 2
    assert rows[1][0] == "Good"
    # Error should be logged mentioning the invalid domain
    assert any("invalid.invalid" in m.message.lower() for m in caplog.records)
