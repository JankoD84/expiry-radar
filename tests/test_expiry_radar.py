import datetime as dt
import http.server
import json
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import expiry_radar as er  # noqa: E402

NOW = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)


def test_classify_thresholds():
    w = [30, 14, 7, 1]
    assert er.classify(NOW + dt.timedelta(days=60), w, NOW)[0] == er.OK
    assert er.classify(NOW + dt.timedelta(days=20), w, NOW) == (er.WARN, 20, 30)
    assert er.classify(NOW + dt.timedelta(days=10), w, NOW) == (er.WARN, 10, 14)
    assert er.classify(NOW + dt.timedelta(days=5), w, NOW) == (er.CRIT, 5, 7)
    assert er.classify(NOW - dt.timedelta(days=1), w, NOW)[0] == er.EXPIRED
    assert er.classify(None, w, NOW)[0] == er.OK


def test_manual_items_and_state_dedup():
    items = [{"type": "manual", "name": "Stripe key", "expires": "2026-12-01", "owner": "@pay"},
             {"type": "manual", "name": "Licence", "expires": "2027-06-01"},
             {"type": "nope", "name": "x"}]
    res = [er.run_item(i, {}, NOW) for i in items]
    assert [r.status for r in res] == [er.WARN, er.OK, er.ERROR]
    state = {}
    first = er.should_notify(res, state, "2026-11-20")
    assert {r.name for r in first} == {"Stripe key", "x"}
    assert er.should_notify(res, state, "2026-11-20") == []               # same day, same threshold: quiet
    assert [r.name for r in er.should_notify(res, state, "2026-11-21")] == ["x"]  # errors repeat daily
    assert "owner @pay" in er.alert_text(res[0])


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key, crt = d / "k.pem", d / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "5", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1], str(crt)
    srv.shutdown()


def test_tls_trusted_cert(tls_server):
    port, ca = tls_server
    when, detail = er.check_tls("localhost", port, ca_file=ca)
    assert 3 <= (when - er.now_utc()).days <= 5 and "INVALID" not in detail
    r = er.run_item({"type": "tls", "host": "localhost", "port": port, "ca_file": ca}, {}, er.now_utc())
    assert r.status == er.CRIT


def test_tls_untrusted_chain_still_reports_date(tls_server):
    port, _ = tls_server
    when, detail = er.check_tls("localhost", port)
    assert "INVALID CHAIN" in detail and when > er.now_utc()


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/domain/example.com"):
            body = {"events": [{"eventAction": "expiration", "eventDate": "2026-12-10T00:00:00Z"}],
                    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Acme Registrar"]]]}]}
            self._send(200, body)
        elif self.path == "/user":
            self._send(200, {"login": "bot"}, {"github-authentication-token-expiration": "2026-11-25 10:00:00 UTC"})
        else:
            self._send(404, {})

    def _send(self, code, body, headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def api():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_domain_rdap(api):
    when, detail = er.check_domain("example.com", rdap_base=api + "/domain/")
    assert when.date().isoformat() == "2026-12-10" and "Acme Registrar" in detail


def test_github_token(api, monkeypatch):
    monkeypatch.setenv("TOK", "x")
    when, detail = er.check_github_token("TOK", api=api)
    assert when.date().isoformat() == "2026-11-25" and "bot" in detail
    monkeypatch.delenv("TOK")
    with pytest.raises(ValueError):
        er.check_github_token("TOK", api=api)


def test_cli_json_inventory_and_exit(tmp_path, capsys):
    inv = tmp_path / "expiry.json"
    inv.write_text(json.dumps({"items": [{"type": "manual", "name": "old", "expires": "2020-01-01"}]}))
    st = tmp_path / "state.json"
    assert er.main([str(inv), "--notify", "stdout", "--state", str(st)]) == 1
    out = capsys.readouterr().out
    assert "EXPIRED" in out and "expiry-radar: 1 item(s)" in out
    assert json.loads(st.read_text())["old"]["key"].startswith("expired")
    assert er.main([str(inv), "--no-notify", "--fail-on", "never", "--format", "markdown"]) == 0
    assert er.main([str(tmp_path / "missing.json")]) == 2
