#!/usr/bin/env python3
"""expiry-radar: know 30 days before a certificate, domain, token or licence expires.

Inventory (expiry.yml or expiry.json):
  defaults: {warn_days: [30, 14, 7, 1], owner: "@platform"}
  items:
    - {type: tls, host: api.example.com, port: 443, owner: "@backend", runbook: "https://…/cert-expired"}
    - {type: domain, name: example.com}                     # RDAP lookup, no API key
    - {type: github-token, token_env: GH_TOKEN, name: "CI release PAT"}
    - {type: manual, name: "Stripe restricted key", expires: 2027-03-01, owner: "@payments"}

Checks run where you run it (CI, cron, your laptop). Secrets stay in your environment;
the inventory holds names and dates only. Alerts go to Slack, Discord or Telegram (see notify.py),
once per threshold thanks to an optional --state file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import notify  # noqa: E402

__version__ = "1.0.0"
OK, WARN, CRIT, EXPIRED, ERROR = "ok", "warn", "critical", "expired", "error"
ORDER = {EXPIRED: 0, ERROR: 1, CRIT: 2, WARN: 3, OK: 4}


@dataclass
class Result:
    name: str
    type: str
    status: str
    expires: str | None = None
    days_left: int | None = None
    detail: str = ""
    owner: str = ""
    runbook: str = ""
    threshold: int | None = None
    extra: dict = field(default_factory=dict)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _cert_not_after(cert: dict) -> dt.datetime:
    return dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)


def check_tls(host: str, port: int = 443, timeout: float = 10, ca_file: str | None = None) -> tuple[dt.datetime, str]:
    """Return (not_after, detail). Verifies the chain and hostname; on verification failure still reads the date."""
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                return _cert_not_after(cert), f"issuer: {issuer.get('organizationName') or issuer.get('commonName', '?')}"
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or str(exc)
        raw = _fetch_unverified(host, port, timeout)
        if raw is None:
            raise
        return raw, f"INVALID CHAIN: {reason}"


def _fetch_unverified(host: str, port: int, timeout: float) -> dt.datetime | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        path = fh.name
    try:
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]  # stdlib decoder, no extra deps
        return _cert_not_after(decoded)
    finally:
        os.unlink(path)


def check_domain(name: str, timeout: float = 15, rdap_base: str = "https://rdap.org/domain/") -> tuple[dt.datetime, str]:
    req = urllib.request.Request(rdap_base + name, headers={"Accept": "application/rdap+json", "User-Agent": f"expiry-radar/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed RDAP bootstrap host
        data = json.loads(resp.read())
    for ev in data.get("events", []):
        if ev.get("eventAction") in ("expiration", "registration expiration"):
            when = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            return when, f"registrar: {_registrar(data)}"
    raise ValueError("registry does not publish an expiration date (common for some ccTLDs): use type: manual")


def _registrar(data: dict) -> str:
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    return item[3]
    return "?"


def check_github_token(token_env: str, api: str = "https://api.github.com", timeout: float = 15) -> tuple[dt.datetime | None, str]:
    token = os.environ.get(token_env, "")
    if not token:
        raise ValueError(f"environment variable {token_env} is not set")
    req = urllib.request.Request(api.rstrip("/") + "/user", headers={"Authorization": f"Bearer {token}", "User-Agent": f"expiry-radar/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - GitHub API
        hdr = resp.headers.get("github-authentication-token-expiration")
        login = json.loads(resp.read()).get("login", "?")
    if not hdr:
        return None, f"token of {login} has no expiration (consider a fine-grained token with expiry)"
    when = dt.datetime.strptime(hdr.replace(" UTC", " +0000"), "%Y-%m-%d %H:%M:%S %z")
    return when, f"token of {login}"


def classify(expires: dt.datetime | None, warn_days: list[int], now: dt.datetime) -> tuple[str, int | None, int | None]:
    if expires is None:
        return OK, None, None
    days = (expires - now).total_seconds() / 86400
    left = int(days) if days >= 0 else -1
    if days < 0:
        return EXPIRED, left, 0
    crossed = [t for t in sorted(warn_days) if days <= t]
    if not crossed:
        return OK, left, None
    t = crossed[0]
    return (CRIT if t <= min(7, max(warn_days)) else WARN), left, t


def run_item(item: dict, defaults: dict, now: dt.datetime) -> Result:
    kind = item.get("type", "manual")
    name = item.get("name") or item.get("host") or "?"
    owner = item.get("owner", defaults.get("owner", ""))
    warn_days = item.get("warn_days", defaults.get("warn_days", [30, 14, 7, 1]))
    res = Result(name=name, type=kind, status=OK, owner=owner, runbook=item.get("runbook", ""))
    try:
        if kind == "tls":
            when, detail = check_tls(item["host"], int(item.get("port", 443)), ca_file=item.get("ca_file"))
            res.name = f"{item['host']}:{item.get('port', 443)}"
        elif kind == "domain":
            when, detail = check_domain(item["name"], rdap_base=defaults.get("rdap_base", "https://rdap.org/domain/"))
        elif kind == "github-token":
            when, detail = check_github_token(item.get("token_env", "GITHUB_TOKEN"))
        elif kind == "manual":
            when = dt.datetime.combine(dt.date.fromisoformat(str(item["expires"])), dt.time(0, 0), dt.timezone.utc)
            detail = item.get("kind", "")
        else:
            raise ValueError(f"unknown type '{kind}'")
        res.detail = detail
        res.status, res.days_left, res.threshold = classify(when, warn_days, now)
        res.expires = when.date().isoformat() if when else None
        if "INVALID CHAIN" in detail and res.status == OK:
            res.status = CRIT
    except (OSError, ValueError, KeyError, urllib.error.URLError, ssl.SSLError) as exc:
        res.status, res.detail = ERROR, f"{exc.__class__.__name__}: {str(exc)[:160]}"
    return res


def load_inventory(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yml", ".yaml"):
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.exit("expiry-radar: PyYAML is needed for YAML inventories (pip install pyyaml) or use JSON")
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if isinstance(data, list):
        data = {"items": data}
    return data


def should_notify(results: list[Result], state: dict, today: str) -> list[Result]:
    """Alert once per item per threshold (and daily while expired or broken)."""
    out = []
    for r in results:
        if r.status == OK:
            state.pop(r.name, None)
            continue
        key = f"{r.status}:{r.threshold}"
        prev = state.get(r.name, {})
        if prev.get("key") != key or (r.status in (EXPIRED, ERROR) and prev.get("day") != today):
            out.append(r)
            state[r.name] = {"key": key, "day": today}
    return out


def render(results: list[Result], fmt: str) -> str:
    rows = sorted(results, key=lambda r: (ORDER[r.status], r.days_left if r.days_left is not None else 10**6))
    if fmt == "json":
        return json.dumps([r.__dict__ for r in rows], indent=2)
    icon = {OK: "✅", WARN: "🟡", CRIT: "🟠", EXPIRED: "🔴", ERROR: "⚠️"}
    if fmt == "markdown":
        lines = ["| | Item | Expires | Days left | Owner | Detail |", "|---|---|---|---|---|---|"]
        lines += [f"| {icon[r.status]} | {r.name} ({r.type}) | {r.expires or '–'} | {'' if r.days_left is None else r.days_left} | {r.owner} | {r.detail} |" for r in rows]
        return "\n".join(lines)
    return "\n".join(f"{r.status.upper():8} {r.name:40} {r.expires or '–':10} {'' if r.days_left is None else str(r.days_left) + 'd':>6}  {r.owner}  {r.detail}" for r in rows)


def alert_text(r: Result) -> str:
    when = "EXPIRED" if r.status == EXPIRED else ("CHECK FAILED" if r.status == ERROR else f"expires in {r.days_left} days ({r.expires})")
    parts = [f"{r.name} ({r.type}): {when}"]
    if r.detail:
        parts.append(r.detail)
    if r.owner:
        parts.append(f"owner {r.owner}")
    if r.runbook:
        parts.append(f"runbook {r.runbook}")
    return " · ".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="expiry-radar", description="Certificates, domains, tokens and licences before they expire")
    ap.add_argument("inventory", type=Path, help="expiry.yml / expiry.json")
    ap.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    ap.add_argument("--notify", action="append", default=None, help="slack:URL | discord:URL | telegram:CHAT_ID | stdout (default: env)")
    ap.add_argument("--no-notify", action="store_true")
    ap.add_argument("--state", type=Path, help="JSON file to alert once per threshold (use in cron/CI cache)")
    ap.add_argument("--fail-on", choices=["warn", "critical", "expired", "never"], default="critical")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = ap.parse_args(argv)
    if not a.inventory.is_file():
        print(f"expiry-radar: {a.inventory} not found", file=sys.stderr)
        return 2
    inv = load_inventory(a.inventory)
    defaults = inv.get("defaults", {})
    now = now_utc()
    results = [run_item(i, defaults, now) for i in inv.get("items", [])]
    print(render(results, a.format))

    if not a.no_notify:
        state = json.loads(a.state.read_text()) if a.state and a.state.is_file() else {}
        due = should_notify(results, state, now.date().isoformat()) if a.state else [r for r in results if r.status != OK]
        if due:
            errors = notify.send("\n".join("• " + alert_text(r) for r in due), a.notify, title=f"expiry-radar: {len(due)} item(s) need attention")
            for e in errors:
                print(f"notify failed: {e}", file=sys.stderr)
        if a.state:
            a.state.write_text(json.dumps(state, indent=2))
    worst = min((ORDER[r.status] for r in results), default=ORDER[OK])
    limit = {"warn": ORDER[WARN], "critical": ORDER[CRIT], "expired": ORDER[EXPIRED], "never": -1}[a.fail_on]
    return 1 if worst <= limit else 0


if __name__ == "__main__":
    sys.exit(main())
