"""notify: send one message to Slack, Discord or Telegram (incoming webhooks / Bot API). Stdlib only.

Targets (repeatable, or via environment):
  slack:<incoming-webhook-url>       or NOTIFY_SLACK_WEBHOOK
  discord:<webhook-url>              or NOTIFY_DISCORD_WEBHOOK
  telegram:<chat_id>                 with NOTIFY_TELEGRAM_TOKEN (or NOTIFY_TELEGRAM_CHAT_ID)
  stdout                             print only (default when nothing is configured)
Secrets are read from the environment and never printed.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = ("hooks.slack.com", "discord.com", "discordapp.com", "api.telegram.org")


def targets_from_env() -> list[str]:
    out = []
    if os.environ.get("NOTIFY_SLACK_WEBHOOK"):
        out.append("slack:" + os.environ["NOTIFY_SLACK_WEBHOOK"])
    if os.environ.get("NOTIFY_DISCORD_WEBHOOK"):
        out.append("discord:" + os.environ["NOTIFY_DISCORD_WEBHOOK"])
    if os.environ.get("NOTIFY_TELEGRAM_TOKEN") and os.environ.get("NOTIFY_TELEGRAM_CHAT_ID"):
        out.append("telegram:" + os.environ["NOTIFY_TELEGRAM_CHAT_ID"])
    return out


def _post(url: str, payload: dict, timeout: float = 15) -> None:
    host = urllib.parse.urlparse(url).hostname or ""
    if not any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS) and not os.environ.get("NOTIFY_ALLOW_ANY_HOST"):
        raise ValueError(f"refusing to post to {host}: not a Slack/Discord/Telegram host")
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "dulvarn-notify/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - host allowlisted above
        resp.read()



def chunks(text: str, limit: int) -> list[str]:
    parts, cur = [], ""
    for line in text.splitlines(keepends=True):
        if len(cur) + len(line) > limit and cur:
            parts.append(cur)
            cur = ""
        cur += line[:limit]
    if cur:
        parts.append(cur)
    return parts or [""]


def send(text: str, targets: list[str] | None = None, title: str | None = None) -> list[str]:
    """Send markdown-ish text. Returns a list of 'target: error' strings (empty = all delivered)."""
    errors: list[str] = []
    targets = targets if targets is not None else (targets_from_env() or ["stdout"])
    body = f"*{title}*\n{text}" if title else text
    for t in targets:
        kind, _, dest = t.partition(":")
        try:
            if kind == "stdout":
                print(body)
            elif kind == "slack":
                for part in chunks(body, 3500):
                    _post(dest, {"text": part, "mrkdwn": True})
            elif kind == "discord":
                for part in chunks(body.replace("*", "**"), 1900):
                    _post(dest, {"content": part, "allowed_mentions": {"parse": []}})
            elif kind == "telegram":
                token = os.environ.get("NOTIFY_TELEGRAM_TOKEN", "")
                if not token:
                    raise ValueError("NOTIFY_TELEGRAM_TOKEN is not set")
                for part in chunks(body, 3800):
                    _post(f"https://api.telegram.org/bot{token}/sendMessage",
                          {"chat_id": dest, "text": part, "disable_web_page_preview": True})
            else:
                raise ValueError(f"unknown target type '{kind}'")
        except (urllib.error.URLError, ValueError, OSError) as exc:
            # never echo the URL or token: they are secrets
            errors.append(f"{kind}: {exc.__class__.__name__}: {str(exc).split('https://')[0][:120]}")
    return errors
