# expiry-radar

**Know 30 days before a certificate, domain, token or licence expires** — not when production goes down.

```bash
python3 expiry_radar.py expiry.yml                         # table
python3 expiry_radar.py expiry.yml --state .state.json     # alert once per threshold (cron / CI)
NOTIFY_TELEGRAM_TOKEN=… NOTIFY_TELEGRAM_CHAT_ID=… python3 expiry_radar.py expiry.yml
```

| Type | How it is checked |
|---|---|
| `tls` | connects, validates chain + hostname, reads `notAfter`; a broken chain is reported as critical even if the date is fine |
| `domain` | RDAP (no API key) — some ccTLDs do not publish dates: use `manual` |
| `github-token` | reads the token's expiry header from the GitHub API (token from an env var) |
| `manual` | API keys, licences, Apple/Google certificates, SAML certs — anything with a date |

Thresholds default to 30 / 14 / 7 / 1 days; ≤ 7 days is critical. Each alert names the owner and links the runbook.

**Alerts:** Slack (incoming webhook), Discord (webhook) or Telegram (bot token + chat id) via environment variables, or `--notify slack:URL`. With `--state`, each item alerts once per threshold; expired and broken items repeat daily.

**Secrets:** the inventory contains names and dates only. Tokens are read from environment variables and never printed.

See `expiry.example.yml` and `examples/expiry-radar.yml` (GitHub Actions, daily). Python 3.10+, PyYAML only for YAML inventories (JSON works without it). MIT License.

## About

Built by **Ján Ďuriš**, QA Automation Engineer (Playwright, Python, CI/CD). Part of a small set of open tools for release quality: [release-ready](https://github.com/JankoD84/release-ready) · [gates-doctor](https://github.com/JankoD84/gates-doctor) · [flaky-playwright-lab](https://github.com/JankoD84/flaky-playwright-lab) · [oncall-rota](https://github.com/JankoD84/oncall-rota) · [expiry-radar](https://github.com/JankoD84/expiry-radar) · [dependabot-tamer](https://github.com/JankoD84/dependabot-tamer)

Flaky tests, slow CI or releases nobody trusts? Find me on [Upwork](https://www.upwork.com/freelancers/~0198692795e824559b) or [LinkedIn](https://www.linkedin.com/in/jduris).
