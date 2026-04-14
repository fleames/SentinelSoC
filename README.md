# Sentinel

Sentinel is a small **SOC-style live dashboard** for a **Caddy JSON access log** on the same machine. It tails the log file locally (no SSH), aggregates traffic, enriches IPs with ASN/country, scores noisy patterns, and serves a web UI plus JSON for scripting.

## Features

- **Live tail** of a JSON access log with rotation-safe binary reads
- **KPIs and charts**: RPS, status mix, top IPs, hosts, paths, referrers, ASN, country
- **Threat-style board**: scored sources, alert buffer, IP drill-down
- **Mute list** with optional **iptables/ip6tables** DROP sync (`SENTINEL_IPTABLES`)
- **Geo** via [ip-api.com](http://ip-api.com) (async workers; cached)
- **Bot / crawler tags** from User-Agent heuristics
- **Optional HTTP Basic Auth** and append-only **audit** JSONL
- **Persistent state** via `SENTINEL_STATE_DIR` (bans + default audit path outside the app tree)
- Parses **Caddy access** lines mixed with other JSON in the same file when possible; prefers real **`http.log.access`** / **`handled request`** shaped events

## Requirements

- Python 3.10+ (typical)
- Packages: `flask`, `requests`

```bash
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # Linux/macOS
pip install flask requests
```

## Configuration

Environment variables (see `sentinel.env.example` for a full template):

| Variable | Purpose |
|----------|---------|
| `LOG_PATH` | Path to the Caddy **access** JSON log file (default `/var/log/caddy/all-access.log`) |
| `LOG_FROM_START` | If `1` / `true` / `yes` / `on` / `y`, replay the file from the beginning on each start, then follow new lines (heavy on large files) |
| `SENTINEL_STATE_DIR` | Directory for durable data: default `bans.json` and `audit.jsonl` when explicit paths are not set |
| `SENTINEL_BAN_LIST` | Override ban list path; if the key is **absent** and `SENTINEL_STATE_DIR` is set, uses `{STATE_DIR}/bans.json` |
| `SENTINEL_AUDIT_LOG` | Override audit JSONL path; empty with `SENTINEL_STATE_DIR` uses `{STATE_DIR}/audit.jsonl` |
| `SENTINEL_AUDIT_DISABLE` | Set to `1` to disable auditing |
| `SENTINEL_IPTABLES` | Set to `1` to add/remove firewall DROP rules for muted IPs (Linux, needs privileges) |
| `SENTINEL_IPTABLES_CHAIN` | iptables chain name (default `INPUT`) |
| `SENTINEL_AUTH_USER` / `SENTINEL_AUTH_PASSWORD` | If both set, protect `/`, `/data`, and `/api/*` with HTTP Basic Auth (`GET /health` stays open) |

The tail thread **re-reads** `LOG_PATH` and `LOG_FROM_START` from the environment when it starts, so systemd `EnvironmentFile` values apply correctly.

## Run

```bash
python sentinel_soc.py
```

Default listen: `0.0.0.0:5000`.

## systemd

Example unit: `sentinel.service` (adjust `WorkingDirectory`, `ExecStart`, and `ReadWritePaths` for your layout).

- Install env file: copy `sentinel.env.example` to `/etc/sentinel/sentinel.env`, restrict permissions (`chmod 600`), set secrets.
- With `ProtectSystem=strict`, every directory you **write** (app dir, `SENTINEL_STATE_DIR`, Caddy log read path, audit path) must be allowed via `ReadWritePaths` or similar.

## Caddy

- Point `LOG_PATH` at the file your **sites** actually log to. If that file is mostly `admin.api` / startup noise, split logging so **access** lines use a dedicated logger (e.g. `http.log.access`) and avoid duplicating **global** JSON into the same file as site access.
- Behind **Cloudflare**, configure Caddy **`trusted_proxies`** and **`client_ip_headers`** so logs reflect the visitor. Sentinel prefers **`Cf-Connecting-Ip`**, then **`client_ip`**, then **`X-Forwarded-For`**, before falling back to **`remote_ip`**.

Reference Caddyfile snippets: `caddy-recommended.caddyfile`.

## HTTP API

| Method | Path | Notes |
|--------|------|--------|
| GET | `/` | Dashboard UI |
| GET | `/data` | Full JSON snapshot for the UI / export |
| GET | `/health` | Plain `ok` (no auth when Basic Auth is enabled) |
| GET | `/api/ip?ip=…` | Per-IP drill-down (paths, geo, tags) |
| POST | `/api/ban` | JSON body `{"ip":"…"}` or `?ip=` — mute IP |
| POST | `/api/unban` | Unmute IP |
| POST | `/api/reset` | Clear in-memory metrics (tail keeps running) |

When auth is enabled, failed attempts are audited (if auditing is on).

## Optional: GoAccess

`caddy-goaccess-report.sh` is a helper pipeline (jq + GoAccess) for static HTML reports; adjust paths inside the script for your host.

## Troubleshooting

- **`journalctl -u sentinel`** should show lines like `log tail path=…` and `log opened … size=…`. If the log cannot be opened, fix permissions or `ReadWritePaths`.
- **`/data`** includes `log_path`, `log_from_start`, `stream_parse_debug`, `state_dir`, `ban_list_path`, `audit_path` for quick checks.
- **Read-only audit path** under systemd hardening: use `SENTINEL_STATE_DIR` under a writable path, or add the audit directory to `ReadWritePaths`, or remove a bad `SENTINEL_AUDIT_LOG` override.

## License

No license file is bundled; add one if you distribute the project.
