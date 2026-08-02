# Security Policy (سياسة الأمان)

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| main    | ✅ (active)        |

## 🔒 Loopback-only by design

RE-Nexus ships **bound to `127.0.0.1` only**. Several endpoints are
**destructive by nature** (`/api/wipe`, `/api/wipe-dir`, `/api/clean`,
`/api/spectral`, `/api/fork`, `/api/vault/*`, `/api/shield/*`,
`/api/ghost-hide`) and accept arbitrary file paths.

- Keep `HOST=127.0.0.1` (the default). Do **not** expose the server to a
  LAN or the Internet.
- Binding to a non-loopback host prints a loud startup warning and is
  considered an operator error, not a supported deployment mode.
- Request-side guards reject non-loopback clients (`403`) and refuse
  operations on the project root, `server.py`, `README.md`,
  `requirements.txt`, `web/`, and `analyzers/`.

## Reporting a vulnerability

If you find an issue that affects **this project itself** (not the targets
it analyzes), please open a private advisory or contact the maintainer —
do not open a public issue with exploit details.

> ⚠️ This tool is for **authorized security research and education only**.
> Using it against systems you do not own or have explicit permission to
> test is illegal in most jurisdictions. The maintainer assumes no liability
> for misuse.
