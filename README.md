# RE-Nexus — عرين النكسس

**Local reverse-engineering lab with 29 analysis & live-system engines.**

A self-contained, local-first toolbelt for malware triage and reverse
engineering: unpack nested payloads, hunt keys in memory, analyze PCAP
traffic, fingerprint compilers, patch anti-debug checks, and manage files
with AES-GCM encryption — all from a single web dashboard bound to
`127.0.0.1`.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![CI](https://img.shields.io/github/actions/workflow/status/YOUR_USERNAME/re-nexus/ci.yml?label=CI)

> ⚠️ **For authorized security research and education only.** This project
> contains tools and test fixtures for analyzing malware. Use it only on
> systems you own or have explicit permission to test.

---

## 🚀 Quick start

```bat
:: Windows — installs missing deps, then starts the server
start.bat

:: Or manually (from the project root)
pip install -r requirements.txt
python -m app.server
```

Then open **http://127.0.0.1:8787/**

| Env var | Default | Description |
| ------- | ------- | ----------- |
| `HOST`  | `127.0.0.1` | Bind address. **Keep loopback.** |
| `PORT`  | `8787`      | Listen port. |

## 🧩 Engines (29)

### Core analysis (20)

| # | Engine | العربية | What it does |
| - | ------ | -------- | ------------ |
| 1 | Shell Ripper | تمزيق الأصداف | Recursive layered-file peel + entropy prediction |
| 2 | Blind Key Trap | مصيدة المفاتيح العمياء | Register/stack-frame key hunt with RAM cache — or live PID read |
| 3 | Network RE | محلل الشبكة | PCAP protocol / C2 classification + live network view |
| 4 | Reverse Timestamp | البصمة الزمنية المعكوسة | Compiler fingerprint → CVE candidate links |
| 5 | Sovereignty Crusher | محطم السيادة | Anti-debug / timestamp / `IsDebuggerPresent` detection + patcher |
| 6 | Tetra Cube | المكعب الرباعي | 4-D attack surface: time, memory, registers, I/O rings |
| 7 | Ghost Spectrum | الطيف الخفي | PEB/ELF header patch (cache-only playback) |
| 8 | Ant Colony | مستعمرة النمل | 10K virtual threads, weakest-jump hunt in ~300 ms |
| 9 | Brain-Link | الوصلة الدماغية | Pseudo-C prediction under hostile debuggers |
| 10 | Kamikaze Engine | المحرك الانتحاري | 500 micro-process reassembly across cores |
| 11 | Shattered Mind | العقل المتشظي | 1000 fragments across threads, CFG in ~400 ms |
| 12 | Blackhole Engineer | ثقب الهندسة الأسود | ETW capture + pre-deletion from buffer |
| 13 | Speculative Injector | الحاقن التخميني | Spectre-v2 style branch-injection analysis |
| 14 | Compiler Flipper | مقلب المترجم | JIT AST sink tracing (`eval`/`exec`/…) |
| 15 | Weighted Future | المستقبل الموزون | LSTM-style register prediction ahead of execution |
| 16 | Register Puzzle | أحجية السجل | XMM drift key reconstruction |
| 17 | Silent Plague | الطاعون الصامت | SMRAM/ACPI persistence analysis |
| 18 | Author | إسناد المؤلف | Language/author attribution heuristics |
| 19 | Spectral Scan | الماسح الطيفي | Archive-scrubbing / sanitization analysis |
| 20 | Combi Scan | مسح كومبي | Full system sweep in one request |

### Elite dashboard (9)

| Engine | العربية | What it does |
| ------ | -------- | ------------ |
| Digital Fingerprint | البصمة الرقمية | Device fingerprint (MAC / host / user / OS) |
| Port Scanner | ماسح المنافذ الداخلي | Local open-port scan |
| Process Monitor | مراقب العمليات | Live process list + memory read |
| File Encryptor | مشفر الملفات | One-click AES-256-GCM encrypt/decrypt |
| Stealth Tasks | مدير المهام الخفي | Background-load monitor |
| Event Log | سجل الأحداث | Interactive server event feed |
| Speculative Brute | الاختراق التخميني | Weak-password audit for encrypted samples |
| Accelerator | مسرع الأداء | Local performance tuning (dry-run by default) |
| Secret Browser | مستعرض الملفات السري | Loopback-only file browser |

### Visual layer

- Glass-morphism sidebar with 1px cyan borders
- Quantum Blur overlay for sensitive modules
- Fragrance Board — live entropy gauge
- Flame Strip — CPU/RAM real-time chart
- 3D scene (`three.js` via CDN) showing engine activity

## 📁 Project layout

```
re-nexus/
├── app/                 # Application package
│   ├── server.py        #   Flask app: 29 engine routes + guards (entry point)
│   ├── singleshot.py    #   Dependency-free asyncio WSGI server (single-sendall + gzip)
│   └── engines/         #   37 engine modules as a package
├── web/                 # Static dashboard (HTML/CSS/JS, three.js)
├── samples/             # Synthetic test fixtures (NOT real malware)
├── .github/workflows/    # CI (syntax check + import smoke test)
├── start.bat            # Windows launcher (installs deps, starts server)
├── requirements.txt
├── SECURITY.md
└── LICENSE
```

## 🔌 API (highlights)

| Method | Endpoint | Purpose |
| ------ | -------- | ------- |
| GET | `/api/health` | Status, uptime, engine list |
| GET | `/api/metrics` | CPU/RAM host metrics (TTL-cached) |
| POST | `/api/shell-ripper` | Unpack nested payloads (multipart upload) |
| POST | `/api/sovereignty` | Anti-analysis scan / bypass patch |
| POST | `/api/memory` | Hunt keys in a file or a live PID |
| POST | `/api/network` | Analyze a PCAP upload |
| POST | `/api/decrypt-probe` | Try decrypting a sample with a candidate key |
| POST | `/api/dash/encrypt` | Encrypt a file (AES-GCM) |
| GET | `/api/dash/browse` | List files (loopback only) |
| GET | `/api/dash/status` | Aggregated dashboard snapshot |

Every engine returns JSON (`{"ok": true, ...}` or `{"ok": false, "error": …}`).
Uploads cap at **48 MB** (`MAX_BODY` in `singleshot.py` is the single source
of truth).

## 🔒 Security & hardening

- The server **only binds to loopback** by default; destructive endpoints
  require loopback clients (403 otherwise) and refuse to touch the project
  root, `app/` (including the engine package), `web/`, `README.md`,
  `LICENSE`, `requirements.txt`, and `.git`.
- `singleshot.py` is a dependency-free WSGI server that buffers the full
  response and transmits it in one `sendall()` (with gzip for JSON/text
  bodies > 1 KB), which avoids header/body-split delivery bugs on
  restrictive stacks.
- File encryption uses **AES-256-GCM** (`cryptography`), passphrase
  hardening via Argon2id (`dimensional_shield.py`), and vault/stego
  storage formats that include per-block nonces.
- See **[SECURITY.md](SECURITY.md)** for the full policy.

## 🧪 Test fixtures

Everything under `samples/` is **synthetic, generated for testing** —
fake RSA keys, placeholder tokens (`ghp_AAAAAAAA…`), and a tiny stub PE
with anti-debug strings. No real credentials or malware.

## 🛠 Tech

- Python 3.9+, Flask, Werkzeug, psutil, cryptography
- asyncio single-sendall WSGI server (stdlib only)
- Vanilla JS dashboard + `three.js` (CDN)

## 📄 License

[MIT](LICENSE) © 2026 YAZAN
