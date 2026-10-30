# CyberSentinel AI: A Cloud-Based Unified Cyber Threat Detection and Risk Analysis Platform

CyberSentinel AI is an educational Streamlit application for reviewing suspicious URLs, network captures, logs, files, and email. It includes interpretable rules, a demonstration URL classifier, scan history, and analyst workflow features. Findings are triage aids, not proof of compromise or safety.

<h2>Authors</h2>
<ul>
  <li>
    Taniya Thakur —
    <a href="https://github.com/taniyathakur17">@taniyathakur17</a>
  </li>
  <li>
    Yuvraj Sharda —
    <a href="https://github.com/yuvrajsharda11">@yuvrajsharda11</a>
  </li>
  <li>
    Zuhaib Hassan —
    <a href="https://github.com/Zuhaibhassan13">@Zuhaibhassan13</a>
  </li>
</ul>

<h2>License</h2>
<p>
  This project is licensed under the
  <a href="LICENSE">MIT License</a>.
  Third-party materials, including the PhiUSIIL dataset, are governed by
  their own license terms. See
  <a href="ml/data/README.md">the dataset attribution and license details</a>.
</p>

## Features

- Hybrid URL phishing analysis with a Random Forest model, heuristic indicators, evidence strength separate from severity, and model evaluation metadata.
- Passive PCAP summaries, port-scan/beacon/DNS heuristics, plus Isolation Forest flow outlier detection relative to the uploaded capture.
- Security log signatures, IOC extraction, MITRE ATT&CK references, and a natural-language-style assistant that applies transparent filters to saved findings.
- Static file checks and email `.eml` analysis for sender/reply-to mismatch, authentication results, pressure language, and links.
- Local image analysis for screenshots: OCR text extraction, QR payload decoding, and URL triage with the existing URL analyzer. Images and extracted links are not sent to third parties or opened automatically.
- Optional public domain RDAP and VirusTotal reputation lookup. Domain names are sent to those services when a lookup is requested; set `VIRUSTOTAL_API_KEY` to enable VirusTotal.
- Unified scan history, cross-scan repeated-indicator timeline, scan comparison, analyst feedback, audit history, roles, and PDF reports.
- Local Cybersecurity Copilot with a built-in topic guide and explicit general-question or saved-scan context. It does not require scans and does not send chat or scan data to an external AI provider.
- Investigation tracking per scan (status, owner, notes), dashboard filters, and user-controlled deletion of scans older than a selected retention period.
- Investigation records that group account-owned scans under one status, owner, and note set; the Copilot can use the linked scans as one conversation context.
- Cybercrime case records for phishing, payment fraud, account takeover, identity theft, and extortion, with incident timelines, payment/extortion details, and linked analyzer scans.
- Case evidence is stored as private files under `data/evidence`, with a SHA-256 manifest, per-file and per-case storage limits, exact indicator matching across a user's cases, and redacted or evidence-inclusive ZIP exports.
- Email attachment filenames, types, sizes, and SHA-256 hashes are extracted locally. An optional, consent-gated VirusTotal hash lookup shares only the hash, never the file.
- PDF reports include an executive summary, investigation notes, findings from each analyzer, and methodology limitations.
- The bundled PhiUSIIL dataset supports real-data URL evaluation, reproducible domain-grouped splits, phishing precision/recall/F1, ROC-AUC, and a confusion matrix.
- Dashboard and Scan History filters cover date range and risk; repeated indicators drill into the related scans.
- Docker deployment with persistent local data volume and a non-root application user.

## Interface

The UI is a sidebar-navigated workspace. Presentation lives in `ui.py` (theme CSS and reusable components such as the risk verdict panel, stat strips and indicator lists); `app.py` holds page logic. Colours are derived from the active Streamlit theme, so light and dark both work. Switch them from the app's Settings menu. Both themes are defined in `.streamlit/config.toml`. All dynamic values written into HTML are escaped, and email links are shown as plain text. Streamlit 1.50 or newer is required.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python ml/evaluate_url_model.py
export CYBERSENTINEL_ENV=production
export CYBERSENTINEL_ADMIN_USERNAME=admin
printf 'Admin password: '; read -s CYBERSENTINEL_ADMIN_PASSWORD; printf '\n'
export CYBERSENTINEL_ADMIN_PASSWORD
streamlit run app.py
```

The bundled model was trained from PhiUSIIL. `python ml/evaluate_url_model.py` reproduces held-out metrics; `python ml/train_url_model.py` retrains on the bundled labeled dataset and takes a few minutes on a typical laptop. Use `python ml/train_url_model.py --synthetic` only to reproduce the clearly identified teaching baseline. Image OCR requires the Tesseract engine: install it with `brew install tesseract` on macOS or your system package manager on Linux. Docker installs it automatically. If Tesseract is missing, QR decoding and URL extraction from decoded QR codes still work, while OCR displays a notice. A fresh development database seeds `admin` / `admin123`; never expose that demo account to a network. The history-preserving release invalidates that bundled demo password, so set `CYBERSENTINEL_ENV=production`, `CYBERSENTINEL_ADMIN_USERNAME=admin`, and a strong `CYBERSENTINEL_ADMIN_PASSWORD` before launching it directly. Production requires at least 14 characters, including upper- and lowercase letters and a number.

## Run with Docker Compose

Copy `.env.example` to `.env` and set `CYBERSENTINEL_ADMIN_PASSWORD` to a strong unique value before starting; production startup will fail until it is set. For local access, run:

```bash
docker compose up --build
```

The database, generated reports, and cybercrime evidence files are stored under `./data`. In the history-preserving release, the original database is kept under `seed/cybersecurity.db`; on first startup, the app copies it into the configured data directory if no database exists there. Compose defaults to production mode, which disables demo credentials and public account registration, and requires a bootstrap username and strong password. An existing configured bootstrap account is rotated to the password supplied in `.env` on production startup when they differ; keep that secret stable between restarts. Set `CYBERSENTINEL_REGISTRATION_ENABLED=1` only when you intend to allow open sign-up. The app binds to localhost on port 8501. Back up all of `./data` before upgrades; restore by stopping the app, restoring the database, reports, and evidence into `./data`, then starting it again. The included Compose file remains a single-instance educational deployment.

The Docker image also honors a `PORT` environment variable for platforms that assign a service port dynamically; it defaults to 8501 for local use. Persistent storage must be mounted at `/app/data` on hosted platforms or database, report, and evidence files may be lost when an instance is replaced.

### Render deployment

The included `render.yaml` defines a Docker web service, a health check, production credentials supplied in the Render Dashboard, and a 1 GB persistent disk mounted at `/app/data` so the imported scan history, reports, and evidence remain available across restarts. On its first start, the app copies the retained database from `seed/cybersecurity.db` onto that disk. Render requires a paid service plan for persistent disks. Review the plan and disk in Render before creating the service; the Blueprint does not contain an administrator password.

### Optional HTTPS website on a VPS

The optional Caddy profile serves the app over HTTPS and obtains certificates automatically. Before using it, create a Linux VPS, point a DNS A/AAAA record for `CYBERSENTINEL_DOMAIN` to the server, allow inbound TCP ports 80 and 443 (and optionally UDP 443), install Docker Compose, copy the project and `.env` to the server, and set a unique production admin password. Keep `.env` private and do not use the example values. Then run:

```bash
docker compose --profile public up --build -d
```

Visit `https://<your-domain>`. Caddy certificate data is kept in persistent Docker volumes. The SQLite database and reports remain in `./data`; protect and back them up. This single-instance setup is for a small private deployment or demonstration. It does not include multi-user rate limiting, centralized monitoring, managed database backups, or high availability. Do not upload sensitive organizational captures until the server's access controls, retention policy, backups, and update process are in place.

## AI, NLP, and evaluation notes

The URL model uses the UCI PhiUSIIL dataset, with attribution and license details in `ml/data/README.md`. The 80/20 holdout groups normalized registrable domains so domains do not cross partitions. This helps limit domain leakage but is not a temporal external evaluation. Only the URL and label columns are used; webpage-derived attributes are excluded. The previous synthetic metrics remain labeled as a demo baseline.

The Copilot uses a small local reference guide for general cybersecurity questions and evidence retrieval for saved scans. It does not call a hosted language model or provide live threat intelligence. The guide is intentionally bounded; unsupported questions receive a transparent fallback. The separate log assistant uses transparent event filters in response to a small set of natural-language query intents. Flow anomaly detection compares flows within the same capture and can flag unusual but benign traffic. Email checks and domain reputation results are also incomplete signals.

## Safety and privacy

- Uploaded files are statically inspected and are not executed. Keep upload limits and retention controls in place before public use.
- Cybercrime evidence may contain sensitive personal or financial information. It is stored on the server filesystem without application-level encryption; restrict host and backup access, and set a retention policy. SHA-256 hashes help verify file integrity but the local database and audit log are not tamper-proof chain-of-custody systems.
- Cybercrime case indicators can identify exact matches among the signed-in user's cases. Matches are investigative leads, not proof of identity, attribution, or criminal conduct. Case exports default to redacted content; original files are included only when explicitly selected.
- Image analysis limits images to 10 MB and 20 megapixels; OCR is time-limited. QR codes and extracted URLs are displayed for review and never followed automatically.
- PCAP parsing and file inspection are resource-intensive; the application should be deployed with request size and process resource limits.
- Domain lookup is opt-in and requires an explicit checkbox. Domain names are sent to public RDAP and, when configured, VirusTotal.
- The app stores scans, feedback, and audit events in SQLite by default. Protect and back up the data volume; define a retention policy before collecting real user data.
- Scan History includes a user-initiated retention control. Deletion permanently removes the signed-in user's matching scans, feedback, and investigation workflow records; audit events are retained.
- Use HTTPS, strong unique credentials, secret management, and access controls for any hosted demonstration.
- Streamlit upload size is capped at 25 MB, and PCAP parsing is capped at 25 MB and 25,000 packets. Large PCAPs return a truncation notice; do not treat partial capture analysis as complete.
- The Docker Compose service runs read-only with a writable data volume and temporary directory, drops Linux capabilities, and disallows privilege escalation. Retain backups of `./data` outside the host.
