# CyberForge — Final Web Security Platform

Render-ready defensive security assessment web app.

## Modules
- Web Scanner: DNS intelligence, TLS inspection, technology fingerprinting, security headers, risk engine
- File Security: SHA-256/SHA-1/MD5, metadata, conservative static checks, VirusTotal-ready backend
- OSINT: passive domain/IP/DNS intelligence
- AI Security Assistant: finding explanation and remediation prioritization
- Professional Reports: scan IDs and browser-printable report generation

## Run
pip install -r requirements.txt
python app.py

## Render
Build: `pip install -r requirements.txt`
Start: `gunicorn app:app`

Optional environment variable:
`VIRUSTOTAL_API_KEY`

Never expose API keys in frontend code. Use only on files and targets you are authorized to assess.
