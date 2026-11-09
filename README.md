# SOC Investigation Manager

> Part of the **ThreatHunter SIEM** project, module 4 of 7: Investigation & Case Management.

A case management tool for SOC investigations, built with Python and Flask. Analysts can open cases for security alerts, assign them, track their status, record findings, attach indicators of compromise (IOCs), tag MITRE ATT&CK techniques and generate a report. Every action is recorded in an audit trail.

## Features

- **Dashboard metrics:** total, open, in progress, escalated, closed and high/critical cases at a glance
- **Case creation:** title, severity (Low, Medium, High, Critical) and an optional assigned analyst
- **Status tracking:** Open → In Progress → Escalated → Closed
- **Analyst assignment:** assign or reassign cases
- **Investigation notes:** timestamped findings added to each case
- **IOCs:** record IPs, domains, URLs and file hashes (MD5, SHA1, SHA256), each validated before saving, with duplicates ignored
- **MITRE ATT&CK tagging:** tag techniques such as `T1059.001`, each linking to its page on the MITRE ATT&CK site
- **Audit trail:** every action (creation, assignment, status changes, notes, IOCs, techniques) is logged with a timestamp
- **Case view and report:** a full case page and a printable investigation report

## Screenshots

### 1. Case creation and dashboard
<img src="screenshots/commit1_case_creation_dashboard.png" alt="Case creation and dashboard" width="700" />

### 2. Status management
<img src="screenshots/commit2_status_management.png" alt="Status management" width="700" />

### 3. Investigation notes
<img src="screenshots/commit3_investigation_notes.png" alt="Investigation notes" width="700" />

### 4. Case history timeline
<img src="screenshots/commit4_case_history_timeline.png" alt="Case history timeline" width="700" />

### 5. Case details view
<img src="screenshots/commit5_case_details_view.png" alt="Case details view" width="700" />

### 6. Investigation report
<img src="screenshots/commit6_investigation_report.png" alt="Investigation report" width="700" />

### 7. SOC metrics dashboard
<img src="screenshots/commit7_soc_metrics_dashboard.png" alt="SOC metrics dashboard" width="700" />

## Running it locally

```bash
git clone https://github.com/Maliyka-L/Investigation_Manager.git
cd Investigation_Manager
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

To turn on Flask debug mode while developing, set `FLASK_DEBUG=1` first. Debug mode is off by default because Flask's debugger can run code, so it must never be enabled where other people can reach the app.

## How it works

- Cases are stored in `data/investigations.json`
- All input is validated: severity, status and IOC type must be allowed values; IPs are checked with Python's `ipaddress` module; domains, hashes and MITRE IDs are checked with patterns; and titles, notes and names have length limits
- Jinja2 auto-escaping stops user-entered text from being run as HTML or JavaScript (XSS)
- Missing cases return a 404 rather than failing silently

## Project structure

```
Investigation_Manager/
├── app.py
├── requirements.txt
├── data/
│   └── investigations.json   # sample case
├── screenshots/               # images used in this README
└── templates/
    ├── index.html             # dashboard
    ├── case.html              # case details, IOCs, MITRE, assignment
    └── report.html            # investigation report
```

## Security notes

This is a local, single-user portfolio project. Before using it anywhere shared, it would need:

- User login and role-based access
- CSRF protection on web forms (for example Flask-WTF)
- A database instead of a JSON file, to handle several users safely

## ThreatHunter SIEM roadmap

1. Log Analysis ✅ ([log_parser_alerting_tool](https://github.com/Maliyka-L/log_parser_alerting_tool))
2. Alert Engine ✅ ([alert_engine](https://github.com/Maliyka-L/alert_engine))
3. Threat Intelligence ✅ ([Threat_Intelligence_module](https://github.com/Maliyka-L/Threat_Intelligence_module))
4. Investigation ✅ (this repo)
5. Case Management ✅ (this repo: IOCs, MITRE tagging, analyst assignment)
6. Dashboard
7. SIEM Integration

## Future improvements

- Search and filtering on the dashboard
- Exporting reports to PDF

## What I learned

_Add 3–5 points here, for example how an audit trail supports investigations, or validating user input in Flask._
