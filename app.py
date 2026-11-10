from flask import Flask, render_template, request, redirect, url_for, abort
import ipaddress
import json
import os
import re
import uuid
from datetime import datetime

app = Flask(__name__)

DATA_FILE = os.path.join("data", "investigations.json")

# Only these values are accepted
ALLOWED_SEVERITIES = ["Low", "Medium", "High", "Critical"]
ALLOWED_STATUSES = ["Open", "In Progress", "Escalated", "Closed"]
ALLOWED_IOC_TYPES = ["IP", "Domain", "URL", "Hash"]
ESCALATION_TEAMS = [
    "Tier 2 Analyst",
    "Incident Response Team",
    "SOC Manager",
    "Threat Intelligence Team"
]

MAX_TITLE_LENGTH = 200
MAX_NOTE_LENGTH = 5000
MAX_NAME_LENGTH = 100
MAX_IOC_LENGTH = 2048
MAX_REASON_LENGTH = 1000

# Patterns used to validate input
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
HASH_PATTERN = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")  # MD5, SHA1, SHA256
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")  # e.g. T1059 or T1059.001


#Helpers

def now():
    # Single place to format timestamps
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_cases():
    # Load investigation data from JSON storage

    if not os.path.exists(DATA_FILE):
        return []

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        # Empty or corrupted file: start with no cases instead of crashing
        return []


def save_cases(cases):
    # Save investigation data, creating the data folder if it doesn't exist

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(cases, file, indent=4)


def find_case(cases, case_id):
    # Return the matching case, or None

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    return None


def add_history(case, action):
    # Record an action in the case audit trail
    case.setdefault("history", []).append(
        {
            "timestamp": now(),
            "action": action
        }
    )


def validate_ioc(ioc_type, value):
    # Return the cleaned IOC value if valid, otherwise None

    value = value.strip()

    if not value or len(value) > MAX_IOC_LENGTH:
        return None

    if ioc_type == "IP":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    if ioc_type == "Domain":
        return value.lower() if DOMAIN_PATTERN.match(value) else None

    if ioc_type == "URL":
        return value if value.startswith(("http://", "https://")) else None

    if ioc_type == "Hash":
        return value.lower() if HASH_PATTERN.match(value) else None

    return None


def add_ioc_to_case(case, ioc_type, value):
    # Add an IOC if it isn't already on the case. Returns True if added.

    for ioc in case.setdefault("iocs", []):
        if ioc["type"] == ioc_type and ioc["value"] == value:
            return False

    case["iocs"].append(
        {
            "type": ioc_type,
            "value": value,
            "added": now()
        }
    )
    add_history(case, f"IOC added: {ioc_type} {value}")
    return True


def add_mitre_to_case(case, technique):
    # Add a MITRE ATT&CK technique ID if not already tagged. Returns True if added.

    if technique in case.setdefault("mitre", []):
        return False

    case["mitre"].append(technique)
    add_history(case, f"MITRE ATT&CK technique tagged: {technique}")
    return True


def build_case(title, severity, assigned_to=""):
    # Create a new case dictionary

    created_time = now()

    return {
        "case_id": str(uuid.uuid4())[:8],
        "title": title,
        "severity": severity,
        "status": "Open",
        "assigned_to": assigned_to,
        "created": created_time,
        "notes": [],
        "iocs": [],
        "mitre": [],
        "escalations": [],

        # Keep a history of important investigation actions
        "history": [
            {
                "timestamp": created_time,
                "action": "Case created"
            }
        ]
    }


#Web pages

@app.route("/")
def dashboard():

    cases = load_cases()

    # Dashboard metrics
    def count_status(status):
        return len([case for case in cases if case.get("status") == status])

    high_priority_cases = len(
        [
            case for case in cases
            if case.get("severity") in ["High", "Critical"]
        ]
    )

    return render_template(
        "index.html",
        cases=cases,
        total_cases=len(cases),
        open_cases=count_status("Open"),
        in_progress_cases=count_status("In Progress"),
        escalated_cases=count_status("Escalated"),
        closed_cases=count_status("Closed"),
        high_priority_cases=high_priority_cases
    )


@app.route("/case/<case_id>")
def case_details(case_id):

    case = find_case(load_cases(), case_id)

    if case is None:
        abort(404, description="Case not found")

    return render_template(
        "case.html",
        case=case,
        ioc_types=ALLOWED_IOC_TYPES,
        escalation_teams=ESCALATION_TEAMS
    )


@app.route("/report/<case_id>")
def generate_report(case_id):

    case = find_case(load_cases(), case_id)

    if case is None:
        abort(404, description="Case not found")

    return render_template("report.html", case=case)


#Form actions

@app.route("/create_case", methods=["POST"])
def create_case():

    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "")
    assigned_to = request.form.get("assigned_to", "").strip()

    # Validate input before saving anything
    if not title or len(title) > MAX_TITLE_LENGTH:
        abort(400, description="Title is required (max 200 characters)")

    if severity not in ALLOWED_SEVERITIES:
        abort(400, description="Invalid severity")

    if len(assigned_to) > MAX_NAME_LENGTH:
        abort(400, description="Analyst name too long")

    cases = load_cases()
    cases.append(build_case(title, severity, assigned_to))
    save_cases(cases)

    return redirect(url_for("dashboard"))


@app.route("/update_status", methods=["POST"])
def update_status():

    case_id = request.form.get("case_id", "")
    new_status = request.form.get("status", "")

    if new_status not in ALLOWED_STATUSES:
        abort(400, description="Invalid status")

    # Escalating needs a team and a reason, so it has its own form
    if new_status == "Escalated":
        abort(400, description="Use the Escalate form on the case page to escalate a case")

    cases = load_cases()
    case = find_case(cases, case_id)

    if case is None:
        abort(404, description="Case not found")

    # Only record a change if the status is actually different
    if case.get("status") != new_status:
        old_status = case.get("status")
        case["status"] = new_status
        add_history(case, f"Status changed from {old_status} to {new_status}")
        save_cases(cases)

    return redirect(url_for("dashboard"))


@app.route("/add_note", methods=["POST"])
def add_note():

    case_id = request.form.get("case_id", "")
    note_text = request.form.get("note", "").strip()

    if not note_text or len(note_text) > MAX_NOTE_LENGTH:
        abort(400, description="Note is required (max 5000 characters)")

    cases = load_cases()
    case = find_case(cases, case_id)

    if case is None:
        abort(404, description="Case not found")

    case.setdefault("notes", []).append(
        {
            "timestamp": now(),
            "text": note_text
        }
    )
    add_history(case, "Investigation note added")
    save_cases(cases)

    return redirect(url_for("dashboard"))


@app.route("/escalate", methods=["POST"])
def escalate_case():

    case_id = request.form.get("case_id", "")
    escalated_to = request.form.get("escalated_to", "")
    reason = request.form.get("reason", "").strip()

    # Escalations must go to a known team and always include a reason
    if escalated_to not in ESCALATION_TEAMS:
        abort(400, description="Choose a valid team to escalate to")

    if not reason or len(reason) > MAX_REASON_LENGTH:
        abort(400, description="A reason is required to escalate (max 1000 characters)")

    cases = load_cases()
    case = find_case(cases, case_id)

    if case is None:
        abort(404, description="Case not found")

    if case.get("status") == "Closed":
        abort(400, description="Closed cases can't be escalated")

    old_status = case.get("status")
    case["status"] = "Escalated"

    case.setdefault("escalations", []).append(
        {
            "timestamp": now(),
            "escalated_to": escalated_to,
            "escalated_by": case.get("assigned_to") or "Unassigned",
            "reason": reason
        }
    )

    add_history(case, f"Status changed from {old_status} to Escalated")
    add_history(case, f"Escalated to {escalated_to}: {reason}")
    save_cases(cases)

    return redirect(url_for("case_details", case_id=case_id))


@app.route("/assign", methods=["POST"])
def assign_case():

    case_id = request.form.get("case_id", "")
    analyst = request.form.get("assigned_to", "").strip()

    if len(analyst) > MAX_NAME_LENGTH:
        abort(400, description="Analyst name too long")

    cases = load_cases()
    case = find_case(cases, case_id)

    if case is None:
        abort(404, description="Case not found")

    if case.get("assigned_to", "") != analyst:
        case["assigned_to"] = analyst
        add_history(case, f"Case assigned to {analyst}" if analyst else "Case unassigned")
        save_cases(cases)

    return redirect(url_for("case_details", case_id=case_id))


@app.route("/add_ioc", methods=["POST"])
def add_ioc():

    case_id = request.form.get("case_id", "")
    ioc_type = request.form.get("ioc_type", "")
    value = request.form.get("ioc_value", "")

    if ioc_type not in ALLOWED_IOC_TYPES:
        abort(400, description="Invalid IOC type")

    clean_value = validate_ioc(ioc_type, value)

    if clean_value is None:
        abort(400, description=f"Invalid {ioc_type} value")

    cases = load_cases()
    case = find_case(cases, case_id)

    if case is None:
        abort(404, description="Case not found")

    if add_ioc_to_case(case, ioc_type, clean_value):
        save_cases(cases)

    return redirect(url_for("case_details", case_id=case_id))


@app.route("/add_mitre", methods=["POST"])
def add_mitre():

    case_id = request.form.get("case_id", "")
    technique = request.form.get("technique", "").strip().upper()

    if not MITRE_PATTERN.match(technique):
        abort(400, description="Invalid MITRE technique ID (e.g. T1059 or T1059.001)")

    cases = load_cases()
    case = find_case(cases, case_id)

    if case is None:
        abort(404, description="Case not found")

    if add_mitre_to_case(case, technique):
        save_cases(cases)

    return redirect(url_for("case_details", case_id=case_id))


if __name__ == "__main__":
    # Debug mode is off by default. To turn it on locally, set FLASK_DEBUG=1
    # Never run with debug on where others can reach the app.
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode)
