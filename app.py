from flask import Flask, render_template, request, redirect
import json
import uuid
import os
from datetime import datetime

app = Flask(__name__)

DATA_FILE = "data/investigations.json"


def load_cases():
    # Load all investigation cases from storage

    if not os.path.exists(DATA_FILE):
        return []

    with open(DATA_FILE, "r") as file:
        return json.load(file)


def save_cases(cases):
    # Save investigation data

    with open(DATA_FILE, "w") as file:
        json.dump(cases, file, indent=4)


@app.route("/")
def dashboard():

    cases = load_cases()

    return render_template(
        "index.html",
        cases=cases
    )


@app.route("/case/<case_id>")
def case_details(case_id):

    cases = load_cases()

    for case in cases:

        if case["case_id"] == case_id:

            return render_template(
                "case.html",
                case=case
            )

    return "Case not found"


@app.route("/create_case", methods=["POST"])
def create_case():

    cases = load_cases()

    created_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    new_case = {
        "case_id": str(uuid.uuid4())[:8],
        "title": request.form["title"],
        "severity": request.form["severity"],
        "status": "Open",
        "created": created_time,
        "notes": [],

        # Store important events for auditing
        "history": [
            {
                "timestamp": created_time,
                "action": "Case created"
            }
        ]
    }

    cases.append(new_case)

    save_cases(cases)

    return redirect("/")


@app.route("/update_status", methods=["POST"])
def update_status():

    case_id = request.form["case_id"]
    new_status = request.form["status"]

    cases = load_cases()

    for case in cases:

        if case["case_id"] == case_id:

            case["status"] = new_status

            # Record status changes in the timeline
            case.setdefault("history", []).append(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": f"Status changed to {new_status}"
                }
            )

            break

    save_cases(cases)

    return redirect("/")


@app.route("/add_note", methods=["POST"])
def add_note():

    case_id = request.form["case_id"]
    note_text = request.form["note"]

    cases = load_cases()

    for case in cases:

        if case["case_id"] == case_id:

            note = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "text": note_text
            }

            case.setdefault("notes", [])
            case["notes"].append(note)

            # Log note activity in the audit trail
            case.setdefault("history", []).append(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "Investigation note added"
                }
            )

            break

    save_cases(cases)

    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)