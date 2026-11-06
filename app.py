from flask import Flask, render_template, request, redirect
import json
import uuid
import os
from datetime import datetime

app = Flask(__name__)

DATA_FILE = "data/investigations.json"


def load_cases():
    """
    Load all investigation cases from storage.
    """

    if not os.path.exists(DATA_FILE):
        return []

    with open(DATA_FILE, "r") as file:
        return json.load(file)


def save_cases(cases):
    """
    Save investigation cases.
    """

    with open(DATA_FILE, "w") as file:
        json.dump(cases, file, indent=4)


@app.route("/")
def dashboard():

    cases = load_cases()

    return render_template(
        "index.html",
        cases=cases
    )


@app.route("/create_case", methods=["POST"])
def create_case():

    cases = load_cases()

    new_case = {
        "case_id": str(uuid.uuid4())[:8],
        "title": request.form["title"],
        "severity": request.form["severity"],
        "status": "Open",
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    cases.append(new_case)

    save_cases(cases)

    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)