import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for
)

from werkzeug.utils import secure_filename

from parser import parse_log_file
from detector import run_all_detections
from reporter import (
    generate_summary,
    export_json_report,
    export_alerts_csv
)


app = Flask(__name__)


UPLOAD_FOLDER = "logs"
ALLOWED_EXTENSIONS = {
    "log",
    "txt"
}


app.config[
    "UPLOAD_FOLDER"
] = UPLOAD_FOLDER


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


def analyze_log_file(file_path):
    events = parse_log_file(
        file_path
    )

    alerts = run_all_detections(
        events
    )

    summary = generate_summary(
        events,
        alerts
    )

    export_json_report(
        events,
        alerts,
        summary
    )

    export_alerts_csv(
        alerts
    )

    return (
        events,
        alerts,
        summary
    )


@app.route(
    "/",
    methods=[
        "GET",
        "POST"
    ]
)
def dashboard():

    default_log = os.path.join(
        app.config[
            "UPLOAD_FOLDER"
        ],
        "auth.log"
    )

    selected_file = "auth.log"
    upload_message = None
    upload_error = None

    if request.method == "POST":

        if "log_file" not in request.files:
            upload_error = (
                "No file was selected."
            )

        else:
            file = request.files[
                "log_file"
            ]

            if file.filename == "":
                upload_error = (
                    "Please select a log file."
                )

            elif not allowed_file(
                file.filename
            ):
                upload_error = (
                    "Only .log and .txt "
                    "files are allowed."
                )

            else:
                filename = secure_filename(
                    file.filename
                )

                file_path = os.path.join(
                    app.config[
                        "UPLOAD_FOLDER"
                    ],
                    filename
                )

                file.save(
                    file_path
                )

                selected_file = filename

                try:
                    (
                        events,
                        alerts,
                        summary
                    ) = analyze_log_file(
                        file_path
                    )

                    upload_message = (
                        f"{filename} analyzed "
                        f"successfully."
                    )

                    return render_template(
                        "dashboard.html",
                        events=events,
                        alerts=alerts,
                        summary=summary,
                        selected_file=selected_file,
                        upload_message=upload_message,
                        upload_error=None
                    )

                except Exception as error:
                    upload_error = (
                        f"Analysis failed: "
                        f"{error}"
                    )

    try:
        (
            events,
            alerts,
            summary
        ) = analyze_log_file(
            default_log
        )

    except Exception as error:
        events = []
        alerts = []

        summary = {
            "total_events": 0,
            "successful_logins": 0,
            "failed_logins": 0,
            "unique_alerts": 0,
            "total_alert_occurrences": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "top_suspicious_ip": None,
            "top_suspicious_ip_alerts": 0,
            "top_attacking_ips": [],
            "most_targeted_users": [],
            "mitre_summary": []
        }

        upload_error = (
            f"Could not analyze "
            f"default log: {error}"
        )

    return render_template(
        "dashboard.html",
        events=events,
        alerts=alerts,
        summary=summary,
        selected_file=selected_file,
        upload_message=upload_message,
        upload_error=upload_error
    )


if __name__ == "__main__":

    os.makedirs(
        UPLOAD_FOLDER,
        exist_ok=True
    )

    app.run(
        debug=True
    )