from flask import Flask, render_template, request
from analyser import analyse

app = Flask(__name__)

MAX_INPUT_LENGTH = 100_000  # headers are rarely bigger than this


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    raw = ""

    if request.method == "POST":
        raw = request.form.get("headers", "")

        if not raw.strip():
            error = "Please paste some email headers."
        elif len(raw) > MAX_INPUT_LENGTH:
            error = "That's too long. Paste only the headers (under 100,000 characters)."
        else:
            result = analyse(raw)
            if not result["hops"] and not result["summary"]["From"]:
                error = "No email headers found. Check that you pasted the raw headers."
                result = None

    return render_template("index.html", result=result, error=error, raw=raw)


if __name__ == "__main__":
    # Localhost only, debug off - same safe settings as your other projects
    app.run(host="127.0.0.1", port=5002, debug=False)
