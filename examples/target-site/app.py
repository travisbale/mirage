import logging
import secrets

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for

app = Flask(__name__)

# In-memory stores — fine for local testing
pending = {}   # pending_token -> email
sessions = {}  # session_token -> email


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        login_source = request.form.get("login_source", "")
        if not login_source:
            error = "Invalid request. Please try again."
        elif email and password:
            token = secrets.token_hex(16)
            pending[token] = email
            resp = make_response(redirect(url_for("mfa")))
            resp.set_cookie("pending_auth", token, httponly=True, samesite="Lax")
            return resp
        error = "Please enter your email and password."
    return render_template("login.html", error=error)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    pending_token = request.cookies.get("pending_auth")
    if not pending_token or pending_token not in pending:
        return redirect(url_for("login"))

    email = pending[pending_token]
    error = None

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if len(code) == 6 and code.isdigit():
            session_token = secrets.token_hex(32)
            sessions[session_token] = pending.pop(pending_token)
            resp = make_response(redirect(url_for("dashboard")))
            resp.delete_cookie("pending_auth")
            resp.set_cookie(
                "auth_session",
                session_token,
                httponly=True,
                samesite="Lax",
                domain=".target.local",
            )
            return resp
        error = "Invalid code. Please try again."

    return render_template("mfa.html", email=email, error=error)


@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("auth_session")
    if not token or token not in sessions:
        return redirect(url_for("login"))
    return render_template("dashboard.html", email=sessions[token])


@app.route("/logout")
def logout():
    token = request.cookies.get("auth_session")
    sessions.pop(token, None)
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("auth_session")
    return resp


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    sent = False
    if request.method == "POST":
        sent = True
    return render_template("forgot.html", sent=sent)


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/settings")
def settings():
    token = request.cookies.get("auth_session")
    if not token or token not in sessions:
        return redirect(url_for("login"))
    return render_template("settings.html", email=sessions[token])


@app.route("/api/telemetry", methods=["POST"])
def api_telemetry():
    data = request.get_json(silent=True) or {}
    app.logger.info("telemetry: %s", data)
    return jsonify({"status": "ok"})


@app.route("/api-login")
def api_login_page():
    return render_template("api_login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    session_token = secrets.token_hex(32)
    access_token = secrets.token_hex(24)
    refresh_token = secrets.token_hex(24)
    sessions[session_token] = email

    resp = make_response(jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }))
    resp.headers["X-Auth-Token"] = f"Bearer {access_token}"
    resp.set_cookie(
        "auth_session",
        session_token,
        httponly=True,
        samesite="Lax",
        domain=".target.local",
    )
    return resp


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=80)
