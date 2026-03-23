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
            resp.set_cookie("pending_auth", token, httponly=True, secure=True, samesite="Lax")
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
                secure=True,
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


@app.route("/demo-complete")
def demo_complete():
    return render_template("demo_complete.html")


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


def _issue_tokens(email, cross_origin=False):
    """Shared logic for JSON token endpoints. Returns a Flask response."""
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
    if cross_origin:
        resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.set_cookie(
        "auth_session",
        session_token,
        httponly=True,
        samesite="None" if cross_origin else "Lax",
        secure=cross_origin,
        domain=".target.local",
    )
    return resp


def _parse_json_credentials():
    """Parse and validate email+password from a JSON request body.
    Returns (email, password) or a (response, status_code) error tuple."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    return email, password


@app.route("/api/login", methods=["POST"])
def api_login():
    result = _parse_json_credentials()
    if not isinstance(result, tuple) or len(result) != 2 or isinstance(result[1], int):
        return result
    email, _ = result
    token = secrets.token_hex(16)
    pending[token] = email
    return jsonify({"pending_token": token, "mfa_required": True})


@app.route("/api/mfa", methods=["POST"])
def api_mfa():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400
    token = data.get("pending_token", "")
    code = data.get("code", "").strip()
    if token not in pending:
        return jsonify({"error": "invalid or expired pending token"}), 400
    if len(code) != 6 or not code.isdigit():
        return jsonify({"error": "invalid code"}), 400
    email = pending.pop(token)
    return _issue_tokens(email)


@app.route("/multi-login")
def multi_login_page():
    return render_template("multi_login.html")


def _cors_preflight():
    """Handle CORS OPTIONS preflight for cross-origin API endpoints."""
    resp = make_response()
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Max-Age"] = "3600"
    return resp


@app.route("/auth", methods=["POST", "OPTIONS"])
def auth():
    """JSON auth endpoint (step 1) for the api host (api.target.local/auth).

    The multi-host phishlet routes api.phish.local/auth → api.target.local/auth.
    Supports CORS preflight so the target site works standalone without the proxy.
    """
    if request.method == "OPTIONS":
        return _cors_preflight()

    result = _parse_json_credentials()
    if not isinstance(result, tuple) or len(result) != 2 or isinstance(result[1], int):
        return result
    email, _ = result
    token = secrets.token_hex(16)
    pending[token] = email
    resp = make_response(jsonify({"pending_token": token, "mfa_required": True}))
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/auth/mfa", methods=["POST", "OPTIONS"])
def auth_mfa():
    """JSON MFA endpoint (step 2) for the api host (api.target.local/auth/mfa)."""
    if request.method == "OPTIONS":
        return _cors_preflight()

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400
    token = data.get("pending_token", "")
    code = data.get("code", "").strip()
    if token not in pending:
        return jsonify({"error": "invalid or expired pending token"}), 400
    if len(code) != 6 or not code.isdigit():
        return jsonify({"error": "invalid code"}), 400
    email = pending.pop(token)
    return _issue_tokens(email, cross_origin=True)


if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)

    cert = "/app/cert.pem"
    key = "/app/key.pem"
    if os.path.exists(cert) and os.path.exists(key):
        app.run(host="0.0.0.0", port=443, ssl_context=(cert, key))
    else:
        app.run(host="0.0.0.0", port=80)
