"""
NR Labs - Demo Web Application
================================
A simple Flask web app deployed to AWS ECS Fargate.
This app exists solely to demonstrate the CI/CD evidence pipeline:
  - GitHub Actions runs SAST/DAST/dependency scans against this app
  - Scan results are pushed to the CI/CD evidence ingest Lambda
  - Evidence flows into the GRC Engineering pipeline

The app intentionally includes some scannable patterns for demo purposes.
"""

import os
import logging
from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Intentionally scannable: hardcoded value (Bandit will flag this)
DEMO_API_KEY = "demo-key-not-real-12345"  # nosec B105 - intentional for demo


@app.route("/")
def index():
    """Landing page."""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head><title>NR Labs GRC Demo App</title></head>
    <body>
        <h1>NR Labs GRC Engineering Demo Application</h1>
        <p>This application demonstrates the CI/CD evidence pipeline.</p>
        <ul>
            <li><a href="/health">/health</a> - Health check</li>
            <li><a href="/api/status">/api/status</a> - Application status</li>
            <li><a href="/api/info">/api/info</a> - System info</li>
        </ul>
        <hr>
        <p><em>Part of the NR Labs GRC Engineering Landing Zone prototype.</em></p>
    </body>
    </html>
    """)


@app.route("/health")
def health():
    """Health check endpoint for ECS/ALB."""
    return jsonify({"status": "healthy", "service": "grc-demo-app"})


@app.route("/api/status")
def status():
    """Application status endpoint."""
    return jsonify({
        "application": "NR Labs GRC Demo App",
        "version": "0.1.0",
        "environment": os.environ.get("ENVIRONMENT", "dev"),
        "status": "running",
    })


@app.route("/api/info")
def info():
    """System info endpoint."""
    # Intentionally scannable: returns some system info (Semgrep may flag)
    return jsonify({
        "python_version": os.sys.version,
        "platform": os.sys.platform,
        "hostname": os.environ.get("HOSTNAME", "unknown"),
    })


@app.route("/api/data", methods=["POST"])
def receive_data():
    """Receive data endpoint."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    # Intentionally scannable: no input validation (SAST will flag)
    app.logger.info(f"Received data: {data}")
    return jsonify({"received": True, "echo": data})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
