"""Hardened version of the KodeBox sample app.

Changes from ~/devsecops/app.py:
  * Settings come from environment variables, never from a file baked into the image.
  * A /healthz endpoint for the container HEALTHCHECK and for Kubernetes probes.
  * Served by gunicorn (see the Dockerfile), not the Flask development server.
"""
import os

from flask import Flask, jsonify

app = Flask(__name__)
APP_ENV = os.environ.get("APP_ENV", "production")


@app.get("/")
def index():
    return f"Hello from the KodeBox DevSecOps lab (hardened, env={APP_ENV})\n"


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
