"""Interactive HTTPS client for positive and negative local API scenarios."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from getpass import getpass
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent


def request(url: str, context: ssl.SSLContext, method: str, path: str, token: str | None = None, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    raw_body = None
    if body is not None:
        raw_body = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url.rstrip("/") + path, data=raw_body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=8) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        finally:
            exc.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Demo-client HTTPS do lokalnego API.")
    parser.add_argument("scenario", choices=("read", "deny-ack", "ack", "logout"), help="Scenariusz do pokazania.")
    parser.add_argument("--url", default=os.environ.get("API_URL", "https://127.0.0.1:8443"))
    parser.add_argument("--ca", type=Path, default=Path(os.environ.get("TLS_CERT_FILE", str(APP_DIR / "tls" / "dev-cert.pem"))))
    args = parser.parse_args()

    if not args.ca.is_file():
        print(f"Brak certyfikatu CA serwera: {args.ca}", file=sys.stderr)
        return 2
    context = ssl.create_default_context(cafile=str(args.ca))
    username = input("Użytkownik: ").strip()
    password = getpass("Hasło: ")
    try:
        status, result = request(args.url, context, "POST", "/auth/login", body={"username": username, "password": password})
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        print(f"Nie można połączyć się z API: {exc}", file=sys.stderr)
        return 2
    if status != 200:
        print(f"Logowanie: HTTP {status} — {json.dumps(result, ensure_ascii=False)}")
        return 1
    token = result["access_token"]
    print(f"Logowanie: OK, rola {result['role']}, sesja {result['expires_in']} s. Token pozostaje ukryty.")

    paths = {
        "read": ("GET", "/api/telemetry"),
        "deny-ack": ("POST", "/api/alerts/ALT-001/ack"),
        "ack": ("POST", "/api/alerts/ALT-001/ack"),
        "logout": ("POST", "/auth/logout"),
    }
    method, path = paths[args.scenario]
    status, result = request(args.url, context, method, path, token=token, body={} if method == "POST" else None)
    print(f"{args.scenario}: HTTP {status} — {json.dumps(result, ensure_ascii=False)}")
    if args.scenario == "deny-ack":
        return 0 if status == 403 else 1
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
