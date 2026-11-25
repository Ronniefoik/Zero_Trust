"""Small, standard-library-only local API for a zero-trust hybrid demo."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from getpass import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
DEFAULT_USERS_FILE = APP_DIR / "data" / "users.json"
DEFAULT_AUDIT_FILE = APP_DIR / "logs" / "audit.jsonl"
DEFAULT_CERT_FILE = APP_DIR / "tls" / "dev-cert.pem"
DEFAULT_KEY_FILE = APP_DIR / "tls" / "dev-key.pem"

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "audytor": frozenset({"telemetry:read", "alerts:read"}),
    "operator": frozenset({"telemetry:read", "alerts:read", "alerts:ack"}),
}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
TOKEN_ISSUER = "local-api-demo"
TOKEN_AUDIENCE = "business-api"
TOKEN_TTL_SECONDS = 600
MAX_BODY_BYTES = 4096
LOGIN_WINDOW_SECONDS = 60
LOGIN_ALERT_THRESHOLD = 3
LOGIN_BLOCK_THRESHOLD = 5


class ConfigurationError(Exception):
    """Raised when the service cannot start with the supplied settings."""


class AuthenticationError(Exception):
    """Raised for a missing, invalid, expired, or revoked session."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return base64 salt and a slow scrypt hash; raw passwords are never saved."""
    if len(password) < 12:
        raise ValueError("Hasło musi mieć co najmniej 12 znaków.")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return _b64url_encode(salt), _b64url_encode(digest)


def verify_password(password: str, salt_text: str, hash_text: str) -> bool:
    try:
        salt = _b64url_decode(salt_text)
        expected = _b64url_decode(hash_text)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def issue_token(username: str, role: str, secret: bytes, now: int | None = None) -> str:
    if role not in ROLE_SCOPES:
        raise ValueError("Nieznana rola.")
    current = int(time.time()) if now is None else now
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": username,
        "role": role,
        "jti": secrets.token_urlsafe(18),
        "iat": current,
        "exp": current + TOKEN_TTL_SECONDS,
    }
    signing_input = f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def verify_token(token: str, secret: bytes, revoked: set[str], now: int | None = None) -> dict[str, Any]:
    try:
        header_text, payload_text, signature_text = token.split(".")
        signing_input = f"{header_text}.{payload_text}"
        expected = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        actual = _b64url_decode(signature_text)
        if not hmac.compare_digest(actual, expected):
            raise AuthenticationError("Nieprawidłowy token.")
        header = json.loads(_b64url_decode(header_text))
        payload = json.loads(_b64url_decode(payload_text))
        current = int(time.time()) if now is None else now
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise AuthenticationError("Nieobsługiwany token.")
        if payload.get("iss") != TOKEN_ISSUER or payload.get("aud") != TOKEN_AUDIENCE:
            raise AuthenticationError("Nieprawidłowe przeznaczenie tokenu.")
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= current:
            raise AuthenticationError("Sesja wygasła.")
        if not isinstance(payload.get("iat"), int) or payload["iat"] > current + 30:
            raise AuthenticationError("Nieprawidłowy czas tokenu.")
        if payload.get("role") not in ROLE_SCOPES or not USERNAME_RE.fullmatch(str(payload.get("sub", ""))):
            raise AuthenticationError("Nieprawidłowa tożsamość tokenu.")
        if not isinstance(payload.get("jti"), str) or payload["jti"] in revoked:
            raise AuthenticationError("Sesja została zamknięta.")
        return payload
    except AuthenticationError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError("Nieprawidłowy token.") from exc


def parse_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for item in value.split(","):
        item = item.strip()
        if item:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError as exc:
                raise ConfigurationError(f"Nieprawidłowa sieć CIDR: {item}") from exc
    if not networks:
        raise ConfigurationError("Lista dozwolonych sieci nie może być pusta.")
    return tuple(networks)


def address_is_allowed(address: str, networks: tuple[Any, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip.version == network.version and ip in network for network in networks)
    except ValueError:
        return False


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    allowed_networks: tuple[Any, ...]
    gateway_networks: tuple[Any, ...]
    auth_mode: str
    session_secret: bytes | None
    users_file: Path
    audit_file: Path
    cert_file: Path
    key_file: Path
    client_ca_file: Path | None

    @classmethod
    def from_env(cls) -> "Settings":
        auth_mode = os.environ.get("AUTH_MODE", "local").strip().lower()
        if auth_mode not in {"local", "trusted_gateway"}:
            raise ConfigurationError("AUTH_MODE musi mieć wartość local albo trusted_gateway.")
        host = os.environ.get("API_BIND_HOST", "127.0.0.1").strip()
        try:
            ipaddress.ip_address(host)
            port = int(os.environ.get("API_PORT", "8443"))
        except ValueError as exc:
            raise ConfigurationError("API_BIND_HOST musi być adresem IP, a API_PORT liczbą 1–65535.") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError("API_PORT musi być w zakresie 1–65535.")
        allowed = parse_networks(os.environ.get("API_ALLOWED_NETWORKS", "127.0.0.1/32,::1/128"))
        gateway_text = os.environ.get("TRUSTED_GATEWAY_NETWORKS", "")
        gateway_networks = parse_networks(gateway_text) if gateway_text.strip() else ()
        secret_text = os.environ.get("SESSION_SECRET", "")
        session_secret = secret_text.encode("utf-8") if secret_text else None
        if auth_mode == "local" and (session_secret is None or len(session_secret) < 32):
            raise ConfigurationError("Ustaw SESSION_SECRET (co najmniej 32 bajty); start_demo.ps1 robi to za Ciebie.")
        client_ca = os.environ.get("TLS_CLIENT_CA", "").strip()
        if auth_mode == "trusted_gateway":
            if not gateway_networks:
                raise ConfigurationError("Tryb trusted_gateway wymaga TRUSTED_GATEWAY_NETWORKS.")
            if not client_ca:
                raise ConfigurationError("Tryb trusted_gateway wymaga certyfikatu CA w TLS_CLIENT_CA (mTLS).")
            if not all(any(network.version == allowed_net.version and network.subnet_of(allowed_net) for allowed_net in allowed) for network in gateway_networks):
                raise ConfigurationError("TRUSTED_GATEWAY_NETWORKS muszą zawierać się w API_ALLOWED_NETWORKS.")
        return cls(
            host=host,
            port=port,
            allowed_networks=allowed,
            gateway_networks=gateway_networks,
            auth_mode=auth_mode,
            session_secret=session_secret,
            users_file=Path(os.environ.get("API_USERS_FILE", str(DEFAULT_USERS_FILE))),
            audit_file=Path(os.environ.get("API_AUDIT_FILE", str(DEFAULT_AUDIT_FILE))),
            cert_file=Path(os.environ.get("TLS_CERT_FILE", str(DEFAULT_CERT_FILE))),
            key_file=Path(os.environ.get("TLS_KEY_FILE", str(DEFAULT_KEY_FILE))),
            client_ca_file=Path(client_ca) if client_ca else None,
        )


class AuditLog:
    """JSON-lines audit events go to a rotating file and stdout for log shipping."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(f"local_api_audit_{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        formatter = logging.Formatter("%(message)s")
        file_handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=4, encoding="utf-8")
        stream_handler = logging.StreamHandler(sys.stdout)
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)
        self._lock = threading.Lock()

    def event(self, name: str, severity: str = "info", **fields: Any) -> None:
        record = {"timestamp": utc_now(), "event": name, "severity": severity, **fields}
        # Callers only pass bounded identifiers and metadata, never credentials or tokens.
        with self._lock:
            self.logger.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))

    def close(self) -> None:
        with self._lock:
            for handler in tuple(self.logger.handlers):
                self.logger.removeHandler(handler)
                handler.close()


class LoginMonitor:
    """Rate limit by source and emit an alert when failures correlate in a short window."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, peer: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            queue = self._failures[peer]
            while queue and current - queue[0] > LOGIN_WINDOW_SECONDS:
                queue.popleft()
            return len(queue) >= LOGIN_BLOCK_THRESHOLD

    def failed(self, peer: str, audit: AuditLog, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            queue = self._failures[peer]
            while queue and current - queue[0] > LOGIN_WINDOW_SECONDS:
                queue.popleft()
            queue.append(current)
            count = len(queue)
            last_alert = self._last_alert.get(peer, 0.0)
            emit_alert = count >= LOGIN_ALERT_THRESHOLD and current - last_alert > LOGIN_WINDOW_SECONDS
            if emit_alert:
                self._last_alert[peer] = current
        if emit_alert:
            audit.event("login_anomaly", "warning", source_ip=peer, failed_attempts=count, window_seconds=LOGIN_WINDOW_SECONDS, detector="correlated_failure_threshold")

    def succeeded(self, peer: str) -> None:
        with self._lock:
            self._failures.pop(peer, None)
            self._last_alert.pop(peer, None)


class ServiceState:
    def __init__(self) -> None:
        self.revoked_tokens: set[str] = set()
        self.alert_status = "otwarty"
        self.lock = threading.RLock()
        self.login_monitor = LoginMonitor()


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, settings: Settings, users: dict[str, dict[str, str]], audit: AuditLog):
        self.settings = settings
        self.users = users
        self.audit = audit
        self.state = ServiceState()
        super().__init__((settings.host, settings.port), ApiHandler)


class ApiHandler(BaseHTTPRequestHandler):
    server: ApiServer
    protocol_version = "HTTP/1.1"
    server_version = "LocalBusinessAPI"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        # Default access logging can accidentally record query strings or credentials.
        return

    @property
    def peer_ip(self) -> str:
        return self.client_address[0]

    def _json(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid_content_length"})
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413 if length > MAX_BODY_BYTES else 400, {"error": "invalid_request_size"})
            return None
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "invalid_json"})
            return None
        if not isinstance(value, dict):
            self._json(400, {"error": "json_object_required"})
            return None
        return value

    def _network_allowed(self) -> bool:
        if address_is_allowed(self.peer_ip, self.server.settings.allowed_networks):
            return True
        self.server.audit.event("network_access_denied", "warning", source_ip=self.peer_ip, path=self.path[:128])
        self._json(403, {"error": "network_not_allowed"})
        return False

    def _principal(self) -> dict[str, str] | None:
        settings = self.server.settings
        if settings.auth_mode == "trusted_gateway":
            if not address_is_allowed(self.peer_ip, settings.gateway_networks):
                self.server.audit.event("gateway_identity_denied", "warning", source_ip=self.peer_ip)
                self._json(403, {"error": "trusted_gateway_required"})
                return None
            username = self.headers.get("X-Authenticated-User", "")
            role = self.headers.get("X-Authenticated-Role", "")
            if not USERNAME_RE.fullmatch(username) or role not in ROLE_SCOPES:
                self.server.audit.event("gateway_identity_invalid", "warning", source_ip=self.peer_ip)
                self._json(401, {"error": "authenticated_gateway_identity_required"})
                return None
            return {"sub": username, "role": role, "jti": "gateway-session"}

        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer ") or settings.session_secret is None:
            self._json(401, {"error": "authentication_required"})
            return None
        try:
            with self.server.state.lock:
                payload = verify_token(authorization[7:], settings.session_secret, self.server.state.revoked_tokens)
            return {"sub": payload["sub"], "role": payload["role"], "jti": payload["jti"]}
        except AuthenticationError:
            self._json(401, {"error": "invalid_or_expired_session"})
            return None

    def _authorize(self, scope: str) -> dict[str, str] | None:
        if not self._network_allowed():
            return None
        principal = self._principal()
        if principal is None:
            return None
        if scope not in ROLE_SCOPES[principal["role"]]:
            self.server.audit.event(
                "authorization_denied",
                "warning",
                actor=principal["sub"],
                role=principal["role"],
                required_scope=scope,
                path=self.path[:128],
                source_ip=self.peer_ip,
            )
            self._json(403, {"error": "insufficient_scope", "required_scope": scope})
            return None
        return principal

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if not self._network_allowed():
            return
        if self.path == "/healthz":
            self._json(200, {"status": "ok", "service": "local-business-api"})
            return
        if self.path == "/api/telemetry":
            principal = self._authorize("telemetry:read")
            if principal is None:
                return
            self.server.audit.event("telemetry_read", actor=principal["sub"], role=principal["role"], source_ip=self.peer_ip)
            self._json(200, {"items": [{"id": "local-api-01", "stan": "działa", "segment": "lokalny", "last_check": utc_now()}]})
            return
        if self.path == "/api/alerts":
            principal = self._authorize("alerts:read")
            if principal is None:
                return
            with self.server.state.lock:
                status = self.server.state.alert_status
            self.server.audit.event("alerts_read", actor=principal["sub"], role=principal["role"], source_ip=self.peer_ip)
            self._json(200, {"items": [{"id": "ALT-001", "severity": "medium", "summary": "Trzy nieudane próby logowania w krótkim czasie", "status": status}]})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if not self._network_allowed():
            return
        if self.path == "/auth/login":
            self._login()
            return
        if self.path == "/auth/logout":
            if self.server.settings.auth_mode != "local":
                self._json(404, {"error": "not_found"})
                return
            principal = self._principal()
            if principal is None:
                return
            with self.server.state.lock:
                self.server.state.revoked_tokens.add(principal["jti"])
            self.server.audit.event("session_closed", actor=principal["sub"], source_ip=self.peer_ip)
            self._json(200, {"status": "session_closed"})
            return
        match = re.fullmatch(r"/api/alerts/([A-Za-z0-9_-]{1,32})/ack", self.path)
        if match:
            principal = self._authorize("alerts:ack")
            if principal is None:
                return
            if match.group(1) != "ALT-001":
                self._json(404, {"error": "alert_not_found"})
                return
            with self.server.state.lock:
                self.server.state.alert_status = "potwierdzony"
            self.server.audit.event("alert_acknowledged", actor=principal["sub"], role=principal["role"], alert_id="ALT-001", source_ip=self.peer_ip)
            self._json(200, {"id": "ALT-001", "status": "potwierdzony"})
            return
        self._json(404, {"error": "not_found"})

    def _login(self) -> None:
        if self.server.settings.auth_mode != "local":
            self._json(404, {"error": "local_login_disabled"})
            return
        monitor = self.server.state.login_monitor
        if monitor.is_blocked(self.peer_ip):
            self.server.audit.event("login_rate_limited", "warning", source_ip=self.peer_ip)
            self._json(429, {"error": "too_many_attempts", "retry_after_seconds": LOGIN_WINDOW_SECONDS})
            return
        data = self._read_json()
        if data is None:
            return
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username) or not isinstance(password, str) or len(password) > 256:
            monitor.failed(self.peer_ip, self.server.audit)
            self.server.audit.event("login_failed", "warning", principal=str(username)[:64] if isinstance(username, str) else "unknown", source_ip=self.peer_ip, reason="invalid_credentials")
            self._json(401, {"error": "invalid_credentials"})
            return
        user = self.server.users.get(username)
        if user is None:
            # Spend a comparable amount of time on unknown accounts.
            verify_password(password, "ZGVtb3NhbHQ", "ZGVtb2hhc2g")
        valid = bool(user and verify_password(password, user["salt"], user["password_hash"]))
        if not valid:
            monitor.failed(self.peer_ip, self.server.audit)
            self.server.audit.event("login_failed", "warning", principal=username, source_ip=self.peer_ip, reason="invalid_credentials")
            self._json(401, {"error": "invalid_credentials"})
            return
        monitor.succeeded(self.peer_ip)
        token = issue_token(username, user["role"], self.server.settings.session_secret or b"")
        self.server.audit.event("login_succeeded", actor=username, role=user["role"], source_ip=self.peer_ip, session_ttl_seconds=TOKEN_TTL_SECONDS)
        self._json(200, {"access_token": token, "token_type": "Bearer", "expires_in": TOKEN_TTL_SECONDS, "role": user["role"]})


def load_users(path: Path) -> dict[str, dict[str, str]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Brak {path}; uruchom: python local_api.py init-users") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Nie można odczytać pliku kont: {path}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1 or not isinstance(document.get("users"), dict):
        raise ConfigurationError("Nieprawidłowy format pliku kont.")
    users: dict[str, dict[str, str]] = {}
    for username, user in document["users"].items():
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username) or not isinstance(user, dict):
            raise ConfigurationError("Nieprawidłowy wpis użytkownika.")
        role, salt, password_hash_text = user.get("role"), user.get("salt"), user.get("password_hash")
        if not isinstance(role, str) or role not in ROLE_SCOPES or not isinstance(salt, str) or not isinstance(password_hash_text, str):
            raise ConfigurationError(f"Nieprawidłowa rola lub skrót hasła dla konta {username}.")
        users[username] = {"role": role, "salt": salt, "password_hash": password_hash_text}
    if not users:
        raise ConfigurationError("Plik kont nie zawiera użytkowników.")
    return users


def initialize_users(path: Path) -> None:
    if path.exists():
        raise ConfigurationError(f"Plik {path} już istnieje; nie zostanie nadpisany.")
    users: dict[str, dict[str, str]] = {}
    print("Utwórz konta demonstracyjne. Hasła zapiszą się wyłącznie jako skróty scrypt.")
    for role, label in (("audytor", "Audytor (odczyt)"), ("operator", "Operator (odczyt + potwierdzanie alertów)")):
        while True:
            username = input(f"{label} — nazwa użytkownika: ").strip()
            if USERNAME_RE.fullmatch(username) and username not in users:
                break
            print("Nazwa musi mieć 3–64 znaki: litery ASCII, cyfry, kropka, myślnik lub podkreślenie; nazwy nie mogą się powtarzać.")
        while True:
            password = getpass("Hasło (co najmniej 12 znaków): ")
            confirmation = getpass("Powtórz hasło: ")
            if password != confirmation:
                print("Hasła się różnią.")
                continue
            try:
                salt, digest = hash_password(password)
                break
            except ValueError as exc:
                print(exc)
        users[username] = {"role": role, "salt": salt, "password_hash": digest}
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps({"schema_version": 1, "users": users}, ensure_ascii=False, indent=2) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
    print(f"Zapisano skróty haseł do {path}.")


def create_tls_context(settings: Settings) -> ssl.SSLContext:
    if not settings.cert_file.is_file() or not settings.key_file.is_file():
        raise ConfigurationError(
            f"Brak certyfikatu TLS. Uruchom generate_dev_certificate.ps1 lub ustaw TLS_CERT_FILE i TLS_KEY_FILE."
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(str(settings.cert_file), str(settings.key_file))
    if settings.client_ca_file:
        if not settings.client_ca_file.is_file():
            raise ConfigurationError(f"Brak certyfikatu CA klienta: {settings.client_ca_file}")
        context.load_verify_locations(cafile=str(settings.client_ca_file))
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def serve() -> int:
    try:
        settings = Settings.from_env()
        users = load_users(settings.users_file) if settings.auth_mode == "local" else {}
        tls_context = create_tls_context(settings)
        audit = AuditLog(settings.audit_file)
        server = ApiServer(settings, users, audit)
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    except (ConfigurationError, OSError, ssl.SSLError) as exc:
        print(f"Nie można uruchomić API: {exc}", file=sys.stderr)
        return 2

    audit.event(
        "service_started",
        bind_host=settings.host,
        bind_port=settings.port,
        auth_mode=settings.auth_mode,
        network_policy=[str(network) for network in settings.allowed_networks],
        mtls=bool(settings.client_ca_file),
    )
    print(f"Lokalne API działa pod https://{settings.host}:{settings.port}; zakończ Ctrl+C.")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        audit.event("service_stopped")
        server.shutdown()
        server.server_close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Bezpieczne lokalne API dla demonstratora Zero Trust.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init-users", help="Utwórz dwa konta demo i zapisz tylko ich skróty haseł.")
    init_parser.add_argument("--file", type=Path, default=DEFAULT_USERS_FILE)
    subparsers.add_parser("serve", help="Uruchom API HTTPS z kontrolą roli i segmentu sieci.")
    args = parser.parse_args()
    try:
        if args.command == "init-users":
            initialize_users(args.file)
            return 0
        return serve()
    except (ConfigurationError, OSError) as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
