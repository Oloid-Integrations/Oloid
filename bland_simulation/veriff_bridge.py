#!/usr/bin/env python3
"""Small HTTPS-friendly bridge for Bland custom tools + Veriff."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import ssl
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request

try:
    import certifi
except ImportError:  # pragma: no cover - depends on local environment
    certifi = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_ssl_context() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


@dataclass(frozen=True)
class BridgeConfig:
    veriff_base_url: str
    veriff_api_key: str
    veriff_shared_secret: str
    db_path: Path
    callback_url: str | None
    delivery_webhook_url: str | None
    delivery_auth_header: str | None
    delivery_auth_value: str | None
    bridge_shared_token: str | None
    bland_api_key: str | None
    bland_sms_agent_number: str | None
    timeout_seconds: int


class BridgeError(RuntimeError):
    """Raised when the bridge cannot complete a request."""


class VeriffClient:
    def __init__(self, config: BridgeConfig) -> None:
        self.config = config

    def create_session(
        self,
        call_id: str | None,
        delivery_channel: str,
        destination: str,
    ) -> dict[str, Any]:
        verification: dict[str, Any] = {
            "vendorData": call_id or f"bland-{uuid.uuid4()}",
            "endUserId": str(uuid.uuid4()),
        }
        if self.config.callback_url:
            verification["callback"] = self.config.callback_url
        if delivery_channel == "email":
            verification["person"] = {"email": destination}
        payload = {"verification": verification}
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-AUTH-CLIENT": self.config.veriff_api_key,
        }
        response = self._request("POST", "/v1/sessions", headers, body)
        verification_response = response.get("verification") or {}
        if not verification_response.get("id") or not verification_response.get("url"):
            raise BridgeError(f"Unexpected Veriff create-session response: {response}")
        return response

    def get_decision(self, session_id: str) -> dict[str, Any]:
        headers = {
            "X-AUTH-CLIENT": self.config.veriff_api_key,
            "X-HMAC-SIGNATURE": self._sign_session_id(session_id),
        }
        return self._request("GET", f"/v1/sessions/{session_id}/decision", headers)

    def _sign_session_id(self, session_id: str) -> str:
        return hmac.new(
            self.config.veriff_shared_secret.encode("utf-8"),
            session_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _verify_response_signature(self, body: bytes, headers: Any) -> None:
        signature = headers.get("x-hmac-signature") or headers.get("vrf-hmac-signature")
        if not signature:
            return
        expected = hmac.new(
            self.config.veriff_shared_secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise BridgeError("Veriff response signature verification failed.")

    def _request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> dict[str, Any]:
        url = parse.urljoin(self.config.veriff_base_url.rstrip("/") + "/", path.lstrip("/"))
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(
                req,
                timeout=self.config.timeout_seconds,
                context=build_ssl_context(),
            ) as response:
                raw = response.read()
                self._verify_response_signature(raw, response.headers)
                return json.loads(raw.decode("utf-8")) if raw else {}
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise BridgeError(f"Veriff {method} {path} failed with HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise BridgeError(f"Veriff {method} {path} failed: {exc.reason}") from exc


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS veriff_sessions (
                session_id TEXT PRIMARY KEY,
                call_id TEXT,
                delivery_channel TEXT NOT NULL,
                destination TEXT NOT NULL,
                verification_url TEXT NOT NULL,
                latest_status TEXT,
                decision_json TEXT,
                latest_event_json TEXT,
                delivery_status TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_veriff_sessions_call_id ON veriff_sessions(call_id)"
        )


def save_session(
    db_path: Path,
    session_id: str,
    call_id: str | None,
    delivery_channel: str,
    destination: str,
    verification_url: str,
    delivery_status: str,
) -> None:
    now = utc_now()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO veriff_sessions (
                session_id, call_id, delivery_channel, destination, verification_url,
                latest_status, decision_json, latest_event_json, delivery_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                call_id = excluded.call_id,
                delivery_channel = excluded.delivery_channel,
                destination = excluded.destination,
                verification_url = excluded.verification_url,
                delivery_status = excluded.delivery_status,
                updated_at = excluded.updated_at
            """,
            (
                session_id,
                call_id,
                delivery_channel,
                destination,
                verification_url,
                "created",
                None,
                None,
                delivery_status,
                now,
                now,
            ),
        )


def update_session_decision(
    db_path: Path,
    session_id: str,
    latest_status: str,
    decision_payload: dict[str, Any],
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE veriff_sessions
            SET latest_status = ?, decision_json = ?, updated_at = ?
            WHERE session_id = ?
            """,
            (latest_status, json.dumps(decision_payload), utc_now(), session_id),
        )


def update_session_event(
    db_path: Path,
    session_id: str,
    latest_status: str,
    event_payload: dict[str, Any],
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE veriff_sessions
            SET latest_status = ?, latest_event_json = ?, updated_at = ?
            WHERE session_id = ?
            """,
            (latest_status, json.dumps(event_payload), utc_now(), session_id),
        )


def lookup_session(db_path: Path, session_id: str | None, call_id: str | None) -> dict[str, Any] | None:
    if not session_id and not call_id:
        return None
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        if session_id:
            row = conn.execute(
                "SELECT * FROM veriff_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT * FROM veriff_sessions
                WHERE call_id = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (call_id,),
            ).fetchone()
    return dict(row) if row else None


def dispatch_verification_link(
    config: BridgeConfig,
    call_id: str | None,
    delivery_channel: str,
    destination: str,
    verification_url: str,
    session_id: str,
) -> str:
    if delivery_channel == "phone" and config.bland_api_key and config.bland_sms_agent_number:
        send_via_bland_sms(
            config.bland_api_key,
            config.bland_sms_agent_number,
            destination,
            verification_url,
            call_id,
            config.timeout_seconds,
        )
        return "sent_via_bland_sms"
    if not config.delivery_webhook_url:
        return "not_configured"

    payload = {
        "call_id": call_id,
        "channel": delivery_channel,
        "destination": destination,
        "verification_url": verification_url,
        "session_id": session_id,
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config.delivery_auth_header and config.delivery_auth_value:
        headers[config.delivery_auth_header] = config.delivery_auth_value

    req = request.Request(config.delivery_webhook_url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(
            req,
            timeout=config.timeout_seconds,
            context=build_ssl_context(),
        ) as response:
            if 200 <= response.status < 300:
                return "sent"
            raise BridgeError(f"Delivery webhook responded with HTTP {response.status}")
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BridgeError(f"Delivery webhook failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise BridgeError(f"Delivery webhook failed: {exc.reason}") from exc


def send_via_bland_sms(
    bland_api_key: str,
    agent_number: str,
    user_number: str,
    verification_url: str,
    call_id: str | None,
    timeout_seconds: int,
) -> None:
    payload = {
        "user_number": user_number,
        "agent_number": agent_number,
        "agent_message": (
            "This is your Veriff identity verification link for the OLOID Aura simulation: "
            f"{verification_url}"
        ),
        "new_conversation": True,
        "request_data": {"call_id": call_id, "purpose": "veriff_link_delivery"},
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = request.Request(
        "https://api.bland.ai/v1/sms/send",
        data=body,
        headers={
            "Content-Type": "application/json",
            "authorization": bland_api_key,
        },
        method="POST",
    )
    try:
        with request.urlopen(
            req,
            timeout=timeout_seconds,
            context=build_ssl_context(),
        ) as response:
            raw = response.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            if parsed.get("errors"):
                raise BridgeError(f"Bland SMS send failed: {parsed['errors']}")
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BridgeError(f"Bland SMS send failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise BridgeError(f"Bland SMS send failed: {exc.reason}") from exc


def normalize_decision(decision_payload: dict[str, Any]) -> dict[str, Any]:
    verification = decision_payload.get("verification")
    if not verification:
        return {
            "status": "pending",
            "approved": False,
            "route_to_agent": True,
            "allow_simulated_reset": False,
            "speech": "The ID verification is not complete, I am routing you to a customer service agent.",
        }

    status = verification.get("status", "pending")
    if status == "approved":
        return {
            "status": status,
            "approved": True,
            "route_to_agent": False,
            "allow_simulated_reset": True,
            "speech": (
                "The ID verification step is complete, and you're approved to continue "
                "with the simulated password reset."
            ),
        }

    return {
        "status": status,
        "approved": False,
        "route_to_agent": True,
        "allow_simulated_reset": False,
        "speech": "The ID verification is not complete, I am routing you to a customer service agent.",
    }


def verify_veriff_webhook_signature(shared_secret: str, raw_body: bytes, headers: Any) -> None:
    signature = headers.get("X-HMAC-SIGNATURE") or headers.get("x-hmac-signature")
    if not signature:
        raise BridgeError("Missing Veriff X-HMAC-SIGNATURE header.")
    expected = hmac.new(
        shared_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise BridgeError("Invalid Veriff webhook signature.")


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "VeriffBridge/1.0"

    @property
    def bridge_config(self) -> BridgeConfig:
        return self.server.bridge_config  # type: ignore[attr-defined]

    @property
    def veriff_client(self) -> VeriffClient:
        return self.server.veriff_client  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._write_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            raw_body, payload = self._read_json_with_raw()
            if self.path.startswith("/veriff/webhooks/"):
                self._handle_veriff_webhook(self.path, raw_body, payload)
                return
            self._authorize()
            if self.path == "/veriff/start":
                self._handle_veriff_start(payload)
                return
            if self.path == "/veriff/status":
                self._handle_veriff_status(payload)
                return
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except BridgeError as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})

    def _authorize(self) -> None:
        token = self.bridge_config.bridge_shared_token
        if not token:
            return
        expected = f"Bearer {token}"
        actual = self.headers.get("Authorization")
        if actual != expected:
            raise BridgeError("Unauthorized request.")

    def _handle_veriff_webhook(self, path: str, raw_body: bytes, payload: dict[str, Any]) -> None:
        verify_veriff_webhook_signature(
            self.bridge_config.veriff_shared_secret,
            raw_body,
            self.headers,
        )
        verification = payload.get("verification") or {}
        session_id = verification.get("id")
        if not session_id:
            raise BridgeError("Webhook payload missing verification.id.")

        existing = lookup_session(self.bridge_config.db_path, session_id, None)
        if not existing:
            save_session(
                self.bridge_config.db_path,
                session_id,
                verification.get("vendorData"),
                "unknown",
                "unknown",
                "",
                "unknown",
            )

        if path == "/veriff/webhooks/decision":
            normalized = normalize_decision(payload)
            update_session_decision(
                self.bridge_config.db_path,
                session_id,
                normalized["status"],
                payload,
            )
            self._write_json(HTTPStatus.OK, {"status": "success"})
            return

        if path == "/veriff/webhooks/event":
            latest_status = str(verification.get("status") or payload.get("status") or "event")
            update_session_event(
                self.bridge_config.db_path,
                session_id,
                latest_status,
                payload,
            )
            self._write_json(HTTPStatus.OK, {"status": "success"})
            return

        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _handle_veriff_start(self, payload: dict[str, Any]) -> None:
        delivery_channel = str(payload.get("delivery_channel", "")).strip().lower()
        destination = str(payload.get("destination", "")).strip()
        call_id = str(payload.get("call_id") or "").strip() or None

        if delivery_channel not in {"email", "phone"}:
            raise BridgeError("delivery_channel must be 'email' or 'phone'.")
        if not destination:
            raise BridgeError("destination is required.")

        session_response = self.veriff_client.create_session(call_id, delivery_channel, destination)
        verification = session_response["verification"]
        session_id = verification["id"]
        verification_url = verification["url"]

        delivery_status = dispatch_verification_link(
            self.bridge_config,
            call_id,
            delivery_channel,
            destination,
            verification_url,
            session_id,
        )
        save_session(
            self.bridge_config.db_path,
            session_id,
            call_id,
            delivery_channel,
            destination,
            verification_url,
            delivery_status,
        )

        if delivery_status in {"sent", "sent_via_bland_sms"}:
            speech = "I sent the Veriff verification link. Please complete the verification now and let me know when you're done."
            route_to_agent = False
        else:
            speech = "I created the Veriff verification link, but link delivery is not configured, so I am routing you to a customer service agent."
            route_to_agent = True

        self._write_json(
            HTTPStatus.OK,
            {
                "status": "success",
                "session_id": session_id,
                "verification_url": verification_url,
                "delivery_status": delivery_status,
                "route_to_agent": route_to_agent,
                "speech": speech,
            },
        )

    def _handle_veriff_status(self, payload: dict[str, Any]) -> None:
        session_id = str(payload.get("session_id") or "").strip() or None
        call_id = str(payload.get("call_id") or "").strip() or None
        session = lookup_session(self.bridge_config.db_path, session_id, call_id)
        if not session:
            raise BridgeError("No Veriff session found for the provided session_id or call_id.")

        decision = self.veriff_client.get_decision(session["session_id"])
        normalized = normalize_decision(decision)
        update_session_decision(
            self.bridge_config.db_path,
            session["session_id"],
            normalized["status"],
            decision,
        )
        response = {
            "status": "success",
            "session_id": session["session_id"],
            "verification_status": normalized["status"],
            "approved": normalized["approved"],
            "route_to_agent": normalized["route_to_agent"],
            "allow_simulated_reset": normalized["allow_simulated_reset"],
            "speech": normalized["speech"],
            "raw_decision": decision,
        }
        self._write_json(HTTPStatus.OK, response)

    def _read_json_with_raw(self) -> tuple[bytes, dict[str, Any]]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            return raw, payload
        except json.JSONDecodeError as exc:
            raise BridgeError(f"Invalid JSON body: {exc}") from exc

    def _write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Bland <-> Veriff bridge service.")
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Bind host. Defaults to HOST env var or 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8787")),
        help="Bind port. Defaults to PORT env var or 8787.",
    )
    parser.add_argument(
        "--db-path",
        default=os.environ.get("VERIFF_DB_PATH", "bland_simulation/veriff_bridge.db"),
        help="SQLite DB path. Defaults to bland_simulation/veriff_bridge.db.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=int(os.environ.get("VERIFF_TIMEOUT_SECONDS", "30")),
        help="Outbound HTTP timeout. Defaults to 30 seconds.",
    )
    return parser.parse_args()


def load_config(args: argparse.Namespace) -> BridgeConfig:
    veriff_base_url = os.environ.get("VERIFF_BASE_URL")
    veriff_api_key = os.environ.get("VERIFF_API_KEY")
    veriff_shared_secret = os.environ.get("VERIFF_SHARED_SECRET")
    if not veriff_base_url or not veriff_api_key or not veriff_shared_secret:
        raise SystemExit(
            "Missing Veriff configuration. Set VERIFF_BASE_URL, VERIFF_API_KEY, and VERIFF_SHARED_SECRET."
        )

    return BridgeConfig(
        veriff_base_url=veriff_base_url,
        veriff_api_key=veriff_api_key,
        veriff_shared_secret=veriff_shared_secret,
        db_path=Path(args.db_path),
        callback_url=os.environ.get("VERIFF_CALLBACK_URL"),
        delivery_webhook_url=os.environ.get("VERIFF_DELIVERY_WEBHOOK_URL"),
        delivery_auth_header=os.environ.get("VERIFF_DELIVERY_AUTH_HEADER"),
        delivery_auth_value=os.environ.get("VERIFF_DELIVERY_AUTH_VALUE"),
        bridge_shared_token=os.environ.get("BRIDGE_SHARED_TOKEN"),
        bland_api_key=os.environ.get("BLAND_API_KEY"),
        bland_sms_agent_number=os.environ.get("BLAND_SMS_AGENT_NUMBER"),
        timeout_seconds=args.timeout_seconds,
    )


def main() -> int:
    args = parse_args()
    config = load_config(args)
    init_db(config.db_path)
    server = ThreadingHTTPServer((args.host, args.port), BridgeHandler)
    server.bridge_config = config  # type: ignore[attr-defined]
    server.veriff_client = VeriffClient(config)  # type: ignore[attr-defined]
    print(f"Veriff bridge listening on http://{args.host}:{args.port}", file=sys.stderr)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())