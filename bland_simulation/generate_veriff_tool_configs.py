#!/usr/bin/env python3
"""Generate Bland custom-tool payloads for the local Veriff bridge."""

from __future__ import annotations

import argparse
import json
from typing import Any


DEFAULT_SEND_TOOL_NAME = "Send Veriff Link"
DEFAULT_STATUS_TOOL_NAME = "Check Veriff Status"


def build_headers(shared_token: str | None) -> dict[str, str]:
    if not shared_token:
        return {"Content-Type": "application/json"}
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {shared_token}",
    }


def build_tool_payloads(
    bridge_base_url: str,
    shared_token: str | None,
    send_tool_name: str,
    status_tool_name: str,
) -> list[dict[str, Any]]:
    bridge_base_url = bridge_base_url.rstrip("/")
    headers = build_headers(shared_token)
    return [
        {
            "name": send_tool_name,
            "description": (
                "Use when the caller chooses ID verification and gives an email or phone number. "
                "Creates a Veriff session and dispatches the hosted verification link."
            ),
            "speech": "One moment while I send the Veriff verification link.",
            "url": f"{bridge_base_url}/veriff/start",
            "method": "POST",
            "headers": headers,
            "body": {
                "call_id": "{{call_id}}",
                "delivery_channel": "{{input.delivery_channel}}",
                "destination": "{{input.destination}}",
            },
            "input_schema": {
                "type": "object",
                "example": {
                    "delivery_channel": "email",
                    "destination": "person@example.com",
                },
                "properties": {
                    "delivery_channel": {"type": "string", "options": "email, phone"},
                    "destination": {"type": "string"},
                },
                "required": ["delivery_channel", "destination"],
            },
            "response": {
                "veriff_session_id": "$.session_id",
                "veriff_delivery_status": "$.delivery_status",
                "veriff_send_speech": "$.speech",
                "veriff_route_to_agent": "$.route_to_agent",
            },
            "timeout": 15000,
        },
        {
            "name": status_tool_name,
            "description": (
                "Use after the caller says they completed Veriff. Checks the decision and returns "
                "whether the simulated reset can continue."
            ),
            "speech": "One moment while I check the Veriff verification status.",
            "url": f"{bridge_base_url}/veriff/status",
            "method": "POST",
            "headers": headers,
            "body": {
                "call_id": "{{call_id}}",
                "session_id": "{{veriff_session_id}}",
            },
            "input_schema": {
                "type": "object",
                "example": {"check_now": True},
                "properties": {"check_now": {"type": "boolean"}},
            },
            "response": {
                "veriff_verification_status": "$.verification_status",
                "veriff_approved": "$.approved",
                "veriff_allow_simulated_reset": "$.allow_simulated_reset",
                "veriff_route_to_agent": "$.route_to_agent",
                "veriff_status_speech": "$.speech",
            },
            "timeout": 15000,
        },
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Bland custom tool payloads for Veriff.")
    parser.add_argument("--bridge-base-url", required=True, help="Public HTTPS URL of the deployed bridge.")
    parser.add_argument("--bridge-shared-token", help="Optional bearer token required by the bridge.")
    parser.add_argument(
        "--send-tool-name",
        default=DEFAULT_SEND_TOOL_NAME,
        help=f"Tool name for Veriff link delivery. Defaults to {DEFAULT_SEND_TOOL_NAME!r}.",
    )
    parser.add_argument(
        "--status-tool-name",
        default=DEFAULT_STATUS_TOOL_NAME,
        help=f"Tool name for Veriff status checks. Defaults to {DEFAULT_STATUS_TOOL_NAME!r}.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payloads = build_tool_payloads(
        args.bridge_base_url,
        args.bridge_shared_token,
        args.send_tool_name,
        args.status_tool_name,
    )
    print(json.dumps(payloads, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
