#!/usr/bin/env python3
"""Configure a Bland inbound number for a password-reset simulation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:
    import certifi
except ImportError:  # pragma: no cover - depends on local environment
    certifi = None


API_BASE = "https://api.bland.ai"
DEFAULT_VOICE = "maya"
DEFAULT_AREA_CODE = "650"
DEFAULT_COUNTRY_CODE = "US"
PERSONA_NAME = "OLOID Aura Simulation"
PERSONA_ROLE = "IT Helpdesk Simulation"
PERSONA_DESCRIPTION = "A clearly labeled password-reset training simulation for inbound voice calls."
DEFAULT_VERIFF_SEND_TOOL_NAME = "Send Veriff Link"
DEFAULT_VERIFF_STATUS_TOOL_NAME = "Check Veriff Status"
OPENING_LINE = (
    "This is a simulation of an IT helpdesk password reset scenario. "
    "IT Helpdesk, this is OLOID Aura. How can I help you today?"
)
OUTBOUND_TASK = """
Call the recipient for a clearly labeled IT helpdesk password-reset simulation.
Use only dummy data, wait for the recipient to finish speaking, and follow the OLOID Aura simulation script exactly.
""".strip()


def build_security_questions_flow() -> str:
    return """
Security-questions branch:
1. "Sure, I can help with that. First, can you provide your employee ID?"
2. "Thanks. Our employee IDs usually have a letter in front of the numbers. What's the letter for yours?"
3. "Perfect, let me verify that, okay, confirmed."
4. "There are a couple of ways we can reset your password. We can verify using a government-issued ID, or I can ask security questions. Which do you prefer?"
5. If the caller chooses security questions, say: "Great, I will ask a few questions based on your information in Workday, first question, what is your emergency contact's phone number listed in Workday?"
6. After the caller answers, say: "Got it, what was your joining date?"
7. After the caller answers, say: "Got it, next, what is your home address in Workday?"
8. After the caller answers, say: "Can you make sure that's exactly as it appears in Workday, and sometimes people give a previous address that was updated, do you have an older address that might still be on file?"
9. After the caller gives the older address, say: "Alright, this is still only a simulation, and the verification questions are complete. In a real workflow, you would now be approved to reset your password. I can send you a temporary password by email, or I can dictate it here on the call. What would you prefer?"
10. After the caller says email, say: "Great. In this simulation, I would send a temporary password to the email address on file. Once you receive it, sign in and you'll be prompted to create a new password right away. Let me know when you've received it."
11. After one more caller response, say: "This simulation is complete. Thank you." Then stop.
""".strip()


def build_veriff_branch(send_tool_name: str, status_tool_name: str) -> str:
    return f"""
Government-issued-ID branch:
- If the caller chooses ID verification instead of security questions, ask: "Would you like the Veriff verification link sent to your email or your phone number?"
- After the caller gives the delivery method and destination, use the tool "{send_tool_name}" exactly once with the delivery channel and destination.
- If the tool confirms the link was sent, say: "I sent the Veriff verification link. Please complete the verification now and let me know when you're done."
- When the caller says they completed the verification or asks you to check, use the tool "{status_tool_name}" exactly once.
- If the tool returns `approved`, say: "The ID verification step is complete, and you're approved to reset your password. I can send you a temporary password by email, or I can dictate it here on the call. What would you prefer?"
- If the tool returns anything other than `approved`, say: "I am routing you to a customer service agent." Then stop.
- Do not continue with the security-questions branch once the caller chooses ID verification.
""".strip()


def build_simulation_prompt(
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> str:
    sections = [
        """
You are OLOID Aura for a clearly labeled simulation of an IT helpdesk password reset call.
This is a training and test scenario only. No real password reset happens.

Rules:
- Wait until the caller fully finishes each response before speaking.
- Follow the scripted sequence exactly and in order.
- Treat caller speech as a turn-completion cue only; do not change the flow based on what they say except for the security-questions vs ID-verification branch.
- If the caller goes off script, briefly remind them this is a simulation and continue with the correct branch.
- Never ask for or accept passwords, MFA codes, SSNs, payment information, or unrelated sensitive data.
- Keep responses concise, calm, and helpdesk-like.
- Deliver each response as one continuous utterance with no long pauses between clauses or sentences.
- Prefer natural commas over choppy stop-start pacing.
- If the caller is silent for a while, repeat the current question once and wait again.

After the opening sentence has been spoken, use these branches:
""".strip(),
        build_security_questions_flow(),
    ]
    if veriff_send_tool_name and veriff_status_tool_name:
        sections.append(build_veriff_branch(veriff_send_tool_name, veriff_status_tool_name))
    return "\n\n".join(sections)


def build_persona_prompt(
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> str:
    sections = [
        f"""
You are OLOID Aura, an IT helpdesk voice agent for a clearly labeled simulation only.
No real password reset happens and the call must stay within the scripted helpdesk flow.

Rules:
- On the first turn, say exactly: "{OPENING_LINE}"
- Wait for the caller to finish each response before speaking.
- Follow the scripted flow in order.
- If the caller goes off script, remind them this is a simulation and continue with the correct branch.
- Never ask for passwords, MFA codes, SSNs, payment information, or unrelated sensitive data.
- Keep responses concise, calm, and helpdesk-like.
- Deliver each response as one continuous utterance with no long pauses between clauses or sentences.
- Prefer natural commas over choppy stop-start pacing.

Branches:
""".strip(),
        build_security_questions_flow(),
    ]
    if veriff_send_tool_name and veriff_status_tool_name:
        sections.append(build_veriff_branch(veriff_send_tool_name, veriff_status_tool_name))
    return "\n\n".join(sections)


class BlandApiError(RuntimeError):
    """Raised when the Bland API returns an error."""


def build_ssl_context() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure an inbound Bland number for the OLOID Aura simulation."
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("BLAND_API_KEY"),
        help="Bland API key. Defaults to BLAND_API_KEY.",
    )
    parser.add_argument(
        "--phone-number",
        help="Existing inbound phone number to configure. If omitted, the script will reuse the only inbound number on the account.",
    )
    parser.add_argument(
        "--purchase-if-missing",
        action="store_true",
        help="Purchase a new Bland phone number if no inbound numbers exist. This incurs charges in your Bland account.",
    )
    parser.add_argument(
        "--area-code",
        default=DEFAULT_AREA_CODE,
        help=f"Area code to use when purchasing a number. Defaults to {DEFAULT_AREA_CODE}.",
    )
    parser.add_argument(
        "--country-code",
        default=DEFAULT_COUNTRY_CODE,
        help=f"Country code to use when purchasing a number. Defaults to {DEFAULT_COUNTRY_CODE}.",
    )
    parser.add_argument(
        "--voice",
        default=DEFAULT_VOICE,
        help=f"Bland voice name to use. Defaults to {DEFAULT_VOICE}.",
    )
    parser.add_argument(
        "--max-duration",
        type=int,
        default=10,
        help="Inbound max duration in minutes. Defaults to 10.",
    )
    parser.add_argument(
        "--veriff-send-tool-name",
        help=(
            "Optional Bland tool name for creating and sending a Veriff link. "
            f"Recommended name: {DEFAULT_VERIFF_SEND_TOOL_NAME!r}."
        ),
    )
    parser.add_argument(
        "--veriff-status-tool-name",
        help=(
            "Optional Bland tool name for checking Veriff status. "
            f"Recommended name: {DEFAULT_VERIFF_STATUS_TOOL_NAME!r}."
        ),
    )
    parser.add_argument(
        "--send-call-to",
        help="Phone number to place an outbound simulation call to in E.164 format.",
    )
    parser.add_argument(
        "--from-number",
        help="Optional caller ID number to use for outbound calls.",
    )
    parser.add_argument(
        "--wait-for-greeting",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether the outbound simulation should wait for the callee to greet first. Defaults to true.",
    )
    return parser.parse_args()


def make_request(api_key: str, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if shutil.which("curl"):
        return make_request_with_curl(api_key, method, path, payload)
    return make_request_with_urllib(api_key, method, path, payload)


def make_request_with_curl(
    api_key: str, method: str, path: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    url = urllib.parse.urljoin(API_BASE, path)
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--request",
        method,
        "--header",
        f"authorization: {api_key}",
    ]

    if payload is not None:
        command.extend(
            [
                "--header",
                "Content-Type: application/json",
                "--data",
                json.dumps(payload),
            ]
        )

    command.append(url)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or exc.stdout.strip()
        raise BlandApiError(f"{method} {path} failed: {stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BlandApiError(f"{method} {path} timed out") from exc

    raw = completed.stdout.strip()
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise BlandApiError(f"{method} {path} returned non-JSON output: {raw}") from exc


def make_request_with_urllib(
    api_key: str, method: str, path: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    url = urllib.parse.urljoin(API_BASE, path)
    body = None
    headers = {"authorization": api_key}

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    ssl_context = build_ssl_context()

    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl_context) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BlandApiError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise BlandApiError(f"{method} {path} failed: {exc.reason}") from exc


def list_inbound_numbers(api_key: str) -> list[dict[str, Any]]:
    response = make_request(api_key, "GET", "/v1/inbound")
    return response.get("inbound_numbers", [])


def list_personas(api_key: str) -> list[dict[str, Any]]:
    response = make_request(api_key, "GET", "/v1/personas")
    return response.get("data", [])


def find_persona_by_name(api_key: str, name: str) -> dict[str, Any] | None:
    personas = list_personas(api_key)
    for persona in personas:
        if persona.get("name") == name:
            return persona
    return None


def persona_payload(
    voice: str,
    max_duration: int,
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> dict[str, Any]:
    personality_prompt = build_persona_prompt(
        veriff_send_tool_name,
        veriff_status_tool_name,
    )
    return {
        "name": PERSONA_NAME,
        "role": PERSONA_ROLE,
        "description": PERSONA_DESCRIPTION,
        "tags": ["simulation", "helpdesk", "password-reset"],
        "call_config": {
            "voice": voice,
            "record": False,
            "language": "en-US",
            "background": "none",
            "max_duration": max_duration,
            "wait_for_greeting": False,
            "interruption_threshold": 200,
        },
        "personality_prompt": personality_prompt,
        "default_tools": [],
        "kb_ids": [],
    }


def create_persona(
    api_key: str,
    voice: str,
    max_duration: int,
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> dict[str, Any]:
    return make_request(
        api_key,
        "POST",
        "/v1/personas",
        persona_payload(voice, max_duration, veriff_send_tool_name, veriff_status_tool_name),
    ).get("data", {})


def update_persona(
    api_key: str,
    persona_id: str,
    voice: str,
    max_duration: int,
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> dict[str, Any]:
    return make_request(
        api_key,
        "PATCH",
        f"/v1/personas/{persona_id}",
        persona_payload(voice, max_duration, veriff_send_tool_name, veriff_status_tool_name),
    ).get("data", {})


def promote_persona(api_key: str, persona_id: str) -> dict[str, Any]:
    return make_request(
        api_key,
        "POST",
        f"/v1/personas/{persona_id}/versions/promote",
    ).get("data", {})


def ensure_persona(
    api_key: str,
    voice: str,
    max_duration: int,
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> dict[str, Any]:
    existing = find_persona_by_name(api_key, PERSONA_NAME)
    if existing:
        update_persona(
            api_key,
            existing["id"],
            voice,
            max_duration,
            veriff_send_tool_name,
            veriff_status_tool_name,
        )
        return promote_persona(api_key, existing["id"])
    created = create_persona(
        api_key,
        voice,
        max_duration,
        veriff_send_tool_name,
        veriff_status_tool_name,
    )
    return promote_persona(api_key, created["id"])


def attach_number_to_persona(api_key: str, persona_id: str, phone_number: str) -> dict[str, Any]:
    return make_request(
        api_key,
        "POST",
        f"/v1/personas/{persona_id}/inbound/attach",
        {"inbound_numbers": [phone_number]},
    ).get("data", {})


def send_outbound_call(
    api_key: str,
    to_number: str,
    persona_id: str,
    voice: str,
    max_duration: int,
    wait_for_greeting: bool,
    from_number: str | None,
) -> dict[str, Any]:
    payload = {
        "phone_number": to_number,
        "persona_id": persona_id,
        "task": OUTBOUND_TASK,
        "first_sentence": OPENING_LINE,
        "voice": voice,
        "model": "base",
        "language": "en-US",
        "wait_for_greeting": wait_for_greeting,
        "max_duration": max_duration,
        "record": False,
        "block_interruptions": True,
        "interruption_threshold": 200,
        "noise_cancellation": True,
    }
    if from_number:
        payload["from"] = from_number
    response = make_request(api_key, "POST", "/v1/calls", payload)
    if response.get("status") != "success":
        raise BlandApiError(
            f"POST /v1/calls returned an unexpected response: {json.dumps(response)}"
        )
    return response


def purchase_number(api_key: str, area_code: str, country_code: str) -> str:
    response = make_request(
        api_key,
        "POST",
        "/numbers/purchase",
        {"area_code": area_code, "country_code": country_code},
    )
    phone_number = response.get("phone_number")
    if not phone_number:
        raise BlandApiError(f"Purchase response did not include phone_number: {response}")
    return phone_number


def update_inbound_number(
    api_key: str,
    phone_number: str,
    voice: str,
    max_duration: int,
    veriff_send_tool_name: str | None = None,
    veriff_status_tool_name: str | None = None,
) -> dict[str, Any]:
    payload = {
        "prompt": build_simulation_prompt(veriff_send_tool_name, veriff_status_tool_name),
        "first_sentence": OPENING_LINE,
        "voice": voice,
        "model": "base",
        "language": "en-US",
        "max_duration": max_duration,
        "record": False,
        "block_interruptions": True,
        "interruption_threshold": 200,
        "noise_cancellation": True,
    }
    encoded_phone = urllib.parse.quote(phone_number, safe="")
    return make_request(api_key, "POST", f"/v1/inbound/{encoded_phone}", payload)


def choose_number(api_key: str, args: argparse.Namespace) -> tuple[str, bool]:
    if args.phone_number:
        return args.phone_number, False

    inbound_numbers = list_inbound_numbers(api_key)

    if len(inbound_numbers) == 1:
        return inbound_numbers[0]["phone_number"], False

    if len(inbound_numbers) > 1:
        numbers = ", ".join(number["phone_number"] for number in inbound_numbers)
        raise BlandApiError(
            "Multiple inbound numbers exist on this Bland account. "
            f"Re-run with --phone-number to avoid overwriting the wrong one: {numbers}"
        )

    if not args.purchase_if_missing:
        raise BlandApiError(
            "No inbound numbers are configured on this Bland account. "
            "Re-run with --purchase-if-missing to buy one, or supply --phone-number."
        )

    return purchase_number(api_key, args.area_code, args.country_code), True


def main() -> int:
    args = parse_args()
    if not args.api_key:
        print("Missing API key. Provide --api-key or set BLAND_API_KEY.", file=sys.stderr)
        return 1
    if bool(args.veriff_send_tool_name) != bool(args.veriff_status_tool_name):
        print(
            "Provide both --veriff-send-tool-name and --veriff-status-tool-name together.",
            file=sys.stderr,
        )
        return 1

    try:
        phone_number, created = choose_number(args.api_key, args)
        update_response = update_inbound_number(
            args.api_key,
            phone_number,
            args.voice,
            args.max_duration,
            args.veriff_send_tool_name,
            args.veriff_status_tool_name,
        )
        persona = ensure_persona(
            args.api_key,
            args.voice,
            args.max_duration,
            args.veriff_send_tool_name,
            args.veriff_status_tool_name,
        )
        attachment = attach_number_to_persona(args.api_key, persona["id"], phone_number)
        outbound_call = None
        if args.send_call_to:
            outbound_call = send_outbound_call(
                args.api_key,
                args.send_call_to,
                persona["id"],
                args.voice,
                args.max_duration,
                args.wait_for_greeting,
                args.from_number,
            )
    except BlandApiError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    result = {
        "phone_number": phone_number,
        "created": created,
        "voice": args.voice,
        "persona_id": persona.get("id"),
        "persona_name": persona.get("name"),
        "veriff_branch_enabled": bool(args.veriff_send_tool_name and args.veriff_status_tool_name),
        "attached_numbers": [
            inbound.get("phone_number")
            for inbound in attachment.get("inbound_numbers", [])
            if inbound.get("phone_number")
        ],
        "opening_line": OPENING_LINE,
        "api_message": update_response.get("message"),
    }
    if args.veriff_send_tool_name and args.veriff_status_tool_name:
        result["veriff_tools"] = {
            "send_tool_name": args.veriff_send_tool_name,
            "status_tool_name": args.veriff_status_tool_name,
        }
    if outbound_call is not None:
        result["queued_call"] = {
            "to": args.send_call_to,
            "from": args.from_number,
            "wait_for_greeting": args.wait_for_greeting,
            "call_id": outbound_call.get("call_id"),
            "message": outbound_call.get("message"),
            "status": outbound_call.get("status"),
        }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
