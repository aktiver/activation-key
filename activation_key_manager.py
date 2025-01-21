import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Any

ONE_YEAR_SECONDS = 365 * 24 * 60 * 60

def encode_token(payload: Dict[str, Any], server_secret: str) -> str:
    """
    Given a dictionary payload, produce a self-contained, HMAC-signed token (base32).
    """
    # Convert to JSON bytes
    payload_json = json.dumps(payload).encode("utf-8")

    # Compute signature
    signature = hmac.new(
        key=server_secret.encode("utf-8"),
        msg=payload_json,
        digestmod=hashlib.sha256
    ).digest()

    # Combine payload and signature
    combined = payload_json + b":::" + signature

    # Return a base32-encoded string
    return base64.b32encode(combined).decode("utf-8")


def decode_token(full_token: str, server_secret: str) -> Dict[str, Any]:
    """
    Decode and validate a full base32 token.
    Returns the payload dict if valid, otherwise raises ValueError.
    """
    try:
        combined = base64.b32decode(full_token.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid token: cannot decode base32.")

    # Split at the ':::' separator
    if b":::" not in combined:
        raise ValueError("Invalid token: missing separator.")
    payload_json, signature = combined.split(b":::", 1)

    # Recompute the expected signature
    expected_signature = hmac.new(
        key=server_secret.encode("utf-8"),
        msg=payload_json,
        digestmod=hashlib.sha256
    ).digest()

    # Compare signatures in constant time
    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("Invalid token: signature mismatch (tampered or wrong).")

    # Decode the JSON
    payload = json.loads(payload_json)

    # Check expiration
    now = int(time.time())
    expires_at = payload.get("expires_at")
    if not expires_at or now > expires_at:
        raise ValueError("Token has expired.")

    return payload



def set_agent_deployed(full_token: str, server_secret: str, deployed: bool) -> str:
    """
    Decodes the token, sets agent_deployed to 1 or 0, then re-encodes and returns the new token.
    If the token is invalid or expired, raises ValueError.
    """
    payload = decode_token(full_token, server_secret)
    # If you want to enforce a one-time use, you could forbid switching from 1->0
    # for demonstration, we allow toggling.
    payload["agent_deployed"] = 1 if deployed else 0

    # Re-encode with the updated payload
    new_token = encode_token(payload, server_secret)
    return new_token
