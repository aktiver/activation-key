import base64
import hashlib
import hmac
import secrets
import time

ONE_YEAR_SECONDS = 365 * 24 * 60 * 60

# How many bytes in each segment
DATA_SIZE = 10   # 4 + 4 + 1 + 1
SIG_SIZE = 10    # partial HMAC
TOTAL_SIZE = DATA_SIZE + SIG_SIZE  # = 20

def _pack_data(created_at: int, expires_at: int, agent_deployed: bool) -> bytes:
    """
    Construct the 10-byte data block:
      - 4 bytes: created_at (big-endian)
      - 4 bytes: expires_at (big-endian)
      - 1 byte: flags (lowest bit = agent_deployed, other 7 bits = random)
      - 1 byte: random
    """
    # 4 bytes each for created/expires
    created_bytes = created_at.to_bytes(4, "big", signed=False)
    expires_bytes = expires_at.to_bytes(4, "big", signed=False)

    # 1 byte: bit0 = agent_deployed, bits1-7 random
    random_7bits = secrets.randbits(7)  # integer in [0..127]
    agent_bit = 1 if agent_deployed else 0
    flag_byte = (random_7bits << 1) | agent_bit  # pack agent_bit as LSB

    # 1 byte: random filler
    filler_byte = secrets.randbits(8)  # 0..255

    # Combine
    return created_bytes + expires_bytes + bytes([flag_byte, filler_byte])


def _unpack_data(data_block: bytes):
    """
    Reverse of _pack_data.
    Return (created_at, expires_at, agent_deployed).
    """
    if len(data_block) != 10:
        raise ValueError("Data block must be 10 bytes")

    created_at = int.from_bytes(data_block[0:4], "big", signed=False)
    expires_at = int.from_bytes(data_block[4:8], "big", signed=False)

    flag_byte = data_block[8]
    agent_deployed = bool(flag_byte & 0x01)  # LSB is agent flag

    # data_block[9] is the random filler byte (not crucial for logic)

    return created_at, expires_at, agent_deployed


def _compute_partial_signature(data_block: bytes, server_secret: str) -> bytes:
    """
    Compute full HMAC-SHA256 over data_block, but return only the first 10 bytes (partial).
    """
    full_digest = hmac.new(
        server_secret.encode("utf-8"),
        data_block,
        hashlib.sha256
    ).digest()
    return full_digest[:SIG_SIZE]  # 10 bytes



def decode_novel_key(pretty_key: str, server_secret: str):
    """
    Reverse of encode_novel_key.
    1) Remove dashes => 35 chars
    2) Discard last 3 "XXX" => 32 chars
    3) Base32 decode => 20 raw bytes
    4) Split => 10-byte data + 10-byte signature
    5) Recompute partial HMAC => compare
    6) Unpack data => (created_at, expires_at, agent_deployed)
    Raises ValueError if signature mismatch or expired.
    Returns dict: { "created_at", "expires_at", "agent_deployed" }
    """
    raw = pretty_key.replace("-", "")
    if len(raw) != 35:
        raise ValueError("Expected 35 characters with dashes removed")

    # remove filler
    real_b32 = raw[:-3]  # first 32
    combined = base64.b32decode(real_b32)  # => 20 bytes

    if len(combined) != TOTAL_SIZE:  # 20
        raise ValueError("Decoded length mismatch")

    data_block = combined[:DATA_SIZE]   # first 10
    sig_block = combined[DATA_SIZE:]    # next 10

    # Recompute partial signature
    expected_sig = _compute_partial_signature(data_block, server_secret)
    if not hmac.compare_digest(sig_block, expected_sig):
        raise ValueError("Signature mismatch (tampered or invalid)")

    # Unpack
    created_at, expires_at, agent_deployed = _unpack_data(data_block)
    now = int(time.time())
    if now > expires_at:
        raise ValueError("Key has expired")

    return {
        "created_at": created_at,
        "expires_at": expires_at,
        "agent_deployed": agent_deployed
    }


def set_agent_deployed(novel_key: str, server_secret: str, deploy: bool) -> str:
    """
    Decode the key, set agent_deployed= (1 or 0), re-encode.
    """
    info = decode_novel_key(novel_key, server_secret)
    new_created = info["created_at"]
    new_expires = info["expires_at"]
    new_agent_flag = deploy
    return encode_novel_key(new_created, new_expires, new_agent_flag, server_secret)
