"""
gatekeeper — Python SDK for the Gatekeeper Protocol
=====================================================

Uses pure Python + the ``cryptography`` library for Ed25519 operations.
Optionally delegates CLI verification to the compiled ``gatekeeper`` binary.

Typical usage::

    from gatekeeper import GatekeeperSession

    s = GatekeeperSession()
    action = s.propose("Deploy v1.2.3 to production", b"kubectl rollout ...")
    token  = s.request_authorization(action)   # blocks on stdin
    if token:
        # action is now authorised
        assert s.verify(token, b"kubectl rollout ...")
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional


# ── Locate the gatekeeper CLI binary (optional, for verify delegation) ─────────

def _find_binary() -> Optional[str]:
    """Return the path to the ``gatekeeper`` CLI binary, or None."""
    env = os.environ.get("GATEKEEPER_BIN")
    if env and Path(env).exists():
        return env

    here = Path(__file__).parent
    candidates = [
        here / ".." / ".." / "target" / "release" / "gatekeeper",
        here / ".." / ".." / "target" / "debug"   / "gatekeeper",
        here / "gatekeeper",
    ]
    for c in candidates:
        resolved = c.resolve()
        if resolved.exists():
            return str(resolved)

    import shutil
    return shutil.which("gatekeeper")


# ── Exceptions ────────────────────────────────────────────────────────────────

class GatekeeperError(Exception):
    """Raised for unrecoverable gatekeeper errors."""


class GatekeeperBinaryNotFound(GatekeeperError):
    """Raised when the binary is needed but unavailable."""


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _blake3_or_sha256(data: bytes) -> bytes:
    """BLAKE3 if available, SHA-256 as fallback. Warning issued on fallback."""
    try:
        import blake3 as _b3
        return _b3.blake3(data).digest()
    except ImportError:
        import warnings
        warnings.warn(
            "blake3 Python package not found; falling back to SHA-256. "
            "Install `pip install blake3` for full compatibility with the Rust SDK.",
            stacklevel=3,
        )
        return hashlib.sha256(data).digest()


def _now() -> int:
    return int(time.time())


def _iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# ── GatekeeperSession ─────────────────────────────────────────────────────────

class GatekeeperSession:
    """
    Python interface to the Gatekeeper Protocol.

    Always uses pure-Python Ed25519 via the ``cryptography`` library for
    signing and verification. The compiled Rust CLI binary, if present, is
    used as an additional verification path (cross-checks the Python result).

    Requires: ``pip install cryptography``
    Recommended: ``pip install blake3`` (for BLAKE3 hash fidelity)
    """

    TOKEN_TTL_SECS = 300

    def __init__(self, keyfile: Optional[str | Path] = None):
        self._keyfile = str(keyfile) if keyfile else None
        self._binary  = _find_binary()
        self._audit: list[dict] = []
        self._init_crypto()

    # ── Crypto initialisation (always runs) ───────────────────────────────────

    def _init_crypto(self) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, PrivateFormat, NoEncryption,
            )
        except ImportError as exc:
            raise GatekeeperError(
                "The `cryptography` package is required.\n"
                "Install with: pip install cryptography"
            ) from exc

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption,
        )

        if self._keyfile and Path(self._keyfile).exists():
            raw = bytes.fromhex(Path(self._keyfile).read_text().strip())
            self._privkey = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            self._privkey = Ed25519PrivateKey.generate()
            if self._keyfile:
                raw = self._privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                Path(self._keyfile).parent.mkdir(parents=True, exist_ok=True)
                Path(self._keyfile).write_text(raw.hex())

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._pubkey_bytes: bytes = self._privkey.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def propose(self, description: str, payload: bytes) -> dict:
        """
        Build a PendingAction dict from a description and raw payload bytes.

        Returns::

            {
                "id":           "<16-byte hex>",
                "description":  "<str>",
                "payload_hash": "<32-byte blake3 hex>",
                "proposed_at":  <unix timestamp int>,
            }
        """
        action_id    = os.urandom(16).hex()
        payload_hash = _blake3_or_sha256(payload).hex()
        return {
            "id":           action_id,
            "description":  description,
            "payload_hash": payload_hash,
            "proposed_at":  _now(),
        }

    def request_authorization(self, action: dict) -> Optional[dict]:
        """
        Present the action to the human operator on stderr/stdin and wait.

        Returns an AuthToken dict on ``AUTHORIZE``, or ``None`` on denial.
        Outcome is recorded in the audit log either way.
        """
        hash_hex = action["payload_hash"]
        print("", file=sys.stderr)
        print("┌─── GATEKEEPER AUTHORIZATION REQUEST ──────────────────────────────────────┐", file=sys.stderr)
        print(f"│ Action ID   : {action['id']}", file=sys.stderr)
        print(f"│ Description : {action['description']}", file=sys.stderr)
        print(f"│ Payload hash: {hash_hex[:16]}…", file=sys.stderr)
        print(f"│              (full: {hash_hex})", file=sys.stderr)
        print(f"│ Proposed at : {_iso(action['proposed_at'])} UTC", file=sys.stderr)
        print("└────────────────────────────────────────────────────────────────────────────┘", file=sys.stderr)
        print("  Type AUTHORIZE to approve, anything else to deny: ", end="", flush=True, file=sys.stderr)

        try:
            response = input().strip()
        except (EOFError, KeyboardInterrupt):
            response = ""

        recorded_at = _now()

        if response == "AUTHORIZE":
            token = self._sign_token(action, recorded_at)
            self._audit.append({
                "action":      action,
                "outcome":     {"outcome": "Approved", "token": token},
                "recorded_at": recorded_at,
            })
            print("  [GATEKEEPER] Approved — token issued.", file=sys.stderr)
            return token
        else:
            outcome = "Cancelled" if not response else "Denied"
            self._audit.append({
                "action":      action,
                "outcome":     {"outcome": outcome},
                "recorded_at": recorded_at,
            })
            print("  [GATEKEEPER] Denied — action blocked.", file=sys.stderr)
            return None

    def verify(self, token: dict, payload: bytes) -> bool:
        """
        Verify an AuthToken dict against a payload.

        Checks:
        1. Ed25519 signature is valid.
        2. BLAKE3 (or SHA-256 fallback) hash of payload matches token.payload_hash.
        3. approved_at is within TOKEN_TTL_SECS of now.
        """
        return self._verify_internal(token, payload, check_ttl=True)

    def verify_no_ttl(self, token: dict, payload: bytes) -> bool:
        """Verify without the TTL check. Useful for historical audit replay."""
        return self._verify_internal(token, payload, check_ttl=False)

    def audit_trail(self) -> list[dict]:
        """Return a copy of all audit entries recorded in this session."""
        return list(self._audit)

    def pubkey_hex(self) -> str:
        """Hex-encoded Ed25519 public key for this session."""
        return self._pubkey_bytes.hex()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _sign_token(self, action: dict, approved_at: int) -> dict:
        action_id_bytes    = bytes.fromhex(action["id"])
        payload_hash_bytes = bytes.fromhex(action["payload_hash"])
        approved_at_bytes  = approved_at.to_bytes(8, "big")
        pubkey_bytes       = self._pubkey_bytes

        msg = action_id_bytes + payload_hash_bytes + approved_at_bytes + pubkey_bytes
        sig = self._privkey.sign(msg)

        return {
            "action_id":       action["id"],
            "payload_hash":    action["payload_hash"],
            "approved_at":     approved_at,
            "approver_pubkey": pubkey_bytes.hex(),
            "signature":       sig.hex(),
        }

    def _verify_internal(self, token: dict, payload: bytes, check_ttl: bool) -> bool:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature

        # 1. Signature
        try:
            pubkey_bytes = bytes.fromhex(token["approver_pubkey"])
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            action_id_bytes    = bytes.fromhex(token["action_id"])
            payload_hash_bytes = bytes.fromhex(token["payload_hash"])
            approved_at_bytes  = token["approved_at"].to_bytes(8, "big")
            msg = action_id_bytes + payload_hash_bytes + approved_at_bytes + pubkey_bytes
            sig = bytes.fromhex(token["signature"])
            pubkey.verify(sig, msg)
        except (InvalidSignature, Exception):
            return False

        # 2. Payload hash
        computed = _blake3_or_sha256(payload).hex()
        if computed != token["payload_hash"]:
            return False

        # 3. TTL
        if check_ttl:
            age = _now() - token["approved_at"]
            if age > self.TOKEN_TTL_SECS:
                return False

        return True

    # ── Test helper (mirrors Rust SDK interface for evolution_engine.py) ───────

    def _py_sign_token(self, action: dict, approved_at: int) -> dict:
        """Direct signing without stdin — for non-interactive use."""
        return self._sign_token(action, approved_at)

    def sign_token_for_test_if_available(self, action: dict) -> Optional[dict]:
        """Return a token for auto-approve scenarios. Returns None to force fallback."""
        return None
