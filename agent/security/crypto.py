"""Guardian Pi — Crypto Module: AES-256-GCM encryption for telemetry."""
from __future__ import annotations
import base64
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TelemetryCrypto:
    """Encrypts telemetry payloads using AES-256-GCM."""

    def __init__(self, key_b64: str | None = None):
        if key_b64:
            self.key = base64.b64decode(key_b64)
        else:
            self.key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    @property
    def key_b64(self) -> str:
        return base64.b64encode(self.key).decode()

    def encrypt(self, data: dict) -> dict:
        """Encrypt a dict payload. Returns {encrypted_data, nonce, tag}."""
        plaintext = json.dumps(data).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        # ciphertext includes the tag (last 16 bytes)
        ct, tag = ciphertext[:-16], ciphertext[-16:]
        return {
            "encrypted_data": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        }

    def decrypt(self, encrypted_data: str, nonce: str, tag: str) -> dict:
        """Decrypt an encrypted payload back to dict."""
        ct = base64.b64decode(encrypted_data)
        n = base64.b64decode(nonce)
        t = base64.b64decode(tag)
        plaintext = self.aesgcm.decrypt(n, ct + t, None)
        return json.loads(plaintext.decode("utf-8"))
