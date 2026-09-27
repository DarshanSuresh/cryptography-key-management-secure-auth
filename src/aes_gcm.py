from __future__ import annotations

import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32          # 256 bits
NONCE_SIZE = 12        # 96 bits, recommended for GCM


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> dict:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, associated_data)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext_and_tag).decode(),
    }


def decrypt(key: bytes, payload: dict, associated_data: bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    nonce = base64.b64decode(payload["nonce"])
    ciphertext_and_tag = base64.b64decode(payload["ciphertext"])

    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)


if __name__ == "__main__":
    key = generate_key()
    message = b"Confidential laboratory message"
    aad = b"record:v1"

    encrypted = encrypt(key, message, aad)
    recovered = decrypt(key, encrypted, aad)

    print("AES-256-GCM demonstration")
    print("Ciphertext:", encrypted["ciphertext"])
    print("Nonce:", encrypted["nonce"])
    print("Recovered:", recovered.decode())
