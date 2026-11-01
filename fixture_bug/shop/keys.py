"""Signing-key helpers."""

PEM_HEADER = "-----BEGIN PRIVATE KEY-----"


def load_signing_key(pem_text):
    if not pem_text.startswith(PEM_HEADER):
        raise ValueError("signing key must be a PKCS#8 PEM file")
    return pem_text


def sign(key, payload):
    return f"signed:{len(key)}:{payload}"
