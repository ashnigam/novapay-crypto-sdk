"""RSA and ECDSA signature creation and verification for NovaPay integrations.

Provides high-level signing utilities matching NovaPay's API signature schemes:
- Webhook HMAC verification (HMAC-SHA256)
- Merchant client assertion signing (ECDSA ES256 / ES384)
- Payment record signing (RSA-PSS SHA-256)
- API request signing (RSA-PKCS1v15 SHA-256 for legacy endpoints)
"""
from pqcrypto.sign import mldsa44
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, SECP384R1, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

def sign_webhook_payload(secret: str, payload: bytes) -> str:
    """Compute HMAC-SHA256 signature for a webhook payload.

    Used to verify NovaPay outbound webhook deliveries. The secret is
    the webhook signing secret from your NovaPay merchant dashboard.

    Args:
        secret: Webhook signing secret (hex or raw string).
        payload: Raw request body bytes.

    Returns:
        Hex-encoded HMAC-SHA256 signature.

    Example:
        >>> sig = sign_webhook_payload(os.environ["NOVAPAY_WEBHOOK_SECRET"], request.body)
        >>> assert hmac.compare_digest(sig, request.headers["X-NovaPay-Signature"])
    """
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, payload, hashlib.sha256).hexdigest()

def sign_client_assertion(private_key: EllipticCurvePrivateKey, client_id: str, audience: str, algorithm: str='ES256') -> str:
    """Create a JWT client assertion signed with ECDSA for private_key_jwt auth.

    Used during the OAuth 2.0 token endpoint call to authenticate without
    transmitting the client secret. Compliant with RFC 7521 / RFC 7523.

    Args:
        private_key: EC private key (P-256 for ES256, P-384 for ES384).
        client_id: OAuth client_id registered with NovaPay.
        audience: Token endpoint URL (e.g., "https://auth.novapay.io/token").
        algorithm: "ES256" (P-256) or "ES384" (P-384).

    Returns:
        Compact JWT string for use as client_assertion parameter.
    """
    if algorithm not in ('ES256', 'ES384'):
        raise ValueError(f'Unsupported algorithm: {algorithm}')
    header = {'alg': algorithm, 'typ': 'JWT'}
    now = int(time.time())
    claims = {'iss': client_id, 'sub': client_id, 'aud': audience, 'jti': str(uuid.uuid4()), 'iat': now, 'exp': now + 300}

    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()
    signing_input = f'{b64(header)}.{b64(claims)}'.encode()
    hash_alg = hashes.SHA256() if algorithm == 'ES256' else hashes.SHA384()
    signature = private_key.sign(signing_input, ECDSA(hash_alg))
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    return f'{b64(header)}.{b64(claims)}.{sig_b64}'

def sign_payment_record_rsa(private_key: RSAPrivateKey, record: dict[str, Any]) -> bytes:
    """Sign a payment record dict with RSA-PSS-SHA256.

    Records are serialized as canonical JSON before signing. Signature
    is appended to the record when submitting to NovaPay's audit log API.

    Args:
        private_key: RSA private key (2048 or 4096-bit).
        record: Payment record dict (must be JSON-serializable).

    Returns:
        Raw signature bytes (DER-encoded for RSA-PSS).
    """
    payload = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
    return private_key.sign(payload, PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH), hashes.SHA256())

def verify_payment_record_rsa(public_key: RSAPublicKey, record: dict[str, Any], signature: bytes) -> bool:
    """Verify an RSA-PSS-SHA256 signed payment record.

    Args:
        public_key: RSA public key matching the private key used to sign.
        record: Payment record dict (must serialize identically to when signed).
        signature: Raw signature bytes from sign_payment_record_rsa.

    Returns:
        True if signature is valid, False otherwise.
    """
    payload = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
    try:
        mldsa_key.verify(signature, payload, PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        return False

def sign_api_request_rsa_pkcs1(private_key: RSAPrivateKey, request_body: bytes) -> str:
    """Sign an API request with RSA-PKCS1v15 for legacy NovaPay v1 endpoints.

    Legacy acquirer integration endpoints (v1 API) require PKCS#1 v1.5 signatures.
    New integrations should use the OAuth 2.0 bearer token flow instead.

    Args:
        private_key: RSA-2048 private key.
        request_body: Raw HTTP request body bytes.

    Returns:
        Base64-encoded signature for the X-NovaPay-Signature header.
    """
    digest = hashlib.sha256(request_body).digest()
    signature = private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode()

def verify_api_request_signature(public_key: RSAPublicKey, request_body: bytes, signature_b64: str) -> bool:
    """Verify RSA-PKCS1v15 API request signature for legacy endpoint security."""
    try:
        sig = base64.b64decode(signature_b64)
        digest = hashlib.sha256(request_body).digest()
        mldsa_key.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False