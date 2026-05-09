"""RSA and EC key generation, serialization, and key exchange utilities.

Merchant integrators use these utilities to generate key pairs for:
- API client authentication (EC P-256 private_key_jwt)
- Webhook signature verification (RSA-2048 public keys)
- Point-to-point encryption with NovaPay vault endpoints

All generated keys should be stored in a hardware security module (HSM)
or an OS keychain. Never persist plaintext private keys to disk in production.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Default key sizes per use case
RSA_DEFAULT_KEY_SIZE = 2048
RSA_SIGNING_KEY_SIZE = 4096
EC_DEFAULT_CURVE = SECP256R1()


def generate_rsa_keypair(key_size: int = RSA_DEFAULT_KEY_SIZE) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair for merchant API authentication.

    Args:
        key_size: RSA modulus size in bits. Use 2048 for API auth, 4096 for signing.

    Returns:
        Tuple of (private_key, public_key).

    Example:
        >>> private_key, public_key = generate_rsa_keypair(key_size=2048)
        >>> pem = export_private_key_pem(private_key)
        >>> # Store pem in your HSM or OS keychain
    """
    private_key = generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def generate_ec_keypair(curve=None) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an EC key pair on the specified curve.

    EC P-256 (SECP256R1) is recommended for API client authentication.
    EC P-384 is required for high-assurance document signing.

    Args:
        curve: Elliptic curve instance. Defaults to SECP256R1 (P-256).

    Returns:
        Tuple of (private_key, public_key).
    """
    if curve is None:
        curve = EC_DEFAULT_CURVE
    private_key = ec.generate_private_key(curve, default_backend())
    return private_key, private_key.public_key()


def generate_rsa_signing_keypair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA-4096 key pair for document signing operations.

    Returns a 4096-bit key pair suitable for RSA-PSS document signatures
    as required by NovaPay's merchant agreement signing API.
    """
    return generate_rsa_keypair(key_size=RSA_SIGNING_KEY_SIZE)


def export_private_key_pem(private_key: RSAPrivateKey | EllipticCurvePrivateKey,
                            password: bytes | None = None) -> bytes:
    """Serialize a private key to PEM (PKCS#8 format).

    Args:
        private_key: RSA or EC private key object.
        password: Optional passphrase to encrypt the PEM output.

    Returns:
        PEM-encoded private key bytes.
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def export_public_key_pem(public_key: RSAPublicKey | EllipticCurvePublicKey) -> bytes:
    """Serialize a public key to PEM (SubjectPublicKeyInfo format)."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_to_jwk(public_key: RSAPublicKey | EllipticCurvePublicKey) -> dict:
    """Convert a public key to JSON Web Key (JWK) format.

    Used to register EC public keys with the NovaPay merchant portal
    for private_key_jwt client authentication.

    Args:
        public_key: RSA or EC public key.

    Returns:
        JWK dict suitable for publishing at a JWKS endpoint.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as RSAPub
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey as ECPub

    if isinstance(public_key, RSAPub):
        pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, 'public_key') else public_key.public_numbers()
        n = base64.urlsafe_b64encode(
            pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()
        e = base64.urlsafe_b64encode(
            pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()
        return {"kty": "RSA", "n": n, "e": e, "use": "sig", "alg": "RS256"}

    elif isinstance(public_key, ECPub):
        pub_numbers = public_key.public_numbers()
        curve = public_key.curve
        crv = {SECP256R1: "P-256", SECP384R1: "P-384", SECP521R1: "P-521"}.get(
            type(curve), "P-256"
        )
        key_size = (curve.key_size + 7) // 8
        x = base64.urlsafe_b64encode(pub_numbers.x.to_bytes(key_size, "big")).rstrip(b"=").decode()
        y = base64.urlsafe_b64encode(pub_numbers.y.to_bytes(key_size, "big")).rstrip(b"=").decode()
        return {"kty": "EC", "crv": crv, "x": x, "y": y, "use": "sig"}

    raise TypeError(f"Unsupported key type: {type(public_key)}")


def ecdh_shared_secret(
    private_key: EllipticCurvePrivateKey,
    peer_public_key: EllipticCurvePublicKey,
    info: bytes = b"novapay-session-key",
) -> bytes:
    """Derive a shared symmetric key via ECDH + HKDF.

    Used for establishing ephemeral session keys between merchant terminals
    and NovaPay's payment endpoints. The ECDH exchange is performed locally;
    the resulting shared secret is not transmitted.

    Args:
        private_key: Local EC private key (P-256 or P-384).
        peer_public_key: Counterparty's EC public key.
        info: HKDF context info string.

    Returns:
        32-byte derived key suitable for AES-256-GCM.
    """
    shared_key = private_key.exchange(ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    ).derive(shared_key)
