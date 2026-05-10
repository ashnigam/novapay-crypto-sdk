"""Certificate management utilities for NovaPay merchant integrations.

Handles RSA certificate generation for local development, certificate chain
validation, and JWK endpoint publication for OAuth client public keys.

Production merchants should use ACM-managed certificates. This module is
intended for local development, on-premise deployments, and SDK testing.
"""

from __future__ import annotations
from pqcrypto.sign import ml_dsa_44 as mldsa44

import datetime
import ipaddress
import logging
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import (
    Certificate,
    CertificateBuilder,
    DNSName,
    IPAddress,
    NameAttribute,
    NameOID,
    random_serial_number,
)
from cryptography.x509.oid import ExtendedKeyUsageOID

logger = logging.getLogger(__name__)


def generate_self_signed_cert(
    common_name: str,
    san_domains: List[str] | None = None,
    san_ips: List[str] | None = None,
    key_size: int = 2048,
    valid_days: int = 365,
) -> tuple[RSAPrivateKey, Certificate]:
    """Generate a self-signed RSA certificate for local webhook server testing.

    Do NOT use self-signed certificates in production. Use ACM-issued or
    CA-signed certificates for all production webhook endpoints.

    Args:
        common_name: Certificate CN (e.g., "localhost" or "webhook.internal").
        san_domains: Subject Alternative Names for DNS hostnames.
        san_ips: Subject Alternative Names for IP addresses.
        key_size: RSA key size (2048 recommended for dev; 4096 for staging).
        valid_days: Certificate validity period in days.

    Returns:
        Tuple of (private_key, certificate).

    Example:
        >>> key, cert = generate_self_signed_cert(
        ...     "localhost",
        ...     san_domains=["localhost", "webhook.local"],
        ...     san_ips=["127.0.0.1"],
        ... )
        >>> # Write to disk for local server
        >>> Path("server.key").write_bytes(export_key_pem(key))
        >>> Path("server.crt").write_bytes(export_cert_pem(cert))
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    subject = issuer = x509.Name([
        NameAttribute(NameOID.COUNTRY_NAME, "US"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "NovaPay Development"),
        NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
        NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.utcnow()
    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [DNSName(d) for d in (san_domains or [common_name])]
                + [IPAddress(ipaddress.ip_address(ip)) for ip in (san_ips or [])]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())
    logger.info("Generated self-signed RSA-%d cert for CN=%s (valid %d days)", key_size, common_name, valid_days)
    return private_key, cert


def generate_ca_signed_cert(
    ca_key: RSAPrivateKey,
    ca_cert: Certificate,
    common_name: str,
    san_domains: List[str] | None = None,
    key_size: int = 2048,
    valid_days: int = 730,
) -> tuple[RSAPrivateKey, Certificate]:
    """Generate an RSA certificate signed by a local CA for integration testing.

    Used in multi-service integration test environments where services need
    to verify each other's certificates against a shared test CA.

    Args:
        ca_key: Private key of the signing CA.
        ca_cert: Certificate of the signing CA.
        common_name: Certificate subject CN.
        san_domains: DNS SANs for the issued certificate.
        key_size: RSA key size for the new certificate.
        valid_days: Validity period in days.

    Returns:
        Tuple of (private_key, signed_certificate).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    now = datetime.datetime.utcnow()
    builder = (
        CertificateBuilder()
        .subject_name(x509.Name([
            NameAttribute(NameOID.ORGANIZATION_NAME, "NovaPay Integration Test"),
            NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [DNSName(d) for d in (san_domains or [common_name])]
            ),
            critical=False,
        )
    )

    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    return private_key, cert


def export_key_pem(private_key: RSAPrivateKey, password: bytes | None = None) -> bytes:
    """Export RSA private key to PEM format."""
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def export_cert_pem(cert: Certificate) -> bytes:
    """Export certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)


def validate_cert_chain(cert: Certificate, ca_cert: Certificate) -> bool:
    """Validate that cert is signed by ca_cert.

    Basic chain validation without OCSP/CRL checks — for integration testing only.
    """
    try:
        ca_public_key = ca_cert.public_key()
        mldsa44.verify(ca_public_key, cert.tbs_certificate_bytes, cert.signature)
        return True
    except Exception as exc:
        logger.debug("Certificate chain validation failed: %s", exc)
        return False
