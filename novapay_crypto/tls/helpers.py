"""TLS context helpers for NovaPay SDK integrations.

On-premise merchants and self-hosted integrators use these helpers to configure
TLS connections to NovaPay's payment and webhook APIs. Supports TLS 1.2 / 1.3
with cipher suite configuration for PCI DSS compliance.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# PCI DSS v4.0 approved cipher suites for payment data in transit
PCI_CIPHER_SUITES = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256"
)

# Extended cipher set for legacy acquirer integrations (TLS 1.2 only)
LEGACY_CIPHER_SUITES = (
    "ECDHE-RSA-AES256-SHA384:"
    "ECDHE-RSA-AES128-SHA256:"
    "RSA-AES256-SHA256:"
    "RSA-AES128-SHA256"
)

NOVAPAY_API_HOSTNAME = "api.novapay.io"
NOVAPAY_PAYMENT_HOSTNAME = "payment.novapay.io"


def create_payment_api_context(
    client_cert: Optional[Path] = None,
    client_key: Optional[Path] = None,
) -> ssl.SSLContext:
    """Create a TLS context for connecting to NovaPay's Payment API.

    Enforces TLS 1.2+ with ECDHE cipher suites for forward secrecy.
    Optionally configures mutual TLS for enterprise merchant accounts.

    Args:
        client_cert: Path to the PEM client certificate (mTLS only).
        client_key: Path to the PEM client private key (mTLS only).

    Returns:
        Configured SSLContext ready for use with httpx, aiohttp, or requests.

    Example:
        >>> ctx = create_payment_api_context()
        >>> response = requests.post(
        ...     "https://api.novapay.io/v2/charges",
        ...     json=charge_data,
        ...     headers={"Authorization": f"Bearer {access_token}"},
        ...     verify=True,
        ... )
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(PCI_CIPHER_SUITES)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()

    if client_cert and client_key:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
        logger.debug("mTLS client certificate loaded: %s", client_cert)

    return ctx


def create_webhook_server_context(
    certfile: Path,
    keyfile: Path,
    ca_bundle: Optional[Path] = None,
) -> ssl.SSLContext:
    """Create a TLS server context for merchants hosting their own webhook receivers.

    Merchants self-hosting webhook endpoints should use this context to ensure
    NovaPay's webhook delivery agent can authenticate the server certificate.

    Args:
        certfile: Path to PEM server certificate (must be signed by a trusted CA).
        keyfile: Path to PEM server private key (RSA-2048 or ECDSA P-256).
        ca_bundle: CA bundle for verifying NovaPay's client certificate (mTLS).

    Returns:
        Configured SSLContext for binding to port 443.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers(PCI_CIPHER_SUITES)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    if ca_bundle:
        ctx.load_verify_locations(cafile=str(ca_bundle))
        ctx.verify_mode = ssl.CERT_OPTIONAL

    return ctx


def create_legacy_acquirer_context() -> ssl.SSLContext:
    """Create a TLS context for connecting to legacy payment processor APIs.

    Some older payment processors (pre-2020 gateway deployments) only support
    TLS 1.2 with RSA key exchange. This context allows connection to those
    endpoints while maintaining certificate verification.

    Note: This context is restricted to known legacy endpoints. Do not use
    for new integrations — use create_payment_api_context() instead.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(LEGACY_CIPHER_SUITES)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()

    logger.warning(
        "Legacy acquirer TLS context — RSA key exchange enabled. "
        "Restrict to: %s and approved legacy endpoints only.",
        ["legacy-processor.acquirer.net", "pos-gateway.banknet.com"],
    )
    return ctx
