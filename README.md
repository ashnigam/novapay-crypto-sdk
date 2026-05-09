# NovaPay Crypto SDK

Python SDK for cryptographic operations used in NovaPay merchant integrations.
Provides RSA/ECDSA key management, TLS context configuration, and certificate
utilities for self-hosted payment terminals and webhook receivers.

## Installation

```bash
pip install novapay-crypto
```

## Quick Start

### Generate a client key pair for OAuth authentication

```python
from novapay_crypto.asymmetric.keys import generate_ec_keypair, public_key_to_jwk

private_key, public_key = generate_ec_keypair()

# Register the public key with your NovaPay merchant account
jwk = public_key_to_jwk(public_key)
print(jwk)  # {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}
```

### Sign API requests

```python
from novapay_crypto.asymmetric.signing import sign_client_assertion

token = sign_client_assertion(
    private_key=private_key,
    client_id="your-client-id",
    audience="https://auth.novapay.io/token",
)
```

### Configure TLS for webhook server

```python
from novapay_crypto.tls.helpers import create_webhook_server_context
from pathlib import Path

ctx = create_webhook_server_context(
    certfile=Path("/etc/ssl/server.crt"),
    keyfile=Path("/etc/ssl/server.key"),
)
```

## Cryptographic Algorithms

| Use Case | Algorithm | Key Size |
|---|---|---|
| OAuth client assertion | ECDSA ES256 | P-256 |
| Webhook signature verification | HMAC-SHA256 | 256-bit |
| Payment record signing | RSA-PSS-SHA256 | 2048–4096 |
| API request signing (legacy) | RSA-PKCS1v15 | 2048-bit |
| TLS client context | ECDHE-RSA | — |

> **Note**: RSA-based operations are under PQC migration review. Future versions
> will support ML-KEM-768 and ML-DSA-65 as drop-in replacements per NIST FIPS 203/204.

## License

Apache 2.0 — see [LICENSE](LICENSE).
