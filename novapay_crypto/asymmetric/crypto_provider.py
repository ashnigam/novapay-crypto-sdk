"""Crypto provider — algorithm-agile dispatch over a vetted PQC library.

SELECTS algorithms from ``crypto_policy``; never implements cryptography. Every
primitive comes from the audited ``pqcrypto`` package, imported lazily so that an
algorithm you do not use never has to be installed. To change algorithms, edit
``crypto_policy.py`` — never this file. This file is yours: Qryptive generated it.

Targets pqcrypto>=1.0.0,<2 (keygen / encaps / decaps, and a verify that raises
rather than returning a bool). The upper bound is deliberate: 1.0 renamed every
function in the 0.x surface with no deprecation period.
"""
import importlib

from . import crypto_policy

# policy name -> pqcrypto module path. Add a future algorithm with ONE row.
_SIGNERS = {
    "ml-dsa-44": "pqcrypto.sign.ml_dsa_44",
    "ml-dsa-65": "pqcrypto.sign.ml_dsa_65",
    "ml-dsa-87": "pqcrypto.sign.ml_dsa_87",
}
_KEMS = {
    "ml-kem-512": "pqcrypto.kem.ml_kem_512",
    "ml-kem-768": "pqcrypto.kem.ml_kem_768",
    "ml-kem-1024": "pqcrypto.kem.ml_kem_1024",
}


def _resolve(registry, name, knob):
    try:
        module_path = registry[name]
    except KeyError:
        raise ValueError(
            "Unknown %s %r in crypto_policy; expected one of %s"
            % (knob, name, sorted(registry))
        )
    try:
        return importlib.import_module(module_path)
    except ImportError as exc:
        raise ImportError(
            "crypto_policy.%s=%r needs %s, which is not installed: %s"
            % (knob, name, module_path, exc)
        )


def _signer():
    return _resolve(_SIGNERS, crypto_policy.SIGNATURE_ALGORITHM, "SIGNATURE_ALGORITHM")


def _kem():
    return _resolve(_KEMS, crypto_policy.KEM_ALGORITHM, "KEM_ALGORITHM")


class _Provider:
    """Algorithm-agile facade for signatures and key exchange."""

    def generate_keypair(self):
        """Return (public_key, secret_key)."""
        return _signer().keygen()

    def sign(self, secret_key, message):
        """Return the signature bytes for `message`."""
        return _signer().sign(secret_key, message)

    def verify(self, public_key, message, signature):
        """Return True if the signature is valid, False if it is not.

        pqcrypto's verify() returns None on success and RAISES on failure, so a
        caller writing `if provider.verify(...)` would reject every VALID
        signature if this forwarded the return value. Normalising that to a bool
        is one of the reasons this facade exists.

        The exception type has moved between pqcrypto releases, so this catches
        broadly on purpose: a verify with a boolean-shaped API must never let an
        exception escape, whatever the library decides to call it.
        """
        try:
            _signer().verify(public_key, message, signature)
        except Exception:
            return False
        return True

    def kex_initiator(self, peer_public_key):
        """Encapsulate to the peer. Return (wire_ciphertext, shared_secret)."""
        return _kem().encaps(peer_public_key)

    def kex_responder_keypair(self):
        """Return (public_key_to_publish, private_key_to_keep)."""
        return _kem().keygen()

    def kex_responder_secret(self, private_key, wire_ciphertext):
        """Decapsulate the initiator's ciphertext. Return the shared secret."""
        return _kem().decaps(private_key, wire_ciphertext)


provider = _Provider()
