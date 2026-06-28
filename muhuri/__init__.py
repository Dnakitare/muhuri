"""
Muhuri — splice-proof, offline-attenuating delegation credentials for AI agent
chains.

Public API:

    from muhuri import KeyPair, mint, attenuate, Muhuri
    from muhuri import authorize, verify_chain, VerifyError
    from muhuri import caveats
    from muhuri.pop import prove
    from muhuri.revocation import RevocationSet
"""
from .keys import KeyPair, verify_sig
from .credential import Link, Muhuri, mint, attenuate, now, MalformedCredential, MAX_DEPTH
from .verify import authorize, verify_chain, parse, VerifyError, Decision
from .pop import NonceStore
from . import caveats
from . import pop
from . import revocation

__all__ = [
    "KeyPair", "verify_sig", "Link", "Muhuri", "mint", "attenuate", "now",
    "MalformedCredential", "MAX_DEPTH", "NonceStore",
    "authorize", "verify_chain", "parse", "VerifyError", "Decision",
    "caveats", "pop", "revocation",
]
__version__ = "0.2.0"
