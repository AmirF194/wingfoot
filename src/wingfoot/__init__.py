"""wingfoot: verified-bot identity for AI agents.

A toolkit around Web Bot Auth (a profile of RFC 9421 HTTP Message Signatures). Sign your
agent's outbound requests with an Ed25519 key, publish the public key at a `.well-known`
directory, and diagnose why a site blocked a signed request.
"""

__version__ = "0.1.0"

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
WEB_BOT_AUTH_TAG = "web-bot-auth"
# Tag for the signature ON the key directory response itself (RFC 9421 directory
# draft §5.2), distinct from the per-request WEB_BOT_AUTH_TAG. Verifiers such as
# Cloudflare require the directory to carry its own signature so no one can mirror
# it and register on your behalf.
DIRECTORY_TAG = "http-message-signatures-directory"

# Drop-in signing for requests / httpx. Imported last so the constants above are
# already defined (integrations -> rfc9421 -> `from . import WEB_BOT_AUTH_TAG`).
from .integrations import httpx_auth, requests_auth, signed_headers  # noqa: E402

__all__ = ["httpx_auth", "requests_auth", "signed_headers", "__version__"]
