"""botpass: verified-bot identity for AI agents.

A toolkit around Web Bot Auth (a profile of RFC 9421 HTTP Message Signatures). Sign your
agent's outbound requests with an Ed25519 key, publish the public key at a `.well-known`
directory, and diagnose why a site blocked a signed request.
"""

__version__ = "0.1.0"

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
WEB_BOT_AUTH_TAG = "web-bot-auth"
