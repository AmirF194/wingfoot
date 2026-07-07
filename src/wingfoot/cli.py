"""wingfoot command-line interface."""
from __future__ import annotations

import argparse
import sys
from urllib.parse import urlsplit

from . import DIRECTORY_PATH, __version__
from . import http as _http
from .directory import directory_json
from .doctor import doctor
from .keys import Identity, ephemeral_identity, generate_private_key, load_identity, save_identity
from .register import PROVIDERS, register
from .rfc9421 import sign_directory, sign_request
from .verifier import _Colors, demo, start_verifier


def _require_identity(C) -> Identity:
    identity = load_identity()
    if identity is None:
        print(f"{C.red}No identity yet.{C.reset} Run `wingfoot init --agent https://your-bot.example` first.",
              file=sys.stderr)
        raise SystemExit(2)
    return identity


def cmd_init(args) -> int:
    C = _Colors()
    agent = args.agent or "http://127.0.0.1:8088"
    identity = Identity(private_key=generate_private_key(), agent_url=agent.rstrip("/"))
    home = save_identity(identity)
    print(f"{C.green}Created your bot identity.{C.reset}")
    print(f"  keyid       {identity.keyid}")
    print(f"  directory   {identity.agent_url}{DIRECTORY_PATH}")
    print(f"  stored in   {home}")
    if not args.agent:
        print(f"\n{C.yellow}Note:{C.reset} using a placeholder directory URL. Re-run with "
              f"`--agent https://your-domain` once you know where you'll host the directory.")
    print(f"\nNext: `wingfoot directory` to see the JSON to host, or `wingfoot demo` to watch it work.")
    return 0


def cmd_directory(args) -> int:
    C = _Colors()
    identity = _require_identity(C)
    print(directory_json([identity.jwk]))
    if args.sign:
        if not identity.agent_url.startswith("http"):
            print(f"\n{C.yellow}Can't sign:{C.reset} no public directory URL. "
                  f"Re-run `wingfoot init --agent https://your-domain` first.", file=sys.stderr)
            return 2
        dir_url = identity.agent_url.rstrip("/") + DIRECTORY_PATH
        signed = sign_directory(dir_url, identity.private_key, identity.keyid)
        print(f"\n{C.dim}# Serve the JSON above with these response headers and "
              f"Content-Type: application/http-message-signatures-directory+json{C.reset}")
        print(f"{C.dim}# Verifiers (e.g. Cloudflare) require this signature. "
              f"Valid until epoch {signed.expires}; re-run before then to refresh.{C.reset}")
        for k, v in signed.headers.items():
            print(f"{k}: {v}")
    return 0


def cmd_serve(args) -> int:
    C = _Colors()
    identity = _require_identity(C)
    server = start_verifier(port=args.port, local_jwks=[identity.jwk])
    port = server.server_address[1]
    print(f"{C.green}Serving your key directory{C.reset} at "
          f"http://127.0.0.1:{port}{DIRECTORY_PATH}")
    print(f"{C.dim}(this endpoint also verifies signed requests; Ctrl-C to stop){C.reset}")
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
        print("\nstopped.")
    return 0


def cmd_verifier(args) -> int:
    C = _Colors()
    server = start_verifier(port=args.port, local_jwks=[], trust_local_only=False)
    port = server.server_address[1]
    print(f"{C.green}Reference verifier{C.reset} on http://127.0.0.1:{port}  "
          f"{C.dim}(fetches signer directories over HTTP; Ctrl-C to stop){C.reset}")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
        print("\nstopped.")
    return 0


def cmd_sign(args) -> int:
    C = _Colors()
    identity = load_identity() or ephemeral_identity(agent_url=_origin(args.url))
    signed = sign_request(args.url, identity.private_key, identity.keyid, identity.agent_url)
    if args.print_only:
        for k, v in signed.headers.items():
            print(f"{k}: {v}")
        return 0
    resp = _http.request(args.url, method=args.method, headers=signed.headers)
    color = C.green if 200 <= resp.status < 300 else C.red
    print(f"{color}HTTP {resp.status}{C.reset}")
    for k, v in signed.headers.items():
        print(f"{C.dim}> {k}: {v[:80]}{'...' if len(v) > 80 else ''}{C.reset}")
    if resp.body:
        print(resp.text[:600])
    return 0 if 200 <= resp.status < 300 else 1


def cmd_doctor(args) -> int:
    return doctor(args.url)


def cmd_demo(args) -> int:
    return 0 if demo() else 1


def cmd_register(args) -> int:
    C = _Colors()
    identity = _require_identity(C)
    return register(identity, args.provider, email=args.email, user_agent=args.user_agent,
                    open_browser=args.open, skip_checks=args.no_check)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wingfoot",
        description="Verified-bot identity for AI agents (Web Bot Auth / RFC 9421), "
                    "with a doctor that reports why a request was blocked.",
    )
    p.add_argument("--version", action="version", version=f"wingfoot {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("demo", help="run the unsigned/signed flow against a local verifier")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("init", help="create a lasting bot identity (keypair + directory)")
    s.add_argument("--agent", help="the origin that will host your directory, e.g. https://your-bot.example")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("directory", help="print the JWKS to host at the well-known path")
    s.add_argument("--sign", action="store_true",
                   help="also print the signed response headers verifiers require")
    s.set_defaults(func=cmd_directory)

    s = sub.add_parser("serve", help="serve your key directory (and verify) locally")
    s.add_argument("--port", type=int, default=8088)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("verifier", help="run a reference verifier for others to test against")
    s.add_argument("--port", type=int, default=8090)
    s.set_defaults(func=cmd_verifier)

    s = sub.add_parser("sign", help="send a Web-Bot-Auth-signed request to a URL")
    s.add_argument("url")
    s.add_argument("-X", "--method", default="GET")
    s.add_argument("--print-only", action="store_true", help="print the headers, don't send")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("doctor", help="diagnose why a URL blocks (or accepts) your signed agent")
    s.add_argument("url")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("register",
                       help="print a ready-to-paste registration packet for each verifier program")
    s.add_argument("provider", nargs="?", choices=[p.slug for p in PROVIDERS],
                   help="only this provider (default: all)")
    s.add_argument("--email", help="contact email to include in the packet")
    s.add_argument("--user-agent", help="your bot's User-Agent, if not wingfoot's default")
    s.add_argument("--open", action="store_true", help="also open the form in your browser")
    s.add_argument("--no-check", action="store_true", help="skip the live directory preflight")
    s.set_defaults(func=cmd_register)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
