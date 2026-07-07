# wingfoot

[![CI](https://github.com/AmirF194/wingfoot/actions/workflows/ci.yml/badge.svg)](https://github.com/AmirF194/wingfoot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)

<p align="center">
  <img src="media/wingfoot-doctor.gif" alt="wingfoot doctor: a blocked 403 request becomes a verified 200 OK" width="760">
</p>

<p align="center"><em><code>wingfoot doctor</code> sends a signed request, reads the response, and tells you why a blocked <code>403</code> becomes a verified <code>200</code>.</em></p>

Verified-bot identity for AI agents, using Web Bot Auth (a profile of
[RFC 9421](https://www.rfc-editor.org/info/rfc9421/) HTTP Message Signatures).

Sign your agent's outbound HTTP requests with an Ed25519 key, publish the public key at a
well-known directory, and check whether a site accepts the signature. Includes a `doctor`
command that sends a signed request and reports why it was accepted or rejected.

Background: Cloudflare, Akamai, and Fastly increasingly block AI agents and crawlers by default.
[Web Bot Auth](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)
lets a legitimate agent prove its identity instead of being treated as a hostile scraper. Setting
it up by hand is fiddly, and a failed signature usually just returns `403` with no explanation.

## Install

Not on PyPI yet, so install from source:

```bash
git clone https://github.com/AmirF194/wingfoot
cd wingfoot
pip install -e .
wingfoot demo
```

Python 3.9+. The only runtime dependency is `cryptography`.

## Demo

`wingfoot demo` starts a local reference verifier, sends one unsigned request and one signed
request, and prints the result. It runs in a single process, so it works offline with no setup.

```console
$ wingfoot demo

1. Unsigned request
   HTTP 403 Forbidden   missing Signature-Input header

2. Signed request
   HTTP 200 OK          verified (keyid ig0azrI2bZdo...)
```

## Usage

```bash
# create a keypair and a key directory
wingfoot init --agent https://your-bot.example

# print the JWKS to publish at /.well-known/http-message-signatures-directory
wingfoot directory

# send a signed request
wingfoot sign https://example.com/

# check why a URL accepts or rejects your signed agent
wingfoot doctor https://example.com/

# get a ready-to-paste registration packet for Cloudflare, DataDome, ...
wingfoot register --email you@example.com
```

`wingfoot doctor` sends a signed request, reads the response, and prints a checklist:

```console
$ wingfoot doctor http://localhost:8088/whoami

  ok   Bot identity                       keyid RtsLV3gfcK73Ql4_...
  ok   Signature is well-formed and cryptographically valid
  ok   Key directory reachable and publishes this key
  Probing the target
  -    Unsigned request                   HTTP 403
  ok   Signed request                     HTTP 200

  Verified-bot access is working: signing changed HTTP 403 to 200.
```

When something is wrong it reports which check failed and how to fix it: expired signature, clock
skew, unreachable directory, key not listed, missing `tag="web-bot-auth"`, and so on.

## Register with verifiers

A valid signature only helps once a verifier (Cloudflare, DataDome, ...) knows your key. None of
them offer automated registration yet — each runs its own web form with a manual review behind
it. `wingfoot register` shrinks that step to copy/paste: it first checks your hosted directory
the way a reviewer would, then prints every answer their forms ask for:

```console
$ wingfoot register --email you@example.com

Preflight — what a reviewer will check
  ok   Key directory reachable
  ok   Directory publishes this key
  ok   Directory response is signed

Cloudflare — Verified Bots
  form   https://dash.cloudflare.com/?to=/:account/configurations
    Bot / agent name          your-bot.example
    User-Agent                wingfoot/0.1.0 (+https://github.com/AmirF194/wingfoot)
    Key directory URL         https://your-bot.example/.well-known/http-message-signatures-directory
    ...
```

Add `--open` to launch the forms in your browser, or name one provider: `wingfoot register datadome`.

## Commands

| Command | What it does |
|---------|--------------|
| `wingfoot demo` | Run the unsigned/signed flow against a local verifier. No setup. |
| `wingfoot init --agent <url>` | Create a lasting identity (keypair + directory). |
| `wingfoot directory` | Print the JWKS to host at the well-known path. |
| `wingfoot serve` | Serve your key directory locally (and verify requests). |
| `wingfoot sign <url>` | Send a Web-Bot-Auth-signed request. |
| `wingfoot doctor <url>` | Diagnose why a URL blocks or accepts your signed agent. |
| `wingfoot register [provider]` | Preflight your setup, then print what to paste into each verifier's registration form. |
| `wingfoot verifier` | Run a reference verifier for others to test against. |

## Use it in your code

Signing is one line — hand a wingfoot auth object to the HTTP client you already use. Every
outbound request gets a fresh Web Bot Auth signature (re-signed per call, so it never expires
mid-session). Run `wingfoot init --agent <url>` once, then:

```python
import requests, wingfoot
requests.get("https://example.com/", auth=wingfoot.requests_auth())

import httpx, wingfoot
httpx.get("https://example.com/", auth=wingfoot.httpx_auth())
```

`requests` and `httpx` are optional extras (`pip install "wingfoot[requests]"` /
`"wingfoot[httpx]"`); wingfoot itself needs only `cryptography`. Driving a different client?
`wingfoot.signed_headers(url)` returns the headers as a plain dict to merge in yourself.

## How it works

Web Bot Auth signs at least the `@authority` derived component and a `Signature-Agent` header,
with the parameter `tag="web-bot-auth"`. Three request headers carry it:

- `Signature-Agent`: the origin that hosts your key directory.
- `Signature-Input`: the covered components plus `created`, `expires`, `keyid`, `tag`.
- `Signature`: the Ed25519 signature over the RFC 9421 signature base.

A verifier fetches `<Signature-Agent>/.well-known/http-message-signatures-directory` (a JWKS),
looks up the key by its RFC 7638 thumbprint (`keyid`), and verifies the signature. The
implementation of that slice lives in [`src/wingfoot/rfc9421.py`](src/wingfoot/rfc9421.py).

## Status

Alpha (v0.1). Signing, verification, the directory, and doctor work and are covered by tests
against a reference verifier. Interoperability with a specific CDN depends on that CDN having your
registered key. Doctor confirms your side is correct so you can register with confidence.

Drop-in signing for `requests` and `httpx` ships now (see
[Use it in your code](#use-it-in-your-code)).

Planned:

- Doctor checks for Cloudflare and Akamai rejection signals.
- Middleware for `aiohttp`, plus an async `httpx` example.
- A TypeScript/Node port.

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

## References

- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/)
- [Web Bot Auth (Cloudflare docs)](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)
- [cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth)
- [HTTP Message Signatures Directory draft](https://www.ietf.org/archive/id/draft-meunier-http-message-signatures-directory-01.html)
