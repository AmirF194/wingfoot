# Contributing to botpass

Thanks for helping. This is a young project and there is plenty of low-hanging fruit.

## Setup

```bash
git clone https://github.com/AmirF194/botpass
cd botpass
pip install -e ".[test]"
pytest
botpass demo
```

## Ground rules

- One issue, one branch, one focused PR. Keep changes small and reviewable.
- Every behavior change ships with a test that fails without it. Tests in `tests/` are plain
  `pytest` functions.
- Be careful with the crypto. `rfc9421.py` is intentionally small and literal so it can be read
  and checked. If you change the signature base or parameter handling, add a round-trip test and
  cite the relevant RFC section.
- Match the existing style: standard library first (the only runtime dependency is
  `cryptography`), type hints, and clear CLI output.

## Good places to start

- New `doctor` checks (clock-skew hints, CDN-specific rejection signals).
- Middleware adapters for `httpx`, `requests`, and `aiohttp`.
- Interoperability tests against other Web Bot Auth implementations.

## Reporting a problem

Open an issue with what you ran, what happened, what you expected, and your OS and Python version.
For anything large, let's agree on the approach in the issue before you build it.
