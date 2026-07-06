# Cross-SDK IV interop test

`test/interop_test.py` verifies that this Python SDK and the Dart
reference `at_client` interoperate for random-IV / `ivNonce` shared-key
encryption, in both directions:

- Python `put` shared -> Dart `get` shared (Python's random IV read by Dart)
- Dart `put` shared -> Python `get` shared (Dart's random IV read by Python)

This directory holds the Dart helper (`bin/iv_interop.dart` +
`pubspec.yaml`) the test shells out to.

## Guarded - off by default

`interop_test.py` is discovered by the normal `unittest` run but **skips**
unless `AT_INTEROP=1` and a Dart SDK is on PATH, so it never affects
standard/fork CI.

## Run locally

Prerequisites: Dart SDK; an atServer reachable (e.g. the ephemeral
environment); two onboarded atSigns with `.atKeys` under
`$HOME/.atsign/keys`.

```bash
# EE example: @alpha and @bravo onboarded, keys in /tmp/eehome/.atsign/keys
HOME=/tmp/eehome AT_INTEROP=1 \
  AT_ROOT=vip.ve.atsign.zone:64 AT_ROOT_DOMAIN=vip.ve.atsign.zone \
  python -m unittest discover -s test -p 'interop_test.py' -v
```

Env (all optional, EE-friendly defaults): `AT_INTEROP_ATSIGN1`
(`@alpha`), `AT_INTEROP_ATSIGN2` (`@bravo`), `AT_ROOT`
(`vip.ve.atsign.zone:64`), `AT_ROOT_DOMAIN` (host of `AT_ROOT`).

> Re-running against a **recreated** EE? Clear the Dart client's local
> storage first (`rm -rf $HOME/.atsign/storage`) - it caches keys from the
> previous atServer and will otherwise fail to decrypt after re-onboarding.
> A fresh CI runner never hits this.

## CI

An opt-in workflow is in `.github/workflows/interop.yml` (manual
`workflow_dispatch`): it starts the ephemeral environment, onboards two
atSigns, installs dependencies, and runs this test with `AT_INTEROP=1`.
