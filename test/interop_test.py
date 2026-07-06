"""
Cross-SDK IV interop test: this Python SDK <-> the Dart reference at_client.

Proves random-IV / ivNonce shared-key encryption interoperates in both directions.
GUARDED: skipped unless AT_INTEROP=1 (and a Dart SDK is on PATH), so it never affects
the normal `unittest discover` run or fork CI.

Prerequisites when AT_INTEROP=1:
  - Dart SDK on PATH
  - an atServer reachable (e.g. the ephemeral environment) at AT_ROOT
  - two onboarded atSigns with .atKeys under $HOME/.atsign/keys

Env (all optional, with EE-friendly defaults):
  AT_INTEROP=1                 enable this test
  AT_INTEROP_ATSIGN1=@alpha    atSign A
  AT_INTEROP_ATSIGN2=@bravo    atSign B
  AT_ROOT=vip.ve.atsign.zone:64   root for the Python client
  AT_ROOT_DOMAIN=vip.ve.atsign.zone   root domain for the Dart helper (host only)
"""
import os
import shutil
import subprocess
import unittest

NS = "itest"
HERE = os.path.dirname(os.path.abspath(__file__))
DART_DIR = os.path.join(HERE, "interop")

ATSIGN1 = os.environ.get("AT_INTEROP_ATSIGN1", "@alpha")
ATSIGN2 = os.environ.get("AT_INTEROP_ATSIGN2", "@bravo")
ROOT = os.environ.get("AT_ROOT", "vip.ve.atsign.zone:64")
ROOT_DOMAIN = os.environ.get("AT_ROOT_DOMAIN", ROOT.split(":")[0])

_enabled = os.environ.get("AT_INTEROP") == "1" and shutil.which("dart") is not None


@unittest.skipUnless(_enabled, "interop disabled (set AT_INTEROP=1 and install Dart)")
class InteropTest(unittest.TestCase):

    _n = 0

    @classmethod
    def setUpClass(cls):
        subprocess.run(["dart", "pub", "get"], cwd=DART_DIR, check=True,
                       capture_output=True)

    def _key(self, prefix):
        InteropTest._n += 1
        return f"{prefix}{os.getpid()}x{InteropTest._n}"

    # ---- Python side (the library under test) ----
    def _py(self, atsign, op, key, value=None, shared_with=None):
        from at_client import AtClient
        from at_client.common import AtSign
        from at_client.common.keys import SharedKey
        from at_client.connections import Address

        client = AtClient(AtSign(atsign), root_address=Address.from_string(ROOT))
        if op == "put-shared":
            k = SharedKey(key, AtSign(atsign), AtSign(shared_with))
            k.set_namespace(NS)
            client.put(k, value)
            return None
        elif op == "get-shared":
            k = SharedKey(key, AtSign(shared_with), AtSign(atsign))
            k.set_namespace(NS)
            return client.get(k)
        raise ValueError(op)

    # ---- Dart side (reference at_client) ----
    def _dart(self, atsign, op, key, value=None, shared_with=None):
        cmd = ["dart", "run", "bin/iv_interop.dart",
               "--atsign", atsign, "--root-domain", ROOT_DOMAIN, "--op", op, "--key", key]
        if value is not None:
            cmd += ["--value", value]
        if shared_with is not None:
            cmd += ["--shared-with", shared_with]
        out = subprocess.run(cmd, cwd=DART_DIR, check=True, capture_output=True, text=True)
        for line in out.stdout.splitlines():
            if line.startswith("VALUE:"):
                return line[len("VALUE:"):]
        return None

    def test_python_put_shared_dart_get_shared(self):
        """Dart reads a shared key Python wrote (Python's random IV -> Dart)."""
        key = self._key("pd")
        val = f"PY2DART_{key}"
        self._py(ATSIGN1, "put-shared", key, value=val, shared_with=ATSIGN2)
        got = self._dart(ATSIGN2, "get-shared", key, shared_with=ATSIGN1)
        self.assertEqual(got, val)

    def test_dart_put_shared_python_get_shared(self):
        """Python reads a shared key Dart wrote (Dart's random IV -> Python)."""
        key = self._key("dp")
        val = f"DART2PY_{key}"
        self._dart(ATSIGN2, "put-shared", key, value=val, shared_with=ATSIGN1)
        got = self._py(ATSIGN1, "get-shared", key, shared_with=ATSIGN2)
        self.assertEqual(got, val)


if __name__ == "__main__":
    unittest.main()
