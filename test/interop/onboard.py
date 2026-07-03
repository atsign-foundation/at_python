#!/usr/bin/env python3
"""Onboard atSigns against a local ephemeral environment via CRAM.

Reads each atSign's CRAM secret from the running `atsigncompany/ephemeral` container
and runs the CRAM -> PKAM onboarding flow, writing `.atKeys` under
`$HOME/.atsign/keys`. Used by the interop CI workflow.

Usage:
    python test/interop/onboard.py @alpha @bravo     # defaults: @alpha @bravo
"""
import subprocess
import sys

from at_client.common import AtSign
from at_client.connections import Address, AtRootConnection, AtSecondaryConnection
from at_client.util import AuthUtil, KeysUtil, OnboardingUtil

ROOT = "vip.ve.atsign.zone:64"


def container_id():
    out = subprocess.check_output(
        ["docker", "ps", "--filter", "ancestor=atsigncompany/ephemeral",
         "--format", "{{.ID}}"]
    ).decode().split()
    if not out:
        raise RuntimeError("no running atsigncompany/ephemeral container found")
    return out[0]


def onboard(name, cid):
    atsign = AtSign("@" + name)
    cram = subprocess.check_output(
        ["docker", "exec", cid, "cat", f"/atsign/atservers/{name}/CRAM"]
    ).decode().strip()
    root = Address.from_string(ROOT)
    secondary = AtRootConnection.get_instance(root.host, root.port).find_secondary(atsign)
    conn = AtSecondaryConnection(secondary)
    conn.connect()
    auth, ob = AuthUtil(), OnboardingUtil()
    auth.authenticate_with_cram(conn, atsign, cram)
    keys = {}
    ob.generate_self_encryption_key(keys)
    ob.generate_pkam_keypair(keys)
    ob.generate_encryption_keypair(keys)
    KeysUtil.save_keys(atsign, keys)
    ob.store_pkam_public_key(conn, keys)
    auth.authenticate_with_pkam(conn, atsign, KeysUtil.load_keys(atsign))
    ob.store_public_encryption_key(conn, atsign.without_prefix, keys)
    ob.delete_cram_key(conn)
    print("onboarded @" + name)


def main():
    names = [a.lstrip("@") for a in (sys.argv[1:] or ["alpha", "bravo"])]
    cid = container_id()
    for name in names:
        onboard(name, cid)


if __name__ == "__main__":
    main()
