#!/usr/bin/env python3
"""asyncio client demo: subscribe to notifications as an async stream, and send one.

Usage (keys in $HOME/.atsign/keys):
    python examples/aio_demo.py @alice                     # subscribe
    python examples/aio_demo.py @alice --to @bob --send hi # notify @bob, then subscribe

Optional: --root host:port (default root.atsign.org:64), --regex <filter>
"""
import argparse
import asyncio

from at_client.aio import AsyncAtClient
from at_client.connections.address import Address


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("atsign")
    parser.add_argument("--root", default="root.atsign.org:64")
    parser.add_argument("--regex", default=".*")
    parser.add_argument("--to", help="atSign to notify")
    parser.add_argument("--send", help="value to notify --to with")
    args = parser.parse_args()

    client = await AsyncAtClient.create(args.atsign, root_address=Address.from_string(args.root))
    print(f"authenticated as {args.atsign}")

    if args.to and args.send:
        notification_id = await client.notify(args.to, "demo", args.send, namespace="aiodemo")
        print(f"notified {args.to}: {notification_id}")

    print(f"listening (regex={args.regex!r}) — Ctrl-C to stop")
    try:
        async for notification in client.monitor(regex=args.regex):
            print(f"{notification.from_atsign} -> {notification.key}: "
                  f"{notification.value if notification.decrypted else '<not decrypted>'}")
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
