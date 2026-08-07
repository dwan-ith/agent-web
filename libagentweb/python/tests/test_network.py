from __future__ import annotations

import socket
import unittest

from libagentweb.network import (
    NetworkPolicyError,
    PinnedResolver,
    resolve_pinned_addresses,
)


class PinnedNetworkPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_connection_resolver_uses_only_policy_checked_addresses(self) -> None:
        async def lookup(_host: str, port: int):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", port),
                )
            ]

        addresses = await resolve_pinned_addresses(
            "publisher.example",
            443,
            allow_private_networks=False,
            lookup=lookup,
        )
        resolver = PinnedResolver("publisher.example", addresses)
        resolved = await resolver.resolve(
            "publisher.example",
            443,
            socket.AF_UNSPEC,
        )
        self.assertEqual([item["host"] for item in resolved], ["93.184.216.34"])
        with self.assertRaises(OSError):
            await resolver.resolve("rebound.internal", 443, socket.AF_UNSPEC)

    async def test_mixed_public_private_dns_answer_fails_closed(self) -> None:
        async def lookup(_host: str, port: int):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", port),
                ),
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                ),
            ]

        with self.assertRaisesRegex(NetworkPolicyError, "non-global"):
            await resolve_pinned_addresses(
                "publisher.example",
                443,
                allow_private_networks=False,
                lookup=lookup,
            )


if __name__ == "__main__":
    unittest.main()
