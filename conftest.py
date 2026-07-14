"""Test shim: fake the confidential-VM SDK (`dstack_sdk`, only real inside a TDX room) and point the
room at the in-repo FakeProfile, so the generic server can be exercised locally with no real TEE and
no subnet."""

import os
import sys
import types

os.environ.setdefault("KATA_TEE_PROFILE", "fake_profile:FakeProfile")

_fake = types.ModuleType("dstack_sdk")


class _Quote:
    def __init__(self, report_data: bytes):
        self.quote = "fake-quote:" + report_data.hex()
        self.event_log = "[]"


class _Key:
    def decode_key(self) -> bytes:
        return b"\x11" * 32


class DstackClient:  # noqa: D401 - fake
    def get_key(self, _path: str) -> "_Key":
        return _Key()

    def get_quote(self, report_data: bytes) -> "_Quote":
        return _Quote(report_data)


_fake.DstackClient = DstackClient
sys.modules.setdefault("dstack_sdk", _fake)
