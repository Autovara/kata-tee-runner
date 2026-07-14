"""The confidential-VM client, shared by sealing (key) and attestation (quote). One instance,
bound to this image; it never leaves the room."""

from dstack_sdk import DstackClient

client = DstackClient()
