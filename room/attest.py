"""Attestation (generic). Bind a report and its execution provenance into a quote."""

import hashlib
import json

from room.dstack import client


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def binding_payload(*, report, bundle_sha256: str, provenance: dict[str, object]) -> dict:
    """The immutable payload covered by the TEE quote for every execution backend."""
    return {
        "report": report,
        "bundle_sha256": bundle_sha256,
        "provenance": provenance,
    }


def bind_and_quote(
    report,
    nonce: bytes,
    project_key: str,
    *,
    bundle_sha256: str,
    provenance: dict[str, object],
):
    answer_hash = hashlib.sha256(canonical(report)).digest()
    binding_hash = hashlib.sha256(
        canonical(
            binding_payload(
                report=report,
                bundle_sha256=bundle_sha256,
                provenance=provenance,
            )
        )
    ).digest()
    report_data = hashlib.sha256(nonce + project_key.encode() + binding_hash).digest()
    quote = client.get_quote(report_data)
    return answer_hash, binding_hash, report_data, quote
