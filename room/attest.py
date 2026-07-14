"""Attestation (generic). Canonicalize the answer and bind it into a TDX quote's report-data so the
quote proves *this* answer for *this* project + round nonce."""

import hashlib
import json

from room.dstack import client


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def bind_and_quote(report, nonce: bytes, project_key: str):
    answer_hash = hashlib.sha256(canonical(report)).digest()
    report_data = hashlib.sha256(nonce + project_key.encode() + answer_hash).digest()
    quote = client.get_quote(report_data)
    return answer_hash, report_data, quote
