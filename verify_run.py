"""Verify a kata-tee-runner result: the proof must cover the returned answer.

Usage:
  python3 verify_run.py response.json --nonce <hex>

It recomputes  report_data = sha256(nonce || project_key || sha256(canonical(binding)))
from the RETURNED answer, and checks it equals what the response claims the quote commits
to. Then you confirm on https://proof.t16z.com that the quote's report_data equals the
same value -- which proves the proof genuinely covers THIS answer (no swap, no replay).
"""
import argparse
import binascii
import hashlib
import json
import sys


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("response", help="the JSON saved from /run")
    ap.add_argument("--nonce", required=True, help="the hex nonce you sent")
    args = ap.parse_args()

    data = json.load(open(args.response, encoding="utf-8"))
    report = data["report"]
    project_key = data["project_key"]

    answer_hash = hashlib.sha256(canonical(report)).digest()
    binding = {
        "report": report,
        "bundle_sha256": data["bundle_sha256"],
        "provenance": data["provenance"],
    }
    binding_hash = hashlib.sha256(canonical(binding)).digest()
    report_data = hashlib.sha256(
        binascii.unhexlify(args.nonce) + project_key.encode() + binding_hash
    ).digest()

    print("Recomputed from the returned answer:")
    print("  answer_sha256 :", answer_hash.hex())
    print("  binding_sha256:", binding_hash.hex())
    print("  report_data   :", report_data.hex())
    print("Response claims the quote commits to:")
    print("  answer_sha256 :", data.get("answer_sha256"))
    print("  report_data   :", data.get("report_data_sha256"))

    ok = (
        answer_hash.hex() == data.get("answer_sha256")
        and binding_hash.hex() == data.get("binding_sha256")
        and report_data.hex() == data.get("report_data_sha256")
    )
    print("\nLocal match:", "PASS" if ok else "FAIL")
    print("\nFinal check: on https://proof.t16z.com, confirm the quote's report_data ==")
    print("  ", report_data.hex())
    print("If it matches, the proof genuinely covers THIS answer.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
