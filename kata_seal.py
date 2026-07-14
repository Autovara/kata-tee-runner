"""kata-seal -- one command for a miner to seal their inference key to a Kata room.

    python3 kata_seal.py --room https://<room-url> --key sk-your-inference-key \
        [--measurement <approved-compose-hash>] [--out sealed_inference_key]

What it does, all locally (your key never leaves your machine):
  1. fetch the room's public key from <room>/pubkey;
  2. VERIFY the room's attestation is a genuine TEE (and matches --measurement if given),
     so you can't be tricked into sealing to a fake room;
  3. seal (encrypt) your key to that public key;
  4. write the sealed blob to a file you include in your PR (default: sealed_inference_key).

Requirements:  pip install eciespy dcap-qvl
"""
import argparse
import asyncio
import inspect
import json
import sys
import time
import urllib.request


def fetch_pubkey(room: str) -> dict:
    with urllib.request.urlopen(f"{room.rstrip('/')}/pubkey", timeout=30) as r:
        return json.loads(r.read().decode())


def verify_room(quote_hex: str, expected_measurement: str | None) -> tuple[str, str]:
    """Verify the room's quote is genuine; return (measurement, tcb_status). Raises on failure."""
    import dcap_qvl

    raw = bytes.fromhex(quote_hex)
    measurement = dcap_qvl.parse_quote(raw).report.mr_config_id[1:33].hex()

    async def _v():
        col = dcap_qvl.get_collateral(dcap_qvl.PHALA_PCCS_URL, raw)
        if inspect.isawaitable(col):
            col = await col
        v = dcap_qvl.verify(raw, col, int(time.time()))
        if inspect.isawaitable(v):
            v = await v
        return v

    status = getattr(asyncio.run(_v()), "status", "")
    if status not in ("UpToDate", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded"):
        raise SystemExit(f"ERROR: room attestation is not valid (status={status}). Not sealing.")
    if expected_measurement and measurement != expected_measurement:
        raise SystemExit(
            f"ERROR: room measurement {measurement} != expected {expected_measurement}.\n"
            "This may be a FAKE room -- not sealing your key."
        )
    return measurement, status


def main() -> None:
    ap = argparse.ArgumentParser(description="Seal your inference key to a Kata room.")
    ap.add_argument("--room", required=True, help="the room URL, e.g. https://<id>-8080.dstack-...phala.network")
    ap.add_argument("--key", required=True, help="your inference API key (sk-...); stays on your machine")
    ap.add_argument("--measurement", default="", help="the approved room compose-hash (recommended)")
    ap.add_argument("--out", default="sealed_inference_key", help="output file to include in your PR")
    ap.add_argument("--no-verify", action="store_true", help="skip attestation check (NOT recommended)")
    args = ap.parse_args()

    info = fetch_pubkey(args.room)
    pubkey = info["pubkey"]

    if args.no_verify:
        print("WARNING: skipping room verification (--no-verify).", file=sys.stderr)
    else:
        measurement, status = verify_room(info["quote"], args.measurement or None)
        print(f"room verified: status={status}, measurement={measurement}")

    from ecies import encrypt

    sealed = encrypt(pubkey, args.key.encode()).hex()
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(sealed)
    print(f"sealed key -> {args.out} ({len(sealed)} hex chars). Add this file to your PR.")


if __name__ == "__main__":
    main()
