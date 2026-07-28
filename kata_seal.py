"""kata-seal -- seal a miner-owned provider credential to a Kata room.

    python3 kata_seal.py --room https://<room-url> --provider openrouter \
        --key-env OPENROUTER_API_KEY --bundle ./my-submission \
        --measurement <approved-compose-hash> [--out sealed_inference_key]

What it does, all locally (your key never leaves your machine):
  1. fetch the room's public key from <room>/pubkey;
  2. VERIFY the room's attestation is a genuine TEE (and matches --measurement if given),
     so you can't be tricked into sealing to a fake room;
  3. bind your provider credential to the agent bundle, then seal it to that public key;
  4. write the sealed blob to a file you include in your PR (default: sealed_inference_key).

Requirements:  pip install eciespy dcap-qvl==0.5.3
"""

import argparse
import asyncio
import getpass
import hashlib
import hmac
import inspect
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from room.bundle import credential_bundle_binding
from room.ids import PROVIDER_ID_REGEX


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def fetch_pubkey(room: str) -> dict:
    url = room.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit(
            "ERROR: --room must be an absolute HTTPS URL without embedded credentials."
        )
    opener = urllib.request.build_opener(_RejectRedirects)
    with opener.open(f"{url}/pubkey", timeout=30) as response:
        body = response.read(64 * 1024 + 1)
    if len(body) > 64 * 1024:
        raise SystemExit("ERROR: room /pubkey response is unexpectedly large.")
    try:
        document = json.loads(body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("ERROR: room /pubkey did not return valid JSON.") from exc
    if not isinstance(document, dict):
        raise SystemExit("ERROR: room /pubkey did not return an object.")
    return document


def verify_room(
    quote_hex: str,
    pubkey: str,
    expected_measurement: str,
) -> tuple[str, str]:
    """Verify the room's quote is genuine; return (measurement, tcb_status). Raises on failure."""
    import dcap_qvl

    try:
        raw = bytes.fromhex(quote_hex)
    except (TypeError, ValueError) as exc:
        raise SystemExit("ERROR: room returned a malformed quote.") from exc
    parsed = dcap_qvl.parse_quote(raw)
    if hasattr(parsed, "is_tdx") and not parsed.is_tdx():
        raise SystemExit("ERROR: room attestation is not a TDX quote. Not sealing.")
    report = parsed.report
    mr_config_id = bytes(report.mr_config_id)
    report_data = bytes(report.report_data)
    if len(mr_config_id) < 33 or len(report_data) < 32:
        raise SystemExit("ERROR: room TDX quote is incomplete. Not sealing.")
    measurement = mr_config_id[1:33].hex()

    async def _v():
        col = dcap_qvl.get_collateral(dcap_qvl.PHALA_PCCS_URL, raw)
        if inspect.isawaitable(col):
            col = await col
        v = dcap_qvl.verify(raw, col, int(time.time()))
        if inspect.isawaitable(v):
            v = await v
        return v

    status = getattr(asyncio.run(_v()), "status", "")
    if status not in ("OK", "SW_HARDENING_NEEDED"):
        raise SystemExit(f"ERROR: room attestation is not valid (status={status}). Not sealing.")
    if measurement != expected_measurement:
        raise SystemExit(
            f"ERROR: room measurement {measurement} != expected {expected_measurement}.\n"
            "This may be a FAKE room -- not sealing your key."
        )
    if (
        not isinstance(pubkey, str)
        or len(pubkey) != 66
        or any(character not in "0123456789abcdef" for character in pubkey)
    ):
        raise SystemExit("ERROR: room returned a malformed sealing public key.")
    expected_binding = hashlib.sha256(
        b"kata-sealing-pubkey:" + bytes.fromhex(pubkey)
    ).digest()
    if not hmac.compare_digest(report_data[:32], expected_binding):
        raise SystemExit(
            "ERROR: room quote does not bind the published sealing key. Not sealing."
        )
    return measurement, status


def load_api_key(*, key_env: str, key_file: str) -> str:
    """Load a credential without putting it in shell history or the process list."""

    if key_env:
        value = os.environ.get(key_env, "")
        source = f"environment variable {key_env}"
    elif key_file:
        path = Path(key_file).expanduser()
        try:
            info = path.lstat()
        except OSError as exc:
            raise SystemExit(f"ERROR: cannot read --key-file: {exc}") from exc
        if path.is_symlink() or not path.is_file():
            raise SystemExit("ERROR: --key-file must be a regular file, not a symlink.")
        if info.st_mode & 0o077:
            raise SystemExit("ERROR: --key-file must not be readable or writable by group/other.")
        try:
            value = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"ERROR: cannot read --key-file: {exc}") from exc
        source = "--key-file"
    else:
        value = getpass.getpass("Provider API key (input hidden): ")
        source = "interactive input"
    if not value.strip():
        raise SystemExit(f"ERROR: provider key from {source} must not be empty.")
    return value.strip()


def main() -> None:
    ap = argparse.ArgumentParser(description="Seal your provider credential to a Kata room.")
    ap.add_argument(
        "--room",
        required=True,
        help="the room URL, e.g. https://<id>-8080.dstack-...phala.network",
    )
    key_source = ap.add_mutually_exclusive_group()
    key_source.add_argument(
        "--key-env",
        default="",
        help="name of an environment variable holding the provider key",
    )
    key_source.add_argument(
        "--key-file",
        default="",
        help=(
            "0600 regular file holding the provider key; omit both key options "
            "for a hidden prompt"
        ),
    )
    ap.add_argument(
        "--provider",
        required=True,
        help="approved provider id, for example openrouter, chutes, or akashml",
    )
    ap.add_argument(
        "--bundle",
        required=True,
        help="submission directory to bind to this credential (sealed_inference_key is excluded)",
    )
    ap.add_argument(
        "--measurement",
        default="",
        help="the approved 64-character room compose hash (required unless --no-verify)",
    )
    ap.add_argument(
        "--out",
        default="",
        help=(
            "output file (default: <bundle>/sealed_inference_key, so the ciphertext is written "
            "into the exact bundle it was bound to)"
        ),
    )
    ap.add_argument(
        "--no-verify",
        action="store_true",
        help="skip attestation check (NOT recommended)",
    )
    args = ap.parse_args()
    if not re.fullmatch(PROVIDER_ID_REGEX, args.provider):
        raise SystemExit("ERROR: --provider must use lowercase letters, digits, _ or -.")
    api_key = load_api_key(key_env=args.key_env, key_file=args.key_file)
    if not args.no_verify and not re.fullmatch(r"[0-9a-f]{64}", args.measurement):
        raise SystemExit(
            "ERROR: --measurement must be the approved 64-character lowercase compose hash."
        )

    info = fetch_pubkey(args.room)
    pubkey = info.get("pubkey")
    quote = info.get("quote")
    if not isinstance(pubkey, str) or not isinstance(quote, str):
        raise SystemExit("ERROR: room /pubkey response is missing pubkey or quote.")

    if args.no_verify:
        print(
            "DANGER: skipping room verification (--no-verify); use only with a room you control.",
            file=sys.stderr,
        )
    else:
        measurement, status = verify_room(quote, pubkey, args.measurement)
        print(f"room verified: status={status}, measurement={measurement}")

    from ecies import encrypt

    try:
        bundle_binding = credential_bundle_binding(Path(args.bundle).expanduser().resolve())
    except RuntimeError as exc:
        raise SystemExit(f"ERROR: cannot bind credential to bundle: {exc}") from exc
    descriptor = json.dumps(
        {
            "version": 1,
            "provider": args.provider,
            "api_key": api_key,
            "bundle_binding": bundle_binding,
        },
        separators=(",", ":"),
    )
    sealed = encrypt(pubkey, descriptor.encode()).hex()
    output = (
        Path(args.out).expanduser().resolve()
        if args.out
        else Path(args.bundle).expanduser().resolve() / "sealed_inference_key"
    )
    with open(output, "w", encoding="utf-8") as f:
        f.write(sealed)
    print(f"sealed credential -> {output} ({len(sealed)} hex chars). Add this file to your PR.")


if __name__ == "__main__":
    main()
