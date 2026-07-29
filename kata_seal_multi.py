"""kata-seal-multi -- seal a SET of miner-owned provider credentials to a Kata room.

Some lanes evaluate a submission against several independent providers -- search, scraping,
summarisation, judging -- and the miner funds all of them.  One key cannot express that, and a run
that discovers the second provider is missing has already spent the miner's money on the first.  So
the whole set is sealed together, and this tool refuses to produce a partial one.

    python3 kata_seal_multi.py --room https://<room-url> \
        --credential-profile <profile-from-your-lane-docs> \
        --providers scrapingdog,apify,openai,chutes \
        --key-env scrapingdog=SCRAPINGDOG_API_KEY \
        --key-env apify=APIFY_API_KEY \
        --key-env openai=OPENAI_API_KEY \
        --key-env chutes=CHUTES_API_KEY \
        --bundle ./my-submission \
        --measurement <approved-compose-hash>

Your lane's documentation gives you the provider list, the credential profile and the approved
measurement.  This tool contains no lane-specific knowledge, which is the point: the same base image
serves every lane, so nothing here may assume one.

What it does, all locally (your keys never leave your machine):
  1. fetch the room's public key from <room>/pubkey;
  2. VERIFY the room's attestation is a genuine TEE and matches --measurement, so you cannot be
     tricked into sealing to a room somebody else controls;
  3. bind the credential set to your agent bundle, then seal it to that public key;
  4. write the ciphertext into the bundle, atomically and 0600.

A key is never accepted as a command-line VALUE -- only as the name of an environment variable, a
0600 file, or a hidden prompt.  Command lines are world-readable in the process list.

Requirements:  pip install eciespy dcap-qvl==0.5.3
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from pathlib import Path

from kata_seal import fetch_pubkey, load_api_key, verify_room, write_atomically
from room.bundle import SEALED_CREDENTIAL_FILENAME, credential_bundle_binding
from room.ids import PROVIDER_ID_REGEX
from room.sealing import MAX_KEY_CHARS, MIN_KEY_CHARS

CREDENTIAL_VERSION = 2
_PROVIDER_PATTERN = re.compile(PROVIDER_ID_REGEX + r"\Z")


def parse_providers(raw: str) -> tuple[str, ...]:
    providers = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not providers:
        raise SystemExit("ERROR: --providers must name at least one provider.")
    if len(set(providers)) != len(providers):
        raise SystemExit("ERROR: --providers must not repeat a provider.")
    for provider in providers:
        if not _PROVIDER_PATTERN.fullmatch(provider):
            raise SystemExit(
                f"ERROR: provider id {provider!r} must be lowercase letters, digits, _ or -."
            )
    return providers


def parse_key_source(argument: str, *, flag: str) -> tuple[str, str]:
    """Split ``provider=value`` for --key-env / --key-file."""
    if "=" not in argument:
        raise SystemExit(f"ERROR: {flag} must be given as provider=value.")
    provider, value = argument.split("=", 1)
    provider, value = provider.strip(), value.strip()
    if not provider or not value:
        raise SystemExit(f"ERROR: {flag} must be given as provider=value.")
    return provider, value


def collect_keys(
    providers: tuple[str, ...],
    *,
    key_envs: dict[str, str],
    key_files: dict[str, str],
) -> dict[str, str]:
    """Load one key per provider, and refuse to seal an incomplete set.

    Refusing here is the whole value of the check.  A set that is short one key seals fine, uploads
    fine, and fails partway through a scored run -- after the miner has already paid for the
    providers that did work.
    """
    unknown = sorted((set(key_envs) | set(key_files)) - set(providers))
    if unknown:
        raise SystemExit(
            f"ERROR: key source given for provider(s) not in --providers: {', '.join(unknown)}."
        )
    both = sorted(set(key_envs) & set(key_files))
    if both:
        raise SystemExit(
            f"ERROR: provider(s) {', '.join(both)} have both --key-env and --key-file."
        )

    keys: dict[str, str] = {}
    for provider in providers:
        if provider in key_envs:
            value = load_api_key(key_env=key_envs[provider], key_file="")
        elif provider in key_files:
            value = load_api_key(key_env="", key_file=key_files[provider])
        else:
            value = getpass.getpass(f"API key for {provider} (input hidden): ").strip()
        if not value:
            raise SystemExit(f"ERROR: the key for {provider} must not be empty.")
        # Mirror the room's own validation so a key the room will refuse is caught here, on the
        # miner's machine, rather than as an attested zero on a scored duel.
        if not MIN_KEY_CHARS <= len(value) <= MAX_KEY_CHARS:
            raise SystemExit(
                f"ERROR: the key for {provider} must be "
                f"{MIN_KEY_CHARS}..{MAX_KEY_CHARS} characters."
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise SystemExit(f"ERROR: the key for {provider} contains a control character.")
        keys[provider] = value
    return keys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seal a set of miner-owned provider credentials to a Kata room."
    )
    parser.add_argument("--room", required=True, help="the room URL (absolute HTTPS)")
    parser.add_argument(
        "--credential-profile",
        required=True,
        help="the credential profile string from your lane's documentation",
    )
    parser.add_argument(
        "--providers",
        required=True,
        help="comma-separated provider ids your lane requires, e.g. a,b,c,d",
    )
    parser.add_argument(
        "--key-env",
        action="append",
        default=[],
        metavar="PROVIDER=ENVVAR",
        help="name of an environment variable holding that provider's key (repeatable)",
    )
    parser.add_argument(
        "--key-file",
        action="append",
        default=[],
        metavar="PROVIDER=PATH",
        help="0600 regular file holding that provider's key (repeatable)",
    )
    parser.add_argument(
        "--bundle",
        required=True,
        help=f"submission directory to bind to ({SEALED_CREDENTIAL_FILENAME} is excluded)",
    )
    parser.add_argument(
        "--measurement",
        default="",
        help="the approved 64-character room compose hash (required unless --no-verify)",
    )
    parser.add_argument(
        "--out",
        default="",
        help=f"output file (default: <bundle>/{SEALED_CREDENTIAL_FILENAME})",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip attestation check (NOT recommended)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    providers = parse_providers(args.providers)
    if not args.credential_profile.strip():
        raise SystemExit("ERROR: --credential-profile must not be empty.")
    if not args.no_verify and not re.fullmatch(r"[0-9a-f]{64}", args.measurement):
        raise SystemExit(
            "ERROR: --measurement must be the approved 64-character lowercase compose hash."
        )

    key_envs = dict(parse_key_source(item, flag="--key-env") for item in args.key_env)
    key_files = dict(parse_key_source(item, flag="--key-file") for item in args.key_file)

    bundle = Path(args.bundle).expanduser().resolve()
    if not bundle.is_dir():
        raise SystemExit(f"ERROR: --bundle {bundle} is not a directory.")

    # Every local check first: no key is read, and no room is contacted, until the arguments are
    # known-good.
    keys = collect_keys(providers, key_envs=key_envs, key_files=key_files)

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
        bundle_binding = credential_bundle_binding(bundle)
    except RuntimeError as exc:
        raise SystemExit(f"ERROR: cannot bind credentials to bundle: {exc}") from exc

    payload = json.dumps(
        {
            "version": CREDENTIAL_VERSION,
            "credential_profile": args.credential_profile.strip(),
            "credentials": {provider: {"api_key": keys[provider]} for provider in providers},
            "bundle_binding": bundle_binding,
        },
        separators=(",", ":"),
    )
    sealed = encrypt(pubkey, payload.encode()).hex()
    output = (
        Path(args.out).expanduser().resolve()
        if args.out
        else bundle / SEALED_CREDENTIAL_FILENAME
    )
    write_atomically(output, sealed)
    print(
        f"sealed {len(providers)} credentials -> {output} ({len(sealed)} hex chars). "
        f"Add this file to your PR."
    )


if __name__ == "__main__":
    main()
