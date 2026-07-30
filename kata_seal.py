"""kata-seal -- seal miner-owned provider credential(s) to a Kata room.

One tool, two credential contracts, chosen explicitly. Which one your lane wants is in your lane's
documentation; this tool contains no lane-specific knowledge, which is the point -- the same base
image serves every lane, so nothing here may assume one.

SINGLE key (version 1) -- one provider funds the run:

    python3 kata_seal.py --room https://<room-url> --provider openrouter \
        --key-env OPENROUTER_API_KEY --bundle ./my-submission \
        --measurement <approved-compose-hash> [--out sealed_inference_key]

MULTIPLE keys (version 2) -- the lane evaluates against several independent providers and the
miner funds all of them. One key cannot express that, and a run that discovers the second provider
is missing has already spent the miner's money on the first, so the whole set is sealed together
and a partial set is refused:

    python3 kata_seal.py --room https://<room-url> \
        --credential-profile <profile-from-your-lane-docs> \
        --providers scrapingdog,apify,openai,chutes \
        --key-env scrapingdog=SCRAPINGDOG_API_KEY \
        --key-env apify=APIFY_API_KEY \
        --key-env openai=OPENAI_API_KEY \
        --key-env chutes=CHUTES_API_KEY \
        --bundle ./my-submission \
        --measurement <approved-compose-hash>

The mode is never inferred. ``--provider`` and ``--providers`` are mutually exclusive and one is
required, because the room dispatches on the sealed payload's version: a version-1 credential where
the lane wants version 2 is refused at run time, after the duel has started, and a credential
failure scores zero. Guessing on the miner's behalf would make that a silent mistake.

Note that ``--key-env`` and ``--key-file`` take different forms in the two modes -- a bare name for
a single key, ``provider=name`` for a set -- and using the wrong one is diagnosed by name rather
than by a confusing lookup failure.

What it does, all locally (your keys never leave your machine):
  1. fetch the room's public key from <room>/pubkey;
  2. VERIFY the room's attestation is a genuine TEE (and matches --measurement if given), so you
     cannot be tricked into sealing to a room somebody else controls;
  3. bind the credential(s) to the agent bundle, then seal them to that public key;
  4. write the sealed blob to a file you include in your PR (default: sealed_inference_key).

A key is never accepted as a command-line VALUE -- only as the name of an environment variable, a
0600 file, or a hidden prompt. Command lines are world-readable in the process list.

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
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from room.bundle import SEALED_CREDENTIAL_FILENAME, credential_bundle_binding
from room.ids import PROVIDER_ID_REGEX
from room.sealing import MAX_KEY_CHARS, MIN_KEY_CHARS

#: The room dispatches on this field; see ``room/profile.py``.
CREDENTIAL_VERSION_SINGLE = 1
CREDENTIAL_VERSION_MULTI = 2

_PROVIDER_PATTERN = re.compile(PROVIDER_ID_REGEX + r"\Z")

#: TCB states in which a room is safe to seal to: fully patched, or patched but wanting software
#: hardening for which no advisory applies here. Everything else -- CONFIGURATION_NEEDED,
#: OUT_OF_DATE, REVOKED and their combinations -- stays refused.
#:
#: Each state is listed in BOTH spellings, and that is the whole point of this set rather than a
#: literal. ``dcap-qvl`` ships a type stub documenting ``OK``/``SW_HARDENING_NEEDED``, but the
#: compiled extension in the pinned 0.5.3 returns Intel's raw TCB names ``UpToDate``/
#: ``SWHardeningNeeded``. The two vocabularies do not intersect, so a check written from the stub
#: refuses every genuinely healthy room -- which is exactly what shipped: from 2026-07-28, when this
#: verification was added, until this fix, NO miner could seal a key at all, against a room that was
#: attesting perfectly (``UpToDate`` with an empty advisory list).
#:
#: Both spellings are kept because the mismatch is the library's, not ours, and a future release
#: correcting its own extension to match its own stub must not break sealing a second time.
HEALTHY_TCB_STATUSES = frozenset({
    "OK", "SW_HARDENING_NEEDED",        # as documented in dcap_qvl's .pyi stub
    "UpToDate", "SWHardeningNeeded",    # as actually returned by the compiled dcap-qvl 0.5.3
})


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
    if status not in HEALTHY_TCB_STATUSES:
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


def write_atomically(path: Path, text: str) -> None:
    """Write 0600, atomically, or leave the previous file untouched.

    A half-written ciphertext is worse than none: it looks like a submitted credential, and the
    miner finds out it was truncated when their duel comes back zeroed.  The temporary file is
    created in the destination directory so the replace is a rename within one filesystem.
    """
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(directory), prefix=".kata-seal-")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        # Never leave the plaintext-adjacent temporary behind on any failure, including Ctrl-C.
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise




# --- the multi-key contract (version 2) ---------------------------------------------------------


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
    """Split ``provider=value`` for --key-env / --key-file in multi-key mode."""
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


# --- one CLI ------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seal miner-owned provider credential(s) to a Kata room."
    )
    parser.add_argument(
        "--room",
        required=True,
        help="the room URL, e.g. https://<id>-8080.dstack-...phala.network",
    )
    # Mutually exclusive AND required: the mode decides the sealed payload's version, and the room
    # refuses the wrong one at run time rather than at seal time.
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--provider",
        default="",
        help="SINGLE-key mode: the one approved provider id, e.g. openrouter",
    )
    mode.add_argument(
        "--providers",
        default="",
        help="MULTI-key mode: comma-separated provider ids your lane requires, e.g. a,b,c,d",
    )
    parser.add_argument(
        "--credential-profile",
        default="",
        help="MULTI-key mode only: the credential profile string from your lane's documentation",
    )
    parser.add_argument(
        "--key-env",
        action="append",
        default=[],
        metavar="ENVVAR | PROVIDER=ENVVAR",
        help=(
            "name of an environment variable holding a provider key. Single-key mode takes a bare "
            "name; multi-key mode takes provider=ENVVAR and is repeatable"
        ),
    )
    parser.add_argument(
        "--key-file",
        action="append",
        default=[],
        metavar="PATH | PROVIDER=PATH",
        help=(
            "0600 regular file holding a provider key. Single-key mode takes a bare path; "
            "multi-key mode takes provider=PATH and is repeatable. Omit both key options for a "
            "hidden prompt"
        ),
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
        help=(
            f"output file (default: <bundle>/{SEALED_CREDENTIAL_FILENAME}, so the ciphertext is "
            "written into the exact bundle it was bound to)"
        ),
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip attestation check (NOT recommended)",
    )
    return parser


def _single_key_source(values: list[str], *, flag: str) -> str:
    """The one bare value for --key-env / --key-file in single-key mode.

    Diagnoses the multi-key form by name. Left alone it would be a baffling failure: ``--key-env
    openai=OPENAI_API_KEY`` would look up an environment variable literally called
    "openai=OPENAI_API_KEY", find nothing, and report an empty key.
    """
    if not values:
        return ""
    if len(values) > 1:
        raise SystemExit(
            f"ERROR: {flag} may be given once in single-key mode. Use --providers for a set."
        )
    value = values[0]
    head = value.split("=", 1)[0].strip()
    if "=" in value and _PROVIDER_PATTERN.fullmatch(head):
        raise SystemExit(
            f"ERROR: {flag} {value!r} is the multi-key form, but --provider selects single-key "
            f"mode. Pass a bare value here, or use --providers with --credential-profile."
        )
    return value


def _seal(*, args, plaintext: str, bundle: Path, summary: str) -> None:
    """Everything after the arguments are known-good; identical for both contracts."""
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

    sealed = encrypt(pubkey, plaintext.encode()).hex()
    output = (
        Path(args.out).expanduser().resolve()
        if args.out
        else bundle / SEALED_CREDENTIAL_FILENAME
    )
    write_atomically(output, sealed)
    print(f"{summary} -> {output} ({len(sealed)} hex chars). Add this file to your PR.")


def main() -> None:
    args = build_parser().parse_args()
    if not args.no_verify and not re.fullmatch(r"[0-9a-f]{64}", args.measurement):
        raise SystemExit(
            "ERROR: --measurement must be the approved 64-character lowercase compose hash."
        )
    bundle = Path(args.bundle).expanduser().resolve()
    if not bundle.is_dir():
        raise SystemExit(f"ERROR: --bundle {bundle} is not a directory.")

    if args.provider:
        if args.credential_profile.strip():
            raise SystemExit(
                "ERROR: --credential-profile belongs to multi-key mode; use --providers."
            )
        if not re.fullmatch(PROVIDER_ID_REGEX, args.provider):
            raise SystemExit("ERROR: --provider must use lowercase letters, digits, _ or -.")
        key_env = _single_key_source(args.key_env, flag="--key-env")
        key_file = _single_key_source(args.key_file, flag="--key-file")
        if key_env and key_file:
            raise SystemExit("ERROR: --key-env and --key-file are mutually exclusive.")
        api_key = load_api_key(key_env=key_env, key_file=key_file)
        try:
            bundle_binding = credential_bundle_binding(bundle)
        except RuntimeError as exc:
            raise SystemExit(f"ERROR: cannot bind credential to bundle: {exc}") from exc
        plaintext = json.dumps(
            {
                "version": CREDENTIAL_VERSION_SINGLE,
                "provider": args.provider,
                "api_key": api_key,
                "bundle_binding": bundle_binding,
            },
            separators=(",", ":"),
        )
        _seal(args=args, plaintext=plaintext, bundle=bundle, summary="sealed credential")
        return

    providers = parse_providers(args.providers)
    if not args.credential_profile.strip():
        raise SystemExit("ERROR: --credential-profile must not be empty.")
    key_envs = dict(parse_key_source(item, flag="--key-env") for item in args.key_env)
    key_files = dict(parse_key_source(item, flag="--key-file") for item in args.key_file)
    # Every local check first: no key is read, and no room is contacted, until the arguments are
    # known-good.
    keys = collect_keys(providers, key_envs=key_envs, key_files=key_files)
    try:
        bundle_binding = credential_bundle_binding(bundle)
    except RuntimeError as exc:
        raise SystemExit(f"ERROR: cannot bind credentials to bundle: {exc}") from exc
    plaintext = json.dumps(
        {
            "version": CREDENTIAL_VERSION_MULTI,
            "credential_profile": args.credential_profile.strip(),
            "credentials": {provider: {"api_key": keys[provider]} for provider in providers},
            "bundle_binding": bundle_binding,
        },
        separators=(",", ":"),
    )
    _seal(
        args=args, plaintext=plaintext, bundle=bundle,
        summary=f"sealed {len(providers)} credentials",
    )


if __name__ == "__main__":
    main()
