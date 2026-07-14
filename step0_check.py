"""A6 Step 0 -- confirm the attestation verifier against a REAL quote.

Reads the quote from a response.json (from an A3 /run), parses it with dcap-qvl, and prints
the real fields + names. Paste the output back so we can finalize DcapQvlVerifier if any
attribute/function name differs from what we assumed.

Usage:
  pip install dcap-qvl            # in a venv
  python3 step0_check.py response.json
"""
import json
import sys
import time


def h(obj, name):
    v = getattr(obj, name, None)
    if v is None:
        return None
    try:
        return v.hex()
    except Exception:
        return str(v)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "response.json"
    data = json.load(open(path, encoding="utf-8"))
    quote_hex = data["quote"]
    expected_rd = data.get("report_data_sha256", "")
    raw = bytes.fromhex(quote_hex)

    import dcap_qvl

    print("dcap_qvl functions:", [x for x in dir(dcap_qvl) if not x.startswith("_")])

    parse = getattr(dcap_qvl, "parse_quote", None) or getattr(dcap_qvl, "parse", None)
    if parse is None:
        print("!! no parse_quote/parse function -- paste the functions list above")
        return
    q = parse(raw)
    report = getattr(q, "report", q)
    print("report attrs:", [x for x in dir(report) if not x.startswith("_")])
    for name in ("report_data", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3", "mr_td", "mrtd", "mr_config_id"):
        val = h(report, name)
        if val is not None:
            print(f"  {name}: {val}")

    mci = getattr(report, "mr_config_id", None)
    if mci is not None:
        print("\n  >>> compose-hash (ALLOW-LIST THIS):", mci[1:33].hex())

    print("\nexpected report_data (from the runner):", expected_rd)
    rd = h(report, "report_data") or ""
    print("MATCH:" , "YES" if rd.startswith(expected_rd) and expected_rd else "check the two above")

    # signature / TCB verification -- get_collateral/verify are async, so run in a loop.
    try:
        import asyncio
        import inspect

        async def _verify():
            col = dcap_qvl.get_collateral(dcap_qvl.PHALA_PCCS_URL, raw)
            if inspect.isawaitable(col):
                col = await col
            v = dcap_qvl.verify(raw, col, int(time.time()))
            if inspect.isawaitable(v):
                v = await v
            return v

        verified = asyncio.run(_verify())
        print("\nverify status:", getattr(verified, "status", verified))
    except Exception as exc:  # noqa: BLE001
        print("\nverify() call needs adjusting:", repr(exc))
        print("(paste this + the functions list; it's a one-line fix)")


if __name__ == "__main__":
    main()
