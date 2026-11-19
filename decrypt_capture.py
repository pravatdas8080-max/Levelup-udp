#!/usr/bin/env python3
"""
Decrypt a captured CreateClan (or any) request body using ZHD's AES keys.
Outputs exact protobuf fields so we know the schema.
"""
import sys, json
from ZHD_m import aes_decrypt, parse_proto, to_str, to_int, first
from ZHD_s import AES_KEY, AES_IV

def describe(v):
    if isinstance(v, (bytes, bytearray)):
        try:
            s = v.decode("utf-8")
            if all(32 <= ord(c) < 127 for c in s):
                return f"str({len(v)}) = {s!r}"
        except Exception:
            pass
        return f"bytes({len(v)}) = {v[:32].hex()}{'…' if len(v) > 32 else ''}"
    if isinstance(v, int):
        return f"varint = {v}"
    return f"{type(v).__name__} = {v!r}"

def main():
    print("\n" + "=" * 60)
    print("  ZHD CAPTURE DECRYPTOR")
    print("=" * 60)
    print(f"  AES key: {AES_KEY.hex()}")
    print(f"  AES iv : {AES_IV.hex()}")
    print("=" * 60 + "\n")

    print("Paste the hex ciphertext body (or pipe via stdin):")
    print("Example: 93 B3 70 98 C5 03 BC C0 66 68 CF E0 87 C7 7B 1F EF ...\n")

    raw = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    if not raw:
        lines = []
        while True:
            try:
                ln = input("▸ ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not ln:
                if lines: break
                continue
            lines.append(ln)
        raw = "\n".join(lines)

    clean = "".join(c for c in raw if c in "0123456789abcdefABCDEF")
    if len(clean) % 2:
        clean = clean[:-1]
    if not clean:
        print("No hex found.")
        return

    ct = bytes.fromhex(clean)
    print(f"\nCiphertext length: {len(ct)} bytes ({len(ct)//16} AES blocks)\n")

    plain = aes_decrypt(ct)
    if plain is None:
        print("❌ AES decrypt failed. Length must be a multiple of 16.")
        return

    print(f"Plaintext ({len(plain)} bytes):")
    print(f"  HEX: {plain.hex()}")
    try:
        print(f"  UTF: {plain.decode('utf-8', 'replace')!r}")
    except Exception:
        pass
    print()

    proto = parse_proto(plain)
    if not proto:
        print("⚠ Could not parse as protobuf. Raw bytes above ^")
        return

    print("─" * 60)
    print("  PROTobuf FIELDS  (this is what the game sends)")
    print("─" * 60)
    for fno in sorted(proto.keys()):
        v = proto[fno]
        if isinstance(v, list):
            for i, item in enumerate(v):
                print(f"  field #{fno}[{i}]: {describe(item)}")
        else:
            print(f"  field #{fno}    : {describe(v)}")
    print()
    print("─" * 60)
    print("  ANALYSIS")
    print("─" * 60)
    for fno in sorted(proto.keys()):
        v = proto[fno]
        if isinstance(v, int):
            print(f"  ✔ field #{fno} is VARINT (int) — likely BADGE or MIN_LEVEL = {v}")
        elif isinstance(v, (bytes, bytearray)):
            try:
                s = v.decode("utf-8")
                if all(32 <= ord(c) < 127 for c in s):
                    tag = "NAME" if len(s) > 6 else "TAG"
                    print(f"  ✔ field #{fno} is STRING — likely {tag} = {s!r}")
            except Exception:
                print(f"  ✔ field #{fno} is BYTES ({len(v)}B)")
    print()

if __name__ == "__main__":
    main()