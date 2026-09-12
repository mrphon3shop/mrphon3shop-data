#!/usr/bin/env python3
"""
memory_tools.py — operate on the encrypted memory repository.

  verify                 signatures + blob hashes + inventory listing
  restore --out FILE     decrypt everything into a single tar for download
  rotate --recipient K   re-encrypt every blob for a new age recipient

The identities (age + fleet signing key) are supplied as files through the
environment by the workflow; nothing here ever prints key material.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGE_KEY = os.environ.get("AGE_IDENTITY_FILE", os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "age.key"))
SIGN_KEY = os.environ.get("FLEET_SIGN_KEY_FILE", os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "fleet_sign"))
SIGNERS = os.path.join(ROOT, "keys", "allowed_signers")


def sh(args: list[str], stdin=None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, stdin=stdin)


def verify_signature(path: str) -> bool:
    sig = path + ".sig"
    if not os.path.exists(sig):
        print(f"  MISSING SIGNATURE  {os.path.relpath(path, ROOT)}")
        return False
    proc = subprocess.run(["ssh-keygen", "-Y", "verify", "-q", "-f", SIGNERS, "-I", "fleet",
                           "-n", "fleet-manifest", "-s", sig], stdin=open(path, "rb"),
                          capture_output=True, text=True)
    ok = proc.returncode == 0
    print(f"  {'ok   ' if ok else 'FAIL '} signature {os.path.relpath(path, ROOT)}")
    return ok


def cmd_verify(_args) -> int:
    failures = 0
    print("== signatures ==")
    for rel in ("state/lease.json", "state/heartbeat.json", "state/handoff.json",
                "state/funnel.json", "manifest/blobs.json", "state/watchdog.json"):
        path = os.path.join(ROOT, rel)
        if os.path.exists(path):
            failures += 0 if verify_signature(path) else 1

    print("== blobs ==")
    index_path = os.path.join(ROOT, "manifest", "blobs.json")
    index = {}
    if os.path.exists(index_path):
        try:
            index = json.load(open(index_path, encoding="utf-8")).get("blobs", {})
        except Exception as exc:  # noqa: BLE001
            print(f"  cannot parse blob index: {exc}")
            failures += 1
    for name, meta in sorted(index.items()):
        blob = os.path.join(ROOT, "blobs", f"{name}.tar.zst.age")
        if not os.path.exists(blob):
            print(f"  MISSING {name}")
            failures += 1
            continue
        digest = hashlib.sha256(open(blob, "rb").read()).hexdigest()
        ok = digest == meta.get("sha256")
        size = os.path.getsize(blob)
        print(f"  {'ok   ' if ok else 'FAIL '} {name:24s} {size/1024:8.1f} KiB  seq={meta.get('seq','-'):>4}  updated={meta.get('updated_at','-')}")
        failures += 0 if ok else 1

    print("== heartbeat ==")
    try:
        hb = json.load(open(os.path.join(ROOT, "state/heartbeat.json"), encoding="utf-8"))
        print(json.dumps(hb, indent=2)[:800])
    except Exception as exc:  # noqa: BLE001
        print(f"  unreadable: {exc}")

    print(f"\nverify finished with {failures} failure(s)")
    return 1 if failures else 0


def cmd_restore(args) -> int:
    if not os.path.exists(AGE_KEY):
        print("no age identity available")
        return 1
    blobs = sorted(os.listdir(os.path.join(ROOT, "blobs")))
    out = args.out or "/tmp/snapshot.tar"
    with tempfile.TemporaryDirectory() as tmp:
        parts = [os.path.join(tmp, "part1.tar")]
        first = True
        combined = os.path.join(tmp, "combined.tar")
        for blob in blobs:
            if not blob.endswith(".age"):
                continue
            dec = os.path.join(tmp, blob.replace(".age", ""))
            proc = sh(["age", "-d", "-i", AGE_KEY, "-o", dec, os.path.join(ROOT, "blobs", blob)])
            if proc.returncode != 0:
                print(f"  cannot decrypt {blob}: {proc.stderr.decode()[:120]}")
                continue
            # strip the tar header noise: concatenating tars is valid and simple
            with open(combined, "ab") as out_fh, open(dec, "rb") as in_fh:
                out_fh.write(in_fh.read())
            first = False
            print(f"  decrypted {blob}")
        if first:
            print("no blobs to restore")
            return 1
        os.replace(combined, out)
    print(f"snapshot written to {out} ({os.path.getsize(out)/1024/1024:.2f} MiB)")
    return 0


def cmd_rotate(args) -> int:
    recipient = args.recipient.strip()
    if not recipient.startswith("age1"):
        print("a valid age recipient (age1...) is required")
        return 1
    rotated = 0
    for blob in sorted(os.listdir(os.path.join(ROOT, "blobs"))):
        if not blob.endswith(".age"):
            continue
        path = os.path.join(ROOT, "blobs", blob)
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "plain.tar.zst")
            if sh(["age", "-d", "-i", AGE_KEY, "-o", plain, path]).returncode != 0:
                print(f"  cannot decrypt {blob} — skipped")
                continue
            enc = os.path.join(tmp, "re.tar.zst.age")
            if sh(["age", "-r", recipient, "-o", enc, plain]).returncode != 0:
                print(f"  cannot re-encrypt {blob} — skipped")
                continue
            os.replace(enc, path)
            rotated += 1
            print(f"  re-encrypted {blob}")

    index_path = os.path.join(ROOT, "manifest", "blobs.json")
    index = json.load(open(index_path, encoding="utf-8"))
    for name, meta in index.get("blobs", {}).items():
        blob = os.path.join(ROOT, "blobs", f"{name}.tar.zst.age")
        if os.path.exists(blob):
            meta["sha256"] = hashlib.sha256(open(blob, "rb").read()).hexdigest()
            meta["size"] = os.path.getsize(blob)
    index["seq"] = int(index.get("seq", 0)) + 1
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, sort_keys=True)
        fh.write("\n")
    if os.path.exists(SIGN_KEY):
        subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", SIGN_KEY,
                        "-n", "fleet-manifest", index_path], check=False)
    open(os.path.join(ROOT, "manifest", "recipient.txt"), "w", encoding="utf-8").write(recipient + "\n")
    print(f"rotated {rotated} blob(s); remember to update the AGE_IDENTITY secret in both repositories")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify").set_defaults(func=cmd_verify)
    r = sub.add_parser("restore")
    r.add_argument("--out", default="/tmp/snapshot.tar")
    r.set_defaults(func=cmd_restore)
    rot = sub.add_parser("rotate")
    rot.add_argument("--recipient", required=True)
    rot.set_defaults(func=cmd_rotate)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
