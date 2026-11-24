# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors

"""Inputs for the ocsf-vectors job.

jwks KID AUTHORITY (--pem PATH | --scalar HEX)
    Print a one-key JWKS for the verifier: the P-256 public key of a PKCS#8
    PEM, or of the demo scalar the examples sign with (a byte repeated 32
    times), bound to the authority_uid the records name.
ndjson
    Read the pretty records an example prints on stdin and write one
    compact record per line, skipping the `//` comment lines.
unsigned
    Remove signatures from each NDJSON record without changing its fingerprint.
"""

import argparse
import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def b64url(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()


def jwks(args: argparse.Namespace) -> None:
    if args.pem:
        with open(args.pem, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
    else:
        key = ec.derive_private_key(int.from_bytes(bytes.fromhex(args.scalar) * 32, "big"), ec.SECP256R1())
    pub = key.public_key().public_numbers()
    entry = {"kty": "EC", "crv": "P-256", "kid": args.kid, "authority_uid": args.authority,
             "x": b64url(pub.x), "y": b64url(pub.y)}
    json.dump({"keys": [entry]}, sys.stdout)


def ndjson(_: argparse.Namespace) -> None:
    text = "\n".join(l for l in sys.stdin.read().splitlines() if not l.lstrip().startswith("//"))
    decoder, i = json.JSONDecoder(), 0
    while text[i:].strip():
        i += len(text[i:]) - len(text[i:].lstrip())
        record, i = decoder.raw_decode(text, i)
        print(json.dumps(record, separators=(",", ":"), ensure_ascii=False))


def unsigned(_: argparse.Namespace) -> None:
    for line in sys.stdin:
        record = json.loads(line)
        for attestation in record.get("attestation_list", []):
            attestation.pop("signatures", None)
        for field in ("signature_b64", "signature_key_id"):
            record.get("unmapped", {}).pop(field, None)
        print(json.dumps(record, separators=(",", ":"), ensure_ascii=False))


parser = argparse.ArgumentParser()
sub = parser.add_subparsers(required=True)
p = sub.add_parser("jwks")
p.add_argument("kid")
p.add_argument("authority")
src = p.add_mutually_exclusive_group(required=True)
src.add_argument("--pem")
src.add_argument("--scalar")
p.set_defaults(run=jwks)
sub.add_parser("ndjson").set_defaults(run=ndjson)
sub.add_parser("unsigned").set_defaults(run=unsigned)
args = parser.parse_args()
args.run(args)
