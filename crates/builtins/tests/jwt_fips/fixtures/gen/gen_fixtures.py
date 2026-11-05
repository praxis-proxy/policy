# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors

"""Sign JWT fixtures with Python `cryptography` as an independent oracle."""
import base64, json, sys
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils, ed25519
from cryptography.hazmat.primitives import hashes, serialization

out_dir = sys.argv[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
ib = lambda i, n=None: i.to_bytes(n or (i.bit_length() + 7) // 8, "big")
ISS, AUD, EXP, NBF = "https://idp.example", "fips-api", 4102444800, 1700000000
claims = {"iss": ISS, "aud": AUD, "sub": "alice", "exp": EXP, "nbf": NBF}

def jws(header, payload, sign):
    si = b64(json.dumps(header, separators=(",", ":")).encode()) + "." + \
         b64(json.dumps(payload, separators=(",", ":")).encode())
    return si + "." + b64(sign(si.encode()))

def rsa_jwk(pub, kid):
    n = pub.public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "n": b64(ib(n.n)), "e": b64(ib(n.e))}

def ec_jwk(pub, kid, crv, size):
    n = pub.public_numbers()
    return {"kty": "EC", "kid": kid, "use": "sig", "crv": crv,
            "x": b64(ib(n.x, size)), "y": b64(ib(n.y, size))}

fixtures = {"issuer": ISS, "audience": AUD, "tokens": {}, "jwks": {"keys": []}}
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
fixtures["jwks"]["keys"].append(rsa_jwk(rsa_key.public_key(), "rsa-2048"))
fixtures["rsa_public_pem"] = rsa_key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
H = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
for bits in ("256", "384", "512"):
    h = H[bits]
    fixtures["tokens"]["RS" + bits] = jws({"alg": "RS" + bits, "kid": "rsa-2048", "typ": "JWT"}, claims,
        lambda m, h=h: rsa_key.sign(m, padding.PKCS1v15(), h()))
    fixtures["tokens"]["PS" + bits] = jws({"alg": "PS" + bits, "kid": "rsa-2048", "typ": "JWT"}, claims,
        lambda m, h=h: rsa_key.sign(m, padding.PSS(mgf=padding.MGF1(h()), salt_length=h.digest_size), h()))
for alg, curve, crv, size, h in (("ES256", ec.SECP256R1(), "P-256", 32, hashes.SHA256),
                                 ("ES384", ec.SECP384R1(), "P-384", 48, hashes.SHA384)):
    key = ec.generate_private_key(curve)
    kid = "ec-" + crv
    fixtures["jwks"]["keys"].append(ec_jwk(key.public_key(), kid, crv, size))
    def sign(m, key=key, h=h, size=size):
        r, s = utils.decode_dss_signature(key.sign(m, ec.ECDSA(h())))
        return ib(r, size) + ib(s, size)
    fixtures["tokens"][alg] = jws({"alg": alg, "kid": kid, "typ": "JWT"}, claims, sign)
    if alg == "ES256":
        fixtures["ec_p256_public_pem"] = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        fixtures["tokens"]["ES256_no_kid"] = jws({"alg": "ES256", "typ": "JWT"}, claims, sign)
        fixtures["tokens"]["ES256_expired"] = jws({"alg": "ES256", "typ": "JWT"},
            dict(claims, exp=1700000100), sign)
        fixtures["tokens"]["ES256_wrong_aud"] = jws({"alg": "ES256", "typ": "JWT"},
            dict(claims, aud="other-api"), sign)
        t = fixtures["tokens"]["ES256_no_kid"]
        h_, p_, s_ = t.split(".")
        bad = bytearray(base64.urlsafe_b64decode(s_ + "=" * (-len(s_) % 4))); bad[5] ^= 1
        fixtures["tokens"]["ES256_bad_signature"] = h_ + "." + p_ + "." + b64(bytes(bad))

small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
fixtures["rsa_1024_jwk"] = rsa_jwk(small.public_key(), "rsa-1024")
fixtures["rsa_1024_token"] = jws({"alg": "RS256", "kid": "rsa-1024", "typ": "JWT"}, claims,
    lambda m: small.sign(m, padding.PKCS1v15(), hashes.SHA256()))
p521 = ec.generate_private_key(ec.SECP521R1())
fixtures["ec_p521_jwk"] = ec_jwk(p521.public_key(), "ec-p521", "P-521", 66)
ed = ed25519.Ed25519PrivateKey.generate()
fixtures["ed25519_public_pem"] = ed.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
fixtures["ed25519_jwk"] = {"kty": "OKP", "crv": "Ed25519", "kid": "ed", "use": "sig",
    "x": b64(ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
json.dump(fixtures, open(out_dir + "/oracle.json", "w"), indent=1, sort_keys=True)
print("tokens:", sorted(fixtures["tokens"]))
