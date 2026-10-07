#!/usr/bin/env python3
"""Independent (pure Python) model of the TPAP SPAKE2+ client math, used to
generate the known-answer vector in src/spake.rs. Not used at runtime."""
import hashlib, hmac, struct
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q: l = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else: l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (l * l - p[0] - q[0]) % P
    return (x, (l * (p[0] - x) - p[1]) % P)

def mul(k, p):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r

def neg(p): return (p[0], (-p[1]) % P)

def decompress(b):
    x = int.from_bytes(b[1:], 'big')
    y = pow((x**3 + A * x + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b) % P, (P + 1) // 4, P)
    if (y & 1) != (b[0] & 1): y = P - y
    return (x, y)

def enc(p): return b'\x04' + p[0].to_bytes(32, 'big') + p[1].to_bytes(32, 'big')
def len8(b): return struct.pack('<Q', len(b)) + b

M = decompress(bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"))
Nn = decompress(bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"))

def encode_w(w):
    b = b'\x00' if w == 0 else w.to_bytes((w.bit_length() + 7) // 8, 'big')
    if len(b) % 2 == 0: return b
    return b'\x00' + b if b[0] & 0x80 else b

def hkdf0(ikm, info, n):
    return HKDF(hashes.SHA256(), n, b'\x00' * 32, info).derive(ikm)

def client(cred, salt, iters, x, user_random, dev_random, dev_share):
    d = hashlib.pbkdf2_hmac('sha256', cred, salt, iters, 80)
    w0 = int.from_bytes(d[:40], 'big') % N
    w1 = int.from_bytes(d[40:], 'big') % N
    L = add(mul(x, G), mul(w0, M))
    R = decompress_full(dev_share)
    Rp = add(R, neg(mul(w0, Nn)))
    Z = mul(x, Rp); V = mul(w1, Rp)
    ctx = hashlib.sha256(b"PAKE V1" + user_random + dev_random).digest()
    tt = b''.join(len8(i) for i in [ctx, b'', b'', enc(M), enc(Nn), enc(L), enc(R), enc(Z), enc(V), encode_w(w0)])
    th = hashlib.sha256(tt).digest()
    ck = hkdf0(th, b"ConfirmationKeys", 64)
    sk = hkdf0(th, b"SharedKey", 32)
    return dict(w0=w0, w1=w1, L=enc(L), user_confirm=hmac.new(ck[:32], enc(R), 'sha256').digest(),
                dev_confirm=hmac.new(ck[32:], enc(L), 'sha256').digest(), shared=sk)

def decompress_full(b): return (int.from_bytes(b[1:33], 'big'), int.from_bytes(b[33:], 'big'))

if __name__ == '__main__':
    cred = b"user@example.com/hunter2"; salt = bytes(range(16)); iters = 1000
    x = 0x1111111111111111111111111111111111111111111111111111111111111111
    y = 0x2222222222222222222222222222222222222222222222222222222222222222
    d = hashlib.pbkdf2_hmac('sha256', cred, salt, iters, 80)
    w0 = int.from_bytes(d[:40], 'big') % N
    dev_share = enc(add(mul(y, G), mul(w0, Nn)))
    ur, dr = bytes([7]) * 32, bytes([9]) * 32
    r = client(cred, salt, iters, x, ur, dr, dev_share)
    print("DEV_SHARE", dev_share.hex())
    for k in ("w0", "w1"): print(k.upper(), format(r[k], '064x'))
    for k in ("L", "user_confirm", "dev_confirm", "shared"): print(k.upper(), r[k].hex())
    # sanity: M, N decompressed points must be on the curve
    assert all((p[1]**2 - (p[0]**3 + A*p[0] + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)) % P == 0 for p in (M, Nn))
