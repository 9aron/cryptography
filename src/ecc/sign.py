# -*- coding: utf-8 -*-

import hashlib
import secrets


def hash_message(message):
    return int(hashlib.sha256(message).hexdigest(), 16)


def generate_ecc_sig(private_key, message, curve):
    n = curve.field.n
    h_m = hash_message(message)
    
    while True:
        k = secrets.randbelow(curve.field.n)
        point = k * curve.g
        r = point.x % n
        
        if r == 0:
            continue
        
        s = (pow(k, -1, n) * (h_m + r * private_key.priv)) % n

        if s != 0:
            break
    
    return (r, s)

def verify_ecc_sig(public_key, message, signature, curve):
    r, s = signature
    n = curve.field.n
    h_m = hash_message(message)

    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False

    s_inv = pow(s, -1, n)
    u = (h_m * s_inv) % n
    v = (r * s_inv) % n

    point_uG = u * curve.g
    point_vQ = v * public_key.pub
    point = point_uG + point_vQ

    return (point.x % n) == r

