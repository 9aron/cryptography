# -*- coding: utf-8 -*-

import os
import sys

relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from eval import profile
from ecc import *


@profile
def profiled_sig(msg, priv_key, curve):
    return generate_ecc_sig(priv_key, msg, curve)

@profile
def profiled_ver(msg, sig, pub_key, curve):
    return verify_ecc_sig(pub_key, msg, sig, curve)

try:
    curve  = sys.argv[1]
except:
    print("usage: python3 t_ecc_* [curve]")
    sys.exit()

c = get_curve(curve)
(pub_key, priv_key) = make_keypair(c)

msg = "hello world!"

sig = profiled_sig(msg, priv_key, c)
if profiled_ver(msg, sig, pub_key, c):
    print("signature verification successful")
else:
    print("error in the signature verification")
