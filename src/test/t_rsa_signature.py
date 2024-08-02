# -*- coding: utf-8 -*-

import os
import sys

relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from eval import profile
from rsa import *


@profile
def profiled_sig(msg, priv_key):
    return signature(msg, priv_key)


@profile
def profiled_ver(msg, sig, pub_key):
    return verify(msg, sig, pub_key)


try:
    key_size = int(sys.argv[1])
except:
    print("usage: python3 t_rsa_* [keysize]")
    sys.exit()

(pub_key, priv_key) = newkeys(key_size)

msg = b"hello world!"

sig = profiled_sig(msg, priv_key)
if profiled_ver(msg, sig, pub_key):
    print("signature verification successful")
else:
    print("error in the signature verification")
