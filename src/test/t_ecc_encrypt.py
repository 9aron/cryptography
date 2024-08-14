# -*- coding: utf-8 -*-

import os
import sys

relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from eval import profile
from ecc import *


@profile
def profiled_encrypt(msg, pub_key, curve):
    return encrypt_ECC(msg, pub_key, curve)

@profile
def profiled_decrypt(crypto, priv_key):
    return decrypt_ECC(crypto, priv_key)


try:
    curve  = sys.argv[1]
except:
    print("usage: python3 t_ecc_* [curve]")
    sys.exit()

c = get_curve(curve)
(pub_key, priv_key) = make_keypair(c)

msg = b"hello world!"

crypto = profiled_encrypt(msg, pub_key, c)
clear = profiled_decrypt(crypto, priv_key)

if msg == clear:
    print("encryption/decryption successful")


# print the results
print("clear text : " + msg.decode("utf-8"))
print()
print("encrypted : " + str(crypto))
print()
print("decrypted : " + clear.decode("utf-8"))
