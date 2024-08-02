# -*- coding: utf-8 -*-

import os
import sys

relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from eval import profile
from rsa import *


@profile
def profiled_encrypt(msg, pub_key):
    return encrypt(msg, pub_key)


@profile
def profiled_decrypt(crypto, priv_key):
    return decrypt(crypto, priv_key)


try:
    key_size = int(sys.argv[1])
except:
    print("usage: python3 t_rsa_* [keysize]")
    sys.exit()


(pub_key, priv_key) = newkeys(key_size)

msg = b"hello world!"

crypto = profiled_encrypt(msg, pub_key)
clear = profiled_decrypt(crypto, priv_key)

if msg == clear:
    print("encryption/decryption successful")


# print the results
print("clear text : " + msg.decode("utf-8"))
print()
print("encrypted : " + crypto.hex())
print()
print("decrypted : " + clear.decode("utf-8"))
