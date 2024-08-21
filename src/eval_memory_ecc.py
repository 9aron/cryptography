# -*- coding: utf-8 -*-

import sys
import random
import string
from memory_profiler import profile
import tracemalloc

from config import *
from rsa import *
from ecc import *


def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    s = ''.join(random.choice(characters) for _ in range(random.randint(1, length)))
    return s.encode('utf-8')


def eval_ecc_mem(curve):
    c = get_curve(curve)
    (pub_key, priv_key) = make_keypair(c)
    msg = generate_random_string()
    crypted = encrypt_ECC(msg, pub_key, c)
    decrypt_ECC(crypted, priv_key)


try:
    curve  = sys.argv[1]
except:
    print("usage: python3 eval_memory_ecc [curve]")
    sys.exit()

tracemalloc.start()
eval_ecc_mem(curve)

snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')

print(tracemalloc.get_traced_memory()[0])

tracemalloc.stop()

