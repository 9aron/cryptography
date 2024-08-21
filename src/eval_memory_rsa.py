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


def eval_rsa_mem(key_size):
    (pub_key, priv_key) = newkeys(key_size)
    msg = generate_random_string()
    crypted = encrypt(msg, pub_key)
    decrypt(crypted, priv_key)


try:
    key_size = int(sys.argv[1])
except:
    print("usage: python3 eval_memory_rsa [keysize]")
    sys.exit()


tracemalloc.start()
eval_rsa_mem(int(key_size))

snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')

print(tracemalloc.get_traced_memory()[0])

tracemalloc.stop()

