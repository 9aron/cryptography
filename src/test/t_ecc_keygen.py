# -*- coding: utf-8 -*-

import os
import sys

relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from eval import profile 
from ecc import *


@profile
def profiled_make_keypair(curve):
    c = get_curve(curve)
    return make_keypair(c)


try:
    curve = sys.argv[1]
except:
    print("usage: python3 t_rsa_* [keysize]")
    sys.exit()

(pub_key, priv_key) = profiled_make_keypair(curve)
print(pub_key, priv_key, sep='\n\n')

print('compression/decompression')
comp_key = pub_key.compress_point()
print(comp_key)

