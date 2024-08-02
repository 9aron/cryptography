# -*- coding: utf-8 -*-

import os
import sys

relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from eval import profile 
from rsa import *


@profile
def profiled_newkeys(key_size):
    return newkeys(key_size)


try:
    key_size = int(sys.argv[1])
except:
    print("usage: python3 t_rsa_* [keysize]")
    sys.exit()

(pub_key, priv_key) = profiled_newkeys(key_size)
print(pub_key, priv_key, sep='\n\n')

