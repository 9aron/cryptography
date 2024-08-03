# -*- coding: utf-8 -*-

# XXX note that this file is temp, remove once you implement memory profiling


import sys
import timeit
from tqdm import tqdm

from rsa import newkeys
from config import N_TEST, MAC
from eval import profile_memory


key_size = int(sys.argv[1])

bar_format = "{l_bar}{bar} | {n_fmt}/{total_fmt} "


@profile_memory
def rsa_key_gen(key_size):
    newkeys(key_size)


# Measure memory usage for key generation
times = []
for _ in tqdm(range(N_TEST), desc="eval mem usage", bar_format=bar_format):
    rsa_key_gen_memory = rsa_key_gen(key_size)
    times.append(rsa_key_gen_memory)

average_rsa_key_gen_memory = sum(times) / N_TEST


# Print results
print(f"RSA Key Generation Memory: {average_rsa_key_gen_memory} MiB")
