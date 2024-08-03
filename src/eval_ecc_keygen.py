# -*- coding: utf-8 -*-

# XXX note that this file is temp, remove once you implement memory profiling


import sys
import timeit
from tqdm import tqdm

from config import N_TEST, MAC
from eval import profile_memory
from ecc import make_keypair, get_curve


curve = sys.argv[1]

bar_format = "{l_bar}{bar} | {n_fmt}/{total_fmt} "


@profile_memory
def ecc_key_gen(curve):
    make_keypair(c)


# Measure memory usage for key generation
c = get_curve(curve)

times = []
for _ in tqdm(range(N_TEST), desc="eval mem usage", bar_format=bar_format):
    ecc_key_gen_memory = ecc_key_gen(c)
    times.append(ecc_key_gen_memory)

average_ecc_key_gen_memory = sum(times) / N_TEST


# Print results
print(f"ECC Key Generation Memory: {average_ecc_key_gen_memory} MiB")
