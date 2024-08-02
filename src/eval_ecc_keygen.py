# -*- coding: utf-8 -*-

import sys
import timeit
from tqdm import tqdm

from ecc import make_keypair, get_curve
from config import N_TEST, MAC
from eval import profile_memory
from um25c import get_mwh_data, connect_to_usb_tester


curve = sys.argv[1]

bar_format = "{l_bar}{bar} | {n_fmt}/{total_fmt} "

c = get_curve(curve)

@profile_memory
def ecc_key_gen(curve):
    make_keypair(c)


# Measure execution time for ECC key generation
ecc_setup_code = f"""
from ecc import make_keypair, get_curve
c = get_curve('{curve}')
"""

times = []
for _ in tqdm(range(N_TEST), desc="eval exec time", bar_format=bar_format):
    ecc_key_gen_time = timeit.timeit(
        stmt="make_keypair(c)",
        setup=ecc_setup_code,
        number=1
    )
    times.append(ecc_key_gen_time)

average_ecc_key_gen_time = sum(times) / N_TEST


# Measure memory usage for key generation
times = []
for _ in tqdm(range(N_TEST), desc="eval mem usage", bar_format=bar_format):
    ecc_key_gen_memory = ecc_key_gen(c)
    times.append(ecc_key_gen_memory)

average_ecc_key_gen_memory = sum(times) / N_TEST



# Measure energy consumption for key generation
sock = connect_to_usb_tester()

times = []
for _ in tqdm(range(N_TEST), desc="eval energy consumption", bar_format=bar_format):
    start_mwh = get_mwh_data(sock)
    make_keypair(c)
    end_mwh = get_mwh_data(sock)
    times.append(end_mwh - start_mwh)

average_ecc_key_gen_energy = sum(times) / N_TEST

sock.close()


# Print results
print(f"ECC Key Generation Time: {average_ecc_key_gen_time:.6f} seconds")
print(f"ECC Key Generation Memory: {average_ecc_key_gen_memory:.2f} MiB")
print(f"ECC Key Generation Energy Consumption: {average_ecc_key_gen_energy} mWh")
