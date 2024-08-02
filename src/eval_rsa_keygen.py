# -*- coding: utf-8 -*-

import sys
import timeit
import csv
from tqdm import tqdm

from rsa import newkeys
from config import N_TEST, MAC
from eval import profile_memory
from um25c import get_mwh_data, connect_to_usb_tester


key_size = int(sys.argv[1])

bar_format = "{l_bar}{bar} | {n_fmt}/{total_fmt} "


@profile_memory
def rsa_key_gen(key_size):
    newkeys(key_size)


# Measure execution time for RSA key generation
rsa_setup_code = """
from rsa import newkeys
"""

times = []
for _ in tqdm(range(N_TEST), desc="eval exec time", bar_format=bar_format):
    rsa_key_gen_time = timeit.timeit(
        stmt=f"newkeys({key_size})",
        setup=rsa_setup_code,
        number=1
    )
    times.append(rsa_key_gen_time)

average_rsa_key_gen_time = sum(times) / N_TEST


# Measure memory usage for key generation
times = []
for _ in tqdm(range(N_TEST), desc="eval mem usage", bar_format=bar_format):
    rsa_key_gen_memory = rsa_key_gen(key_size)
    times.append(rsa_key_gen_memory)

average_rsa_key_gen_memory = sum(times) / N_TEST


# Measure energy consumption for key generation
sock = connect_to_usb_tester()

times = []
for _ in tqdm(range(N_TEST), desc="eval energy consumption", bar_format=bar_format):
    start_mwh = get_mwh_data(sock)
    newkeys(key_size)
    end_mwh = get_mwh_data(sock)
    times.append(end_mwh - start_mwh)

average_rsa_key_gen_energy = sum(times) / N_TEST

sock.close()


# csv
fields = ['keysize', 'exec time', 'mem usage', 'energy consumption']

# Print results
print(f"RSA Key Generation Time: {average_rsa_key_gen_time} seconds")
print(f"RSA Key Generation Memory: {average_rsa_key_gen_memory} MiB")
print(f"RSA Key Generation Energy Consumption: {average_rsa_key_gen_energy} mWh")
