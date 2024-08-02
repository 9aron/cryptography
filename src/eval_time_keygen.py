# -*- coding: utf-8 -*-

import csv
import timeit
import pprint
from tqdm import tqdm

from rsa import newkeys
#from ecc import make_keypair, get_curve
#from config import N_TEST, MAC, RSA_KEYSIZE, EC
from config import *


bar_format = "{l_bar}{bar} | {n_fmt}/{total_fmt} "

csv_file_path = 'csv/keygen_exectime.csv' # TODO put this in config files, and make code for it to exec well



# Measure execution time for RSA key generation
def eval_rsa_keygen(key_size, desc, form=bar_format, n_t=N_TEST):
    rsa_setup_code = """
from rsa import newkeys
"""

    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        rsa_key_gen_time = timeit.timeit(stmt=f"newkeys({key_size})", setup=rsa_setup_code, number=1)
        times.append(rsa_key_gen_time)

    average_rsa_key_gen_time = sum(times) / N_TEST

    return average_rsa_key_gen_time


# Measure execution time for ECC key generation
def eval_ecc_keygen(curve, desc, form=bar_format, n_t=N_TEST):
    ecc_setup_code = f"""
from ecc import make_keypair, get_curve
c = get_curve('{curve}')
"""

    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        ecc_key_gen_time = timeit.timeit(stmt="make_keypair(c)", setup=ecc_setup_code, number=1)
        times.append(ecc_key_gen_time)

    average_ecc_key_gen_time = sum(times) / N_TEST

    return average_ecc_key_gen_time


# evaluation 
print('[+] evaluating exection time for rsa and ecc')

data = []
for lvl, r_ks, e_ks in zip(SEC_LVL, RSA_KEYSIZE, EC):
    print(f"\n[+] security level {lvl}")
    r_des = f"[+] generating {r_ks} bit rsa key"
    e_des = f"[+] generating {e_ks[4:7]} bit ecc key"

    rsa_avg_t = eval_rsa_keygen(r_ks, r_des)
    ecc_avg_t = eval_ecc_keygen(e_ks, e_des)

    data.append({'sec_lvl': lvl, 'rsa_keysize': r_ks, 'rsa_exec_time': rsa_avg_t, 'ecc_keysize': int(e_ks[4:7]), 'ecc_exec_time': ecc_avg_t})


# csv
# csv fields
fieldnames = ['sec_lvl', 'rsa_keysize', 'rsa_exec_time', 'ecc_keysize', 'ecc_exec_time']

# Writing data to csv
with open(csv_file_path, mode='w', newline='') as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()

    # Write each row of data
    for row in data:
        writer.writerow(row)

print(f"[+] Data has been written to {csv_file_path}")

# Print results
if PRINT:
    print("\n[+] printing the data to stdout")
    for row in data:
        print(str(row))