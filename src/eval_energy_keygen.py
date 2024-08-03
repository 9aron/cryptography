# -*- coding: utf-8 -*-

import csv
import timeit
import pprint
from tqdm import tqdm

from config import *
from rsa import newkeys
from ecc import make_keypair, get_curve
from um25c import get_mwh_data, connect_to_usb_tester


csv_file_path = 'csv/keygen_energy.csv' # TODO put this in config files, and make code for it to exec well


# Measure energy consumption for rsa key generation
def eval_rsa_keygen(sock, key_size, desc, form=BAR_FORMAT, n_t=N_TEST):
    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        start_mwh = get_mwh_data(sock)
        newkeys(key_size)
        end_mwh = get_mwh_data(sock)
        times.append(end_mwh - start_mwh)

    average_rsa_key_gen_energy = sum(times) / N_TEST

    return average_rsa_key_gen_energy


# Measure energy consumption for ecc key generation
def eval_ecc_keygen(sock, curve, desc, form=BAR_FORMAT, n_t=N_TEST):
    c = get_curve(curve)

    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        start_mwh = get_mwh_data(sock)
        make_keypair(c)
        end_mwh = get_mwh_data(sock)
        times.append(end_mwh - start_mwh)

    average_ecc_key_gen_energy = sum(times) / N_TEST

    return average_ecc_key_gen_energy


# evaluation 
print('[+] evaluating energy consumption for rsa and ecc')

sock = connect_to_usb_tester()

data = []
for lvl, r_ks, e_ks in zip(SEC_LVL, RSA_KEYSIZE, EC):
    print(f"\n[+] security level {lvl}")
    r_des = f"[+] generating {r_ks} bit rsa key"
    e_des = f"[+] generating {e_ks[4:7]} bit ecc key"

    rsa_avg_t = eval_rsa_keygen(sock, int(r_ks), r_des)
    ecc_avg_t = eval_ecc_keygen(sock, e_ks, e_des)

    data.append({'sec_lvl': lvl, 'rsa_keysize': r_ks, 'rsa_energy': rsa_avg_t, 'ecc_keysize': int(e_ks[4:7]), 'ecc_energy': ecc_avg_t})

sock.close()


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
