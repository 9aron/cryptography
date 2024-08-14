# -*- coding: utf-8 -*-

import os
import csv
import timeit
import pprint
import random
import string
from tqdm import tqdm

from config import *
from rsa import *
from ecc import *
from um25c import get_mwh_data, connect_to_usb_tester


csv_file_path = 'csv/verify_energy.csv' # TODO put this in config files, and make code for it to exec well


def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    s = ''.join(random.choice(characters) for _ in range(length))
    return s.encode('utf-8')


# Measure energy consumption for rsa key generation
def eval_rsa_verify(sock, key_size, desc, form=BAR_FORMAT, n_t=N_TEST):
    (pub_key, priv_key) = newkeys(key_size)

    msg = generate_random_string()
    
    sig = signature(msg, priv_key)

    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        start_mwh = get_mwh_data(sock)

        verify(msg, sig, pub_key)

        end_mwh = get_mwh_data(sock)
        times.append(end_mwh - start_mwh)

    average_rsa_key_gen_energy = sum(times) / N_TEST

    return average_rsa_key_gen_energy


# Measure energy consumption for ecc key generation
def eval_ecc_verify(sock, curve, desc, form=BAR_FORMAT, n_t=N_TEST):
    c = get_curve(curve)
    (pub_key, priv_key) = make_keypair(c)

    msg = generate_random_string()
    
    sig = generate_ecc_sig(priv_key, msg, c)

    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        start_mwh = get_mwh_data(sock)

        verify_ecc_sig(pub_key, msg, sig, c)

        end_mwh = get_mwh_data(sock)
        times.append(end_mwh - start_mwh)

    average_ecc_key_gen_energy = sum(times) / N_TEST

    return average_ecc_key_gen_energy


# evaluation 
print('[+] evaluating energy consumption for rsa and ecc')

sock = connect_to_usb_tester(MAC)

data = []
for lvl, r_ks, e_ks in zip(SEC_LVL, RSA_KEYSIZE, EC):
    print(f"\n[+] security level {lvl}")
    r_des = f"[+] verify in {r_ks} bit rsa key"
    e_des = f"[+] verify in {e_ks[4:7]} bit ecc key"

    rsa_avg_t = eval_rsa_verify(sock, int(r_ks), r_des)
    ecc_avg_t = eval_ecc_verify(sock, e_ks, e_des)

    data.append({'sec_lvl': lvl, 'rsa_keysize': r_ks, 'rsa_energy': rsa_avg_t, 'ecc_keysize': int(e_ks[4:7]), 'ecc_energy': ecc_avg_t})

sock.close()


# csv
# csv fields
fieldnames = ['sec_lvl', 'rsa_keysize', 'rsa_energy', 'ecc_keysize', 'ecc_energy']

# Writing data to csv
if os.path.exists(csv_file_path):
    with open(csv_file_path, mode='a', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write each row of data
        for row in data:
            writer.writerow(row)
else:
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
