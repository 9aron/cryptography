# -*- coding: utf-8 -*-

import os
import csv
import timeit
import pprint
import random
import string
from tqdm import tqdm

from config import *


csv_file_path = DECRYPT_EXEC


# Measure execution time for RSA key generation
def eval_rsa_decrypt(key_size, desc, form=BAR_FORMAT, n_t=N_TEST):
    rsa_setup_code = f"""
import random
import string
from rsa import newkeys
from rsa import encrypt, decrypt
def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    s = ''.join(random.choice(characters) for _ in range(length))
    return s.encode('utf-8')
(pub_key, priv_key) = newkeys({key_size})
msg = generate_random_string()
crypted = encrypt(msg, pub_key)
"""

        
    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        rsa_key_gen_time = timeit.timeit(stmt="decrypt(crypted, priv_key)", setup=rsa_setup_code, number=1)
        times.append(rsa_key_gen_time)

    average_rsa_key_gen_time = sum(times) / N_TEST

    return average_rsa_key_gen_time


# Measure execution time for ECC key generation
def eval_ecc_decrypt(curve, desc, form=BAR_FORMAT, n_t=N_TEST):
    ecc_setup_code = f"""
import random
import string
from ecc import make_keypair, get_curve
from ecc import encrypt_ECC, decrypt_ECC
def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    s = ''.join(random.choice(characters) for _ in range(length))
    return s.encode('utf-8')
c = get_curve('{curve}')
(pub_key, priv_key) = make_keypair(c)
msg = generate_random_string()
crypted = encrypt_ECC(msg, pub_key, c)
"""

    times = []
    for _ in tqdm(range(n_t), desc=desc, bar_format=form):
        ecc_key_gen_time = timeit.timeit(stmt="decrypt_ECC(crypted, priv_key)", setup=ecc_setup_code, number=1)
        times.append(ecc_key_gen_time)

    average_ecc_key_gen_time = sum(times) / N_TEST

    return average_ecc_key_gen_time


# evaluation 
print('[+] evaluating exection time for rsa and ecc')

data = []
for lvl, r_ks, e_ks in zip(SEC_LVL, RSA_KEYSIZE, EC):
    print(f"\n[+] security level {lvl}")
    r_des = f"[+] decryption in {r_ks} bit rsa key"
    e_des = f"[+] decryption in {e_ks[4:7]} bit ecc key"

    rsa_avg_t = eval_rsa_decrypt(int(r_ks), r_des)
    ecc_avg_t = eval_ecc_decrypt(e_ks, e_des)

    data.append({'sec_lvl': lvl, 'rsa_keysize': r_ks, 'rsa_exec_time': rsa_avg_t, 'ecc_keysize': int(e_ks[4:7]), 'ecc_exec_time': ecc_avg_t})


# csv
# csv fields
fieldnames = ['sec_lvl', 'rsa_keysize', 'rsa_exec_time', 'ecc_keysize', 'ecc_exec_time']

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

print(f"[+] Data has been written to {csv_file_path}\n")


# Print results
if PRINT:
    print("\n[+] printing the data to stdout")
    for row in data:
        print(str(row))
