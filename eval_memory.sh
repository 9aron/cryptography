#!/usr/bin/env bash

cd ~/cryptography/src/


echo "[+] eval rsa memory usage"
python3 eval_memory_ecc.py secp192r1
python3 eval_memory_ecc.py secp224r1
python3 eval_memory_ecc.py secp256r1
python3 eval_memory_ecc.py secp384r1

echo "[+] eval ecc memory usage"
python3 eval_memory_rsa.py 1024
python3 eval_memory_rsa.py 2048
python3 eval_memory_rsa.py 3072
python3 eval_memory_rsa.py 7680

