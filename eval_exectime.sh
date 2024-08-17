#!/usr/bin/env bash

cd ~/cryptography/src/

python3 eval_time_keygen.py
python3 eval_time_encrypt.py
python3 eval_time_decrypt.py
python3 eval_time_sign.py
python3 eval_time_verify.py
