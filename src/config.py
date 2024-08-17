# -*- coding: utf-8 -*-

MAC         = "98:DA:F0:00:5A:85"
BAR_FORMAT  = "{l_bar}{bar} | {n_fmt}/{total_fmt} "
N_TEST      = 10 # number of test to be done
GMP         = True
PRINT       = False

SEC_LVL     = ( 80, 112, 128) #, 192) #, 256 )
RSA_KEYSIZE = ( '1024', '2048', '3072', '7680', '15360' )
EC          = ( 'secp192r1', 'secp224r1', 'secp256r1', 'secp384r1', 'secp521r1' )

DECRYPT_ENERGY = 'csv/decrypt_energy.csv'
ENCRYPT_ENERGY = 'csv/encrypt_energy.csv'
KEYGEN_ENERGY  = 'csv/keygen_energy.csv'
SIG_ENERGY     = 'csv/sign_energy.csv'
VERIFY_ENERGY  = 'csv/verify_energy.csv'

DECRYPT_EXEC = 'csv/decrypt_exectime.csv'
ENCRYPT_EXEC = 'csv/encrypt_exectime.csv'
KEYGEN_EXEC  = 'csv/keygen_exectime.csv'
SIG_EXEC     = 'csv/sig_exectime.csv'
VERIFY_EXEC  = 'csv/verify_exectime.csv'
