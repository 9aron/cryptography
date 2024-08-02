""" Implementation based on the book Algorithm Design by Michael T. Goodrich and Roberto Tamassia, 2002. """

import os
import sys
import math
import gmpy2

import rsa.util as util
import rsa.randnum as randnum


relative_path = os.path.join('..')
sys.path.insert(0, relative_path)

from config import GMP


__all__ = ["getprime", "are_relatively_prime"]



def get_primality_testing_rounds(number: int) -> int:
    bitsize = util.bit_size(number)
    if bitsize >= 1536:
        return 3
    if bitsize >= 1024:
        return 4
    if bitsize >= 512:
        return 7
    return 10


def miller_rabin_primality_testing(n: int, k: int) -> bool:
    if n < 2:
        return False

    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    for _ in range(k):
        a = randnum.randint(n - 3) + 1

        if GMP:
            base = gmpy2.mpz(a)
            exp = gmpy2.mpz(d)
            mod = gmpy2.mpz(n)

            x = gmpy2.powmod(base, exp, mod)
        else:
            x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            if GMP:
                base2 = gmpy2.mpz(x)
                exp2 = gmpy2.mpz(2)
                mod2 = gmpy2.mpz(n)

                x = gmpy2.powmod(base2, exp2, mod2)
            else:
                x = pow(x, 2, n)

            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False

    return True


def is_prime(number: int) -> bool:
    if number < 10:
        return number in {2, 3, 5, 7}

    if not (number & 1):
        return False

    k = get_primality_testing_rounds(number)

    return miller_rabin_primality_testing(number, k + 1)


def getprime(nbits: int) -> int:
    assert nbits > 3  # the loop will hang on too small numbers

    while True:
        integer = randnum.read_random_odd_int(nbits)

        if is_prime(integer):
            return integer



def are_relatively_prime(a: int, b: int) -> bool:
    return math.gcd(a, b) == 1
