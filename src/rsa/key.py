# -*- coding: utf-8 -*-

# TODO delete unneeded comments

import os
import sys
import typing

import rsa.prime as prime
import rsa.util as util


DEFAULT_EXPONENT = 65537

class PublicKey:
    __slots__ = ("n", "e")

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return "PublicKey(%i, %i)" % (self.n, self.e)

    def __getstate__(self) -> typing.Tuple[int, int]:
        """Returns the key as tuple for pickling."""
        return self.n, self.e

    def __setstate__(self, state: typing.Tuple[int, int]) -> None:
        """Sets the key from tuple."""
        self.n, self.e = state

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.n, self.e))


class PrivateKey:
    __slots__ = ("n", "e", "d", "p", "q")

    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q


    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return "PrivateKey(%i, %i, %i, %i, %i)" % (
            self.n,
            self.e,
            self.d,
            self.p,
            self.q,
        )

    def __getstate__(self) -> typing.Tuple:
        return self.n, self.e, self.d, self.p, self.q

    def __setstate__(self, state: typing.Tuple) -> None:
        self.n, self.e, self.d, self.p, self.q

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return all([getattr(self, k) == getattr(other, k) for k in self.__slots__])

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q))


def find_p_q(nbits: int) -> typing.Tuple[int, int]:
    total_bits = nbits * 2

    # Make sure that p and q aren't too close or the factoring programs can
    # factor n.
    shift = nbits // 16
    pbits = nbits + shift
    qbits = nbits - shift

    # Choose the two initial primes
    p = prime.getprime(pbits)
    q = prime.getprime(qbits)

    def is_acceptable(p: int, q: int) -> bool:
        if p == q:
            return False

        # Make sure we have just the right amount of bits
        found_size = util.bit_size(p * q)
        return total_bits == found_size

    # Keep choosing other primes until they match our requirements.
    change_p = False
    while not is_acceptable(p, q):
        # Change p on one iteration and q on the other
        if change_p:
            p = prime.getprime(pbits)
        else:
            q = prime.getprime(qbits)

        change_p = not change_p

    # We want p > q as described on
    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return max(p, q), min(p, q)


def calculate_keys_custom_exponent(p: int, q: int, exponent: int) -> typing.Tuple[int, int]:
    phi_n = (p - 1) * (q - 1)

    try:
        d = util.inverse(exponent, phi_n)
    except util.NotRelativePrimeError as ex:
        raise util.NotRelativePrimeError(
            exponent,
            phi_n,
            ex.d,
            msg="e (%d) and phi_n (%d) are not relatively prime (divider=%i)"
            % (exponent, phi_n, ex.d),
        ) from ex

    if (exponent * d) % phi_n != 1:
        raise ValueError(
            "e (%d) and d (%d) are not mult. inv. modulo " "phi_n (%d)" % (exponent, d, phi_n)
        )

    return exponent, d


def gen_keys(nbits: int) -> typing.Tuple:
    # Regenerate prime values, until calculate_keys_custom_exponent doesn't raise a  ValueError.
    while True:
        p, q = find_p_q(nbits // 2)
        try:
            (e, d) = calculate_keys_custom_exponent(p, q, DEFAULT_EXPONENT)
            break
        except ValueError:
            pass

    return p, q, e, d


def newkeys(nbits: int) -> typing.Tuple[PublicKey, PrivateKey]:
    # Generate the key components
    result = gen_keys(nbits)
    if len(result) == 4:
        p, q, e, d = result

    # Create the key objects
    n = p * q
    return (PublicKey(n, e), PrivateKey(n, e, d, p, q))


