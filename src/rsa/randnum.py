# Source inspired by code by Yesudeep Mangalapilly <yesudeep@gmail.com>

import os
import struct

import rsa.util as util


def read_random_bits(nbits: int) -> bytes:
    nbytes, rbits = divmod(nbits, 8)

    randomdata = os.urandom(nbytes)

    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= 8 - rbits
        randomdata = struct.pack("B", randomvalue) + randomdata

    return randomdata


def read_random_int(nbits: int) -> int:
    randomdata = read_random_bits(nbits)
    value = util.bytes2int(randomdata)

    value |= 1 << (nbits - 1)

    return value


def read_random_odd_int(nbits: int) -> int:
    value = read_random_int(nbits)

    return value | 1


def randint(maxvalue: int) -> int:
    bit_size = util.bit_size(maxvalue)

    tries = 0
    while True:
        value = read_random_int(bit_size)
        if value <= maxvalue:
            break

        if tries % 10 == 0 and tries:
            bit_size -= 1
        tries += 1

    return value
