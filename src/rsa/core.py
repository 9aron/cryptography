import itertools
import typing
import hashlib
from hmac import compare_digest

import rsa.util as util
from rsa.key import PublicKey, PrivateKey


def assert_int(var: int, name: str) -> None:
    if isinstance(var, int):
        return

    raise TypeError("{} should be an integer, not {}".format(name, var.__class__))


def encrypt_int(message: int, ekey: int, n: int) -> int:
    assert_int(message, "message")
    assert_int(ekey, "ekey")
    assert_int(n, "n")

    if message < 0:
        raise ValueError("Only non-negative numbers are supported")

    if message >= n:
        raise OverflowError("The message %i is too long for n=%i" % (message, n))

    return pow(message, ekey, n)


def decrypt_int(cyphertext: int, dkey: int, n: int) -> int:
    assert_int(cyphertext, "cyphertext")
    assert_int(dkey, "dkey")
    assert_int(n, "n")

    message = pow(cyphertext, dkey, n)
    return message


def encrypt(message: bytes, pub_key: PublicKey) -> bytes:
    keylength = util.byte_size(pub_key.n)
    if len(message) > keylength:
        raise OverflowError("The message is too large to fit in the block size.")

    payload = util.bytes2int(message)
    encrypted = encrypt_int(payload, pub_key.e, pub_key.n)
    block = util.int2bytes(encrypted, keylength)

    return block


def decrypt(crypto: bytes, priv_key: PrivateKey) -> bytes:
    blocksize = util.byte_size(priv_key.n)
    encrypted = util.bytes2int(crypto)
    decrypted = decrypt_int(encrypted, priv_key.d, priv_key.n)
    cleartext = util.int2bytes(decrypted, blocksize)

    return cleartext.lstrip(b'\x00')  # Strip any trailing zero bytes added during encryption


def sign_hash(hash_value: bytes, priv_key: PrivateKey) -> bytes:
    payload = util.bytes2int(hash_value)
    encrypted = decrypt_int(payload, priv_key.d, priv_key.n)
    block = util.int2bytes(encrypted)

    return block


def compute_hash(message: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(message)
    return hasher.digest()


def signature(message: bytes, priv_key: PrivateKey) -> bytes:
    msg_hash = compute_hash(message)
    return sign_hash(msg_hash, priv_key)


def verify(message: bytes, sig: bytes, pub_key: PublicKey) -> str:
    encrypted = util.bytes2int(sig)
    decrypted = encrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = util.int2bytes(decrypted)

    message_hash = compute_hash(message)

    if message_hash != clearsig:
        return False

    return True

