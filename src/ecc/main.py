import hashlib
from tinyec import registry
from tinyec.ec import Point
import secrets


def hash_function(data):
    return hashlib.sha256(data.encode()).hexdigest()

def xor_hex_strings(s1, s2):
    return hex(int(s1, 16) ^ int(s2, 16))[2:]

def point_multiplication(scalar, point):
    return scalar * point


# shared key
def generate_initial_shared_key(idedge, prk):
    h1_idedge = hash_function(idedge)
    ksh = xor_hex_strings(h1_idedge, prk)
    
    return ksh

def update_shared_key_for_new_node(ksh, prk, idni, curve, base_point, nList):
    h1_idni = hash_function(idni)
    ksh = xor_hex_strings(h1_idni, ksh)
    
    ksh_int = int(ksh, 16)
    gksh = ksh_int * base_point
    
    nList.append(h1_idni)
    
    return ksh, gksh, nList

def update_shared_key_for_leaving_node(ksh, idni, curve, base_point, nList):
    h1_idni = hash_function(idni)
    ksh = xor_hex_strings(h1_idni, ksh)

    ksh_int = int(ksh, 16)  # Convert ksh to an integer
    gksh = ksh_int * base_point

    if h1_idni in nList:
        nList.remove(h1_idni)

    return ksh, gksh, nList


# text
def convert_text_to_blocks(plaintext, p):
    N = (p - 8) // 8
    
    M = len(plaintext)
    B = (M + N - 1) // N
    
    blocks = []
    for i in range(B):
        block = plaintext[i*N:(i+1)*N]
        block_values = ''.join([str(ord(c)).zfill(3) for c in block])  # zfill to ensure 3 digits for each ASCII value
        blocks.append(block_values)
    
    return blocks


def secure_blocks(blocks, InV):
    previous_block = InV
    secured_blocks = []

    for block in blocks:
        secured_block = xor_hex_strings(previous_block, block)
        mapped_block = secured_block
        secured_blocks.append(mapped_block)
        previous_block = secured_block

    return secured_blocks

def map_to_curve(xi, curve):
    while True:
        yi_square = (xi**3 + curve.a * xi + curve.b) % curve.field.p
        yi = pow(yi_square, (curve.field.p + 1) // 4, curve.field.p)

        if pow(yi, 2, curve.field.p) == yi_square:
            return (xi, yi)

        xi += 1

def map_blocks_to_curve(secured_blocks, curve):
    mapped_points = []

    for block in secured_blocks:
        xi = int(block, 16)
        point = map_to_curve(xi, curve)
        mapped_points.append(point)

    return mapped_points


def encrypt_mapped_points(mapped_points, gksh, curve):
    encrypted_points = []

    for point in mapped_points:
        xi, yi = point
        mapped_point = curve.point(xi, yi)
        encrypted_point = mapped_point + gksh
        encrypted_points.append(encrypted_point)

    return encrypted_points

def decrypt_ciphertext(encrypted_points, gksh, curve):
    decrypted_points = []

    for point in encrypted_points:
        decrypted_point = point - gksh
        decrypted_points.append((decrypted_point.x, decrypted_point.y))

    return decrypted_points


def decode_points_to_binary(decrypted_points, InV):
    binary_values = []
    previous_value = int(InV, 16)

    for point in decrypted_points:
        xi = point[0]
        decoded_value = xi ^ previous_value
        binary_value = bin(decoded_value)[2:]
        binary_values.append(binary_value)
        previous_value = xi

    return binary_values

def convert_binary_to_text(binary_values):
    plaintext = ""

    for binary_value in binary_values:
        segments = [binary_value[i:i+8] for i in range(0, len(binary_value), 8)]

        for segment in segments:
            if len(segment) == 8:  # Ensure segment is 8 bits long
                plaintext += chr(int(segment, 2))

    return plaintext

def hash_message(message):
    message_hash = hashlib.sha256(message.encode()).hexdigest()
    return int(message_hash, 16)


def sign_message(message, private_key, curve):
    z = hash_message(message)
    k = secrets.randbelow(curve.field.n)
    R = k * curve.g
    r = R.x % curve.field.p

    if r == 0:
        raise ValueError("r cannot be zero; retry with a different k")

    s = (z + r * private_key) * pow(k, -1, curve.field.n) % curve.field.n

    if s == 0:
        raise ValueError("s cannot be zero; retry with a different k")

    return (r, s)

def verify_signature(message, signature, public_key, curve):
    r, s = signature

    if not (1 <= r <= curve.field.n - 1) or not (1 <= s <= curve.field.n - 1):
        return False  # Invalid signature components

    z = hash_message(message)
    s_inv = pow(s, -1, curve.field.n)
    u1 = (z * s_inv) % curve.field.n
    u2 = (r * s_inv) % curve.field.n
    R_prime = u1 * curve.g + u2 * public_key

    if R_prime.x % curve.field.n == r % curve.field.n:
        return True
    else:
        return False
