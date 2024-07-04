import hashlib
import random

# secp256k1 curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def inverse_mod(k, p):
    """Returns the inverse of k modulo p."""
    return pow(k, p - 2, p)

def point_add(p1, p2):
    """Adds two points on the secp256k1 curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * inverse_mod(2 * p1[1], p)) % p
    else:
        lam = ((p2[1] - p1[1]) * inverse_mod(p2[0] - p1[0], p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)

def scalar_mult(k, point):
    """Multiplies a point by a scalar."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def generate_keypair():
    """Generates a new ECDSA keypair."""
    private_key = random.randrange(1, n)
    public_key = scalar_mult(private_key, G)
    return private_key, public_key[0].to_bytes(32) + public_key[1].to_bytes(32)

def sign(private_key, message_hash):
    """Signs a message using ECDSA."""
    z = int.from_bytes(message_hash, 'big')
    r = 0
    s = 0
    while not r or not s:
        k = random.randrange(1, n)
        x, y = scalar_mult(k, G)
        r = x % n
        s = (inverse_mod(k, n) * (z + r * private_key)) % n
    return r.to_bytes(32) + s.to_bytes(32)

def verify(public_key, message_hash, signature):
    """Verifies an ECDSA signature."""
    z = int.from_bytes(message_hash, 'big')
    r, s = int.from_bytes(signature[:32]), int.from_bytes(signature[32:])
    w = inverse_mod(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    x, y = point_add(scalar_mult(u1, G), scalar_mult(u2, (int.from_bytes(public_key[:32]), int.from_bytes(public_key[32:]))))
    return r == x % n

# Example usage
private_key, public_key = generate_keypair()
message_hash = hashlib.sha256(b"Hello, World!").digest()
signature = sign(private_key, message_hash)
print(f"Signature: {signature}")
print(f"Verification result: {verify(public_key, message_hash, signature)}")

# tron block 62913164
print(verify(bytes.fromhex("12b50d6895e6010f0f7fb4e6eba00fb4eca46229649b60520bc09f8bb3b9dc26d66ab4752a2f3bd6a5e517b6a173a0a6f1cbe4867a0195d2bfeb9f823817a9e0"), hashlib.sha256(bytes.fromhex("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e")).digest(), bytes.fromhex("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d6440603182085317e8d1eb51453e4b058a1b6b231b7be8214b920969df35eb2dc0988e27048edd7")))