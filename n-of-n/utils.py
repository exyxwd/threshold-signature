import random
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Hash import SHA256

rand = random.randrange

def add(values: list[int], size: int) -> int:
    result = 0
    for v in values:
        result = (result + v) % size
    return result

def add_ec(points: list[EccPoint]) -> int:
    result = points[0]
    for v in points[1:]:
        result = (result + v)
    return result

def generate_additive_shares(secret: int, n: int, size: int) -> list[int]:
    shares = [rand(size) for _ in range(n-1)]
    last_sh = (secret - add(shares, size)) % size
    shares = [last_sh] + shares

    return shares

def multiply(values: list[int], size: int) -> int:
    result = 1
    for v in values:
        result = (result * v) % size
    return result

def egcd(a: int, p: int) -> int:
    q = p
    x, last_x = 0, 1
    y, last_y = 1, 0
    while q != 0:
        quot = a // q
        a, q = q, a % q
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x % p

def hash(message: str, q: int):
    message_digest = SHA256.new(data=message.encode("utf-8"))
    m = int(message_digest.hexdigest(), 16) % q

    return m
    
def verify_ecdsa_signature(message: int, r: int, s: int, Y: EccPoint, q: int, G: EccPoint) -> None:
    if r >= q or s >= q:
        raise VerifySignatureError("Signature out of bound q. Abort.")
    m = hash(message, q)
    w = egcd(s, q)
    u1 = (m * w) % q
    u2 = (r * w) % q
    V = u1 * G + u2 * Y
    v = int(V.x)
    if v != r:
        raise VerifySignatureError("Signature mismatch. Abort.")
    

class VerifySignatureError(Exception):
    def __init__(self, message):
        self.message = f"Signature verification failed. {message}"
        super().__init__(self.message)