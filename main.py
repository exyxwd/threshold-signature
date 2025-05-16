import random
import argparse
from sha256 import generate_hash
from ecc import Point
from shamir import generate_shares, reconstruct_secret, modinv

# === Helper Functions ===
def hash_message(msg):
    return int.from_bytes(generate_hash(msg.encode())) # SHA256 hash

def find_order(G: Point):
    """Find the order of point G on the curve."""
    point = G
    for i in range(1, G.prime + 2):  # p+1 per Hasse's theorem
        if point.x is None:  # Point at infinity
            return i
        point += G
    return None

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generate_coprime_k(n):
    while True:
        k = random.randint(1, n - 1)
        if gcd(k, n) == 1:
            return k

# === ECDSA Sign/Verify ===
def sign(msg, d, k, G, n):
    e = hash_message(msg) % n
    R = k * G
    r = R.x.num % n
    if r == 0:
        raise ValueError("Invalid r value")
    s = ((e + r * d) * modinv(k, n)) % n
    if s == 0:
        raise ValueError("Invalid s value")
    return (r, s)

def verify(msg, sig, P, G, n):
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = hash_message(msg) % n
    s_inv = modinv(s, n)
    u1 = (e * s_inv) % n
    u2 = (r * s_inv) % n
    R = u1 * G + u2 * P
    if R.x is None:
        return False
    return R.x.num % n == r

# === Main Demo ===
def main():
    parser = argparse.ArgumentParser(description="Threshold Signature Demo")
    parser.add_argument("-n", "--num-shares", type=int, default=5, help="Number of shares to generate, must be <= threshold (default: 5)")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="Threshold for secret reconstruction, must be >= shares (default: 3)")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")
    if args.threshold > args.num_shares:
        parser.error("Threshold cannot be greater than the number of shares.")

    # === Secp256k1 Curve Parameters ===
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    G = Point(x, y, a, b, p)
    # order of G
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    print("=== Secp256k1 Threshold Signature Demo ===")

    # Generate keypair
    d = random.randint(1, n - 1)
    P = d * G
    print(f"Private key (d): {d}")
    print(f"Public key (P): {P}\n")

    # Shamir's Secret Sharing
    t = args.threshold
    n_shares = args.num_shares
    shares = generate_shares(d, t, n_shares, n)
    print("Shares:")
    for i, share in enumerate(shares, 1):
        print(f"Share {i}: {share}")
    print()

    # Reconstruct secret from t shares
    selected_shares = shares[:t]
    d_rec = reconstruct_secret(selected_shares, n)
    print(f"Reconstructed d from {t} shares: {d_rec}\n")

    # Sign a message
    msg = "Hello threshold ECDSA"

    print(f"Message: {msg}")

    k = random.randint(1, n - 1)
    sig = sign(msg, d_rec, k, G, n)
    print(f"Signature: {sig}\n")

    # Verify signature
    valid = verify(msg, sig, P, G, n)
    print(f"Signature valid? {valid}")

if __name__ == "__main__":
    main()
