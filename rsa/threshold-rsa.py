import random
import hashlib
from sympy import nextprime, isprime, gcd
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from math import factorial

# ====================================================
# === Global Parameters ==============================
# ====================================================

L = 512         # Bit length of p', q'
k = 3           # Threshold (minimum # of participants to sign)
l = 5           # Total number of participants
L1 = 128        # Security parameter for Fiat-Shamir challenge

# ====================================================
# === Helper / Protocol Functions ====================
# ====================================================

def generate_safe_prime(bits):
    while True:
        p_prime = getPrime(bits)
        p = 2 * p_prime + 1
        if isprime(p):
            return p, p_prime

def H(msg):
    return bytes_to_long(hashlib.sha256(msg).digest())

def H_prime(*args):
    concat = b"".join(long_to_bytes(x) for x in args)
    h = hashlib.sha256(concat).digest()
    return int.from_bytes(h, "big") % (2 ** (2 * L + L1))

def eval_poly(coeffs, x, mod):
    result = 0
    for i, coef in enumerate(coeffs):
        result = (result + coef * pow(x, i, mod)) % mod
    return result

def lagrange_coeffs(S, i, mod, factorial_l):
    lambdas = {}
    for j in S:
        num = factorial_l
        denom = 1
        for j_prime in S:
            if j_prime != j:
                num = (num * (i - j_prime)) % mod
                denom = (denom * (j - j_prime)) % mod
        lambdas[j] = (num * inverse(denom, mod)) % mod
    return lambdas

def extended_euclid(a, b):
    if b == 0:
        return (1, 0, a)
    x1, y1, d = extended_euclid(b, a % b)
    x, y = y1, x1 - (a // b) * y1
    return x, y, d

# Signature Share Generation
def signature_share(i, msg, SKs, vks, v, N, M):
    si = SKs[i - 1]
    vi = vks[i - 1]
    x = H(msg) % N
    delta = factorial(l)
    x2 = pow(x, 2 * delta, N)
    x_tilde = pow(x, 4 * delta, N)
    xi = pow(x2, si, N)

    r = random.randrange(0, 2 ** (2 * L + L1))
    v_r = pow(v, r, N)
    x_r = pow(x_tilde, r, N)
    c = H_prime(v, x_tilde, vi, pow(xi, 2, N), v_r, x_r)
    z = (si * c + r) % M

    return (xi, (z, c))

# Signature Share Verification
def verify_share(i, msg, xi, proof, vks, v, N):
    vi = vks[i - 1]
    x = H(msg) % N
    delta = factorial(l)
    x_tilde = pow(x, 4 * delta, N)
    z, c = proof

    lhs_v = pow(v, z, N)
    rhs_v = (lhs_v * inverse(pow(vi, c, N), N)) % N

    lhs_x = pow(x_tilde, z, N)
    rhs_x = (lhs_x * inverse(pow(xi, 2 * c, N), N)) % N

    c_check = H_prime(v, x_tilde, vi, pow(xi, 2, N), rhs_v, rhs_x)
    return c_check == c

# Combine Shares into a Full Signature
def combine_shares(msg, shares_dict, N, e, M):
    x = H(msg) % N
    delta = factorial(l)
    S = list(shares_dict.keys())
    lambdas = lagrange_coeffs(S, 0, M, delta)

    w = 1
    for i in S:
        xi, _ = shares_dict[i]
        lam = lambdas[i]
        w = (w * pow(xi, 2 * lam, N)) % N

    e_prime = 4 * delta ** 2
    a, b, _ = extended_euclid(e_prime, e)
    sig = (pow(w, a, N) * pow(x, b, N)) % N
    return sig

def verify_signature(msg, sig, e, N):
    x = H(msg) % N
    return pow(sig, e, N) == x

# ====================================================
# === Main Execution ================================
# ====================================================

def main():
    # === Key Generation ===
    print("Generating first pair of safe primes...")
    p, p_prime = generate_safe_prime(L)
    print(f"\rp={p}, p'={p_prime}")
    print("Generating second pair of safe primes...")
    q, q_prime = generate_safe_prime(L)
    print(f"q={q}, q'={q_prime}")
    N = p * q
    M = p_prime * q_prime
    print(f"N = {N}, M = {M}")
    e = nextprime(max(l, 65537))
    d = inverse(e, M)
    print(f"e = {e}, d = {d}")

    # === Polynomial & Shares ===
    poly = [d] + [random.randrange(M) for _ in range(1, k)]
    shares = [eval_poly(poly, i, M) for i in range(1, l + 1)]

    # === Generate Verification Keys ===
    while True:
        rand_elem = random.randrange(2, N)
        if gcd(rand_elem, N) == 1:
            v = pow(rand_elem, 2, N)
            break
    vks = [pow(v, si, N) for si in shares]

    # === Signature Share Generation ===
    msg = b"Test message"
    sig_shares = {}
    for i in range(1, k + 1):
        xi, proof = signature_share(i, msg, shares, vks, v, N, M)
        if verify_share(i, msg, xi, proof, vks, v, N):
            print(f"Signature share {i}: ({xi}, {proof})")
            sig_shares[i] = (xi, proof)
        else:
            print(f"Signature share verification failed!")
            return

    # === Combine Signature Shares ===
    final_signature = combine_shares(msg, sig_shares, N, e, M)
    print(f"Combined signature: {final_signature}")
    
    if verify_signature(msg, final_signature, e, N):
        print("✅Signature verified correctly.")
    else:
        print("❌Signature verification failed!")

if __name__ == "__main__":
    main()
