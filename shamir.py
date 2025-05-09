import random

def modinv(a, p):
    """Modular inverse using Extended Euclidean Algorithm."""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0")
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def eval_poly(poly, x, p):
    """Evaluate polynomial at x modulo p. poly is list of coefficients [a_0, a_1, ..., a_d]."""
    result = 0
    for i, coeff in enumerate(poly):
        result = (result + coeff * pow(x, i, p)) % p
    return result

def generate_shares(secret, t, n, p):
    """Generate n shares with threshold t, using prime field p."""
    # Random polynomial of degree t-1 with secret as constant term
    coeffs = [secret] + [random.randrange(0, p) for _ in range(t - 1)]
    shares = []
    for i in range(1, n + 1):
        x = i
        y = eval_poly(coeffs, x, p)
        shares.append((x, y))
    return shares

def lagrange_interpolate(x, x_s, y_s, p):
    """Lagrange interpolation at point x. x_s and y_s are lists of t x,y pairs."""
    total = 0
    k = len(x_s)
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        li = 1
        for j in range(k):
            if i == j:
                continue
            xj = x_s[j]
            li *= (x - xj) * modinv(xi - xj, p)
            li %= p
        total += yi * li
        total %= p
    return total

def reconstruct_secret(shares, p):
    """Recover secret (polynomial at x=0) from at least t shares."""
    x_s, y_s = zip(*shares)
    return lagrange_interpolate(0, x_s, y_s, p)


if __name__ == "__main__":
    # Parameters
    secret = 1234
    threshold = 3
    num_shares = 5
    prime = 9739  # same field as ECC

    # Generate shares
    shares = generate_shares(secret, threshold, num_shares, prime)
    print("Generated Shares:")
    for s in shares:
        print(s)

    # Pick any 3 shares to reconstruct
    subset = shares[:3]
    recovered = reconstruct_secret(subset, prime)
    print(f"\nReconstructed secret from 3 shares: {recovered}")
    assert recovered == secret
