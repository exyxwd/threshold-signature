# 1. Modular Arithmetic

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

def mod_add(a, b, p):
    return (a + b) % p

def mod_sub(a, b, p):
    return (a - b) % p

def mod_mul(a, b, p):
    return (a * b) % p

def mod_pow(a, exp, p):
    return pow(a, exp, p)

# 2. Elliptic Curve Arithmetic

# Toy curve: y^2 = x^3 + ax + b over field F_p
# Choose small prime field
p = 9739
a = 497
b = 1768

O = (None, None)  # Point at infinity

def is_on_curve(P):
    if P == O:
        return True
    x, y = P
    return (y ** 2 - (x ** 3 + a * x + b)) % p == 0

def point_add(P, Q):
    if P == O:
        return Q
    if Q == O:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 != y2:
        return O

    if P == Q:
        return point_double(P)

    # slope = (y2 - y1) / (x2 - x1)
    m = mod_mul(mod_sub(y2, y1, p), modinv(mod_sub(x2, x1, p), p), p)
    x3 = mod_sub(mod_sub(mod_pow(m, 2, p), x1, p), x2, p)
    y3 = mod_sub(mod_mul(m, mod_sub(x1, x3, p), p), y1, p)
    return (x3, y3)

def point_double(P):
    if P == O:
        return O

    x, y = P
    m = mod_mul(3 * x * x + a, modinv(2 * y, p), p)
    x3 = mod_sub(mod_pow(m, 2, p), 2 * x, p)
    y3 = mod_sub(mod_mul(m, mod_sub(x, x3, p), p), y, p)
    return (x3, y3)

def scalar_mult(k, P):
    """Multiply point P by scalar k using double-and-add."""
    result = O
    addend = P

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result

if __name__ == "__main__":
    # Base point on the curve
    G = (1804, 5368)
    assert is_on_curve(G)

    print("Testing scalar multiplication:")
    for k in range(1, 6):
        P = scalar_mult(k, G)
        print(f"{k} * G = {P}")
        assert is_on_curve(P)
