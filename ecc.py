# ecc_oop.py

class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            raise ValueError(f"Num {num} not in field range 0 to {prime - 1}")
        self.num = num
        self.prime = prime

    def __eq__(self, other):
        return self.num == other.num and self.prime == other.prime

    def __add__(self, other):
        self._check_field(other)
        return FieldElement((self.num + other.num) % self.prime, self.prime)

    def __sub__(self, other):
        self._check_field(other)
        return FieldElement((self.num - other.num) % self.prime, self.prime)

    def __mul__(self, other):
        self._check_field(other)
        return FieldElement((self.num * other.num) % self.prime, self.prime)

    def __pow__(self, exp):
        return FieldElement(pow(self.num, exp, self.prime), self.prime)

    def __truediv__(self, other):
        self._check_field(other)
        return self * other.inv()

    def __neg__(self):
        return FieldElement(-self.num % self.prime, self.prime)

    def inv(self):
        return FieldElement(pow(self.num, -1, self.prime), self.prime)

    def _check_field(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot operate on two numbers in different Fields.")

    def __repr__(self):
        return f"FieldElement_{self.prime}({self.num})"


class Point:
    def __init__(self, x, y, a, b, prime):
        self.a = FieldElement(a, prime)
        self.b = FieldElement(b, prime)
        self.prime = prime

        if x is None and y is None:
            self.x = self.y = None  # Point at infinity
        else:
            self.x = FieldElement(x, prime)
            self.y = FieldElement(y, prime)

            if not self._is_on_curve():
                raise ValueError(f"Point ({x}, {y}) is not on the curve")

    def _is_on_curve(self):
        if self.x is None:
            return True
        left = self.y ** 2
        right = self.x ** 3 + self.a * self.x + self.b
        return left == right

    def __eq__(self, other):
        return (
            self.x == other.x and
            self.y == other.y and
            self.a == other.a and
            self.b == other.b
        )

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError("Points are not on the same curve")

        if self.x is None:
            return other
        if other.x is None:
            return self

        # Vertical line
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a.num, self.b.num, self.prime)

        # Point doubling
        if self == other:
            if self.y.num == 0:
                return self.__class__(None, None, self.a.num, self.b.num, self.prime)
            s = (self.x ** 2 * FieldElement(3, self.prime) + self.a) / (self.y * FieldElement(2, self.prime))
        else:
            s = (other.y - self.y) / (other.x - self.x)

        x3 = s ** 2 - self.x - other.x
        y3 = s * (self.x - x3) - self.y

        return self.__class__(x3.num, y3.num, self.a.num, self.b.num, self.prime)

    def __rmul__(self, coef):
        coef = coef % self.prime
        result = self.__class__(None, None, self.a.num, self.b.num, self.prime)
        addend = self

        while coef:
            if coef & 1:
                result += addend
            addend += addend
            coef >>= 1

        return result

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        return f"Point({self.x.num}, {self.y.num})"

# Example usage
if __name__ == "__main__":
    # Define curve: y^2 = x^3 + ax + b over F_p
    p = 9739
    a = 497
    b = 1768

    # Base point
    G = Point(1804, 5368, a, b, p)

    print("Testing scalar multiplication with OOP:")
    for k in range(1, 6):
        P = k * G
        print(f"{k} * G = {P}")
