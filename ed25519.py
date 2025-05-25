import hashlib
import secrets
import struct
from typing import List, Set, Dict, Tuple, Optional
from dataclasses import dataclass
from threading import Lock
import math

# Ed25519 constants
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_FIELD_SIZE = 2**255 - 19
ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555

@dataclass
class ThresholdSigEd25519Params:
    private_key: 'Scalar'
    public_key: bytes
    private_shares: List['Scalar']
    sig: Optional[List['Scalar']] = None

class Scalar:
    def __init__(self, value: int):
        self.value = value % ED25519_ORDER
    
    @classmethod
    def from_bytes_mod_order_wide(cls, data: bytes) -> 'Scalar':
        """Create scalar from 64-byte hash, reducing modulo order"""
        value = int.from_bytes(data, 'little')
        return cls(value)
    
    @classmethod
    def from_bits(cls, data: bytes) -> 'Scalar':
        """Create scalar from 32-byte data"""
        if len(data) != 32:
            raise ValueError("Expected 32 bytes")
        value = int.from_bytes(data, 'little')
        return cls(value)
    
    @classmethod
    def from_bigint(cls, value: int) -> 'Scalar':
        return cls(value)
    
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(32, 'little')
    
    def add(self, other: 'Scalar') -> 'Scalar':
        return Scalar(self.value + other.value)
    
    def subtract(self, other: 'Scalar') -> 'Scalar':
        return Scalar(self.value - other.value)
    
    def multiply(self, other: 'Scalar') -> 'Scalar':
        return Scalar(self.value * other.value)
    
    def multiply_and_add(self, mul: 'Scalar', add: 'Scalar') -> 'Scalar':
        return Scalar(self.value * mul.value + add.value)
    
    def invert(self) -> 'Scalar':
        return Scalar(pow(self.value, ED25519_ORDER - 2, ED25519_ORDER))
    
    def __eq__(self, other) -> bool:
        return isinstance(other, Scalar) and self.value == other.value

# Constants
SCALAR_ZERO = Scalar(0)
SCALAR_ONE = Scalar(1)

class FieldElement:
    def __init__(self, value: int):
        self.value = value % ED25519_FIELD_SIZE
    
    def add(self, other: 'FieldElement') -> 'FieldElement':
        return FieldElement(self.value + other.value)
    
    def subtract(self, other: 'FieldElement') -> 'FieldElement':
        return FieldElement(self.value - other.value)
    
    def multiply(self, other: 'FieldElement') -> 'FieldElement':
        return FieldElement(self.value * other.value)
    
    def square(self) -> 'FieldElement':
        return FieldElement(self.value * self.value)
    
    def invert(self) -> 'FieldElement':
        return FieldElement(pow(self.value, ED25519_FIELD_SIZE - 2, ED25519_FIELD_SIZE))
    
    def is_negative(self) -> bool:
        return self.value % 2 == 1
    
    def __eq__(self, other) -> bool:
        return isinstance(other, FieldElement) and self.value == other.value

class EdwardsPoint:
    def __init__(self, x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement):
        self.x = x
        self.y = y
        self.z = z
        self.t = t
    
    @classmethod
    def identity(cls) -> 'EdwardsPoint':
        return cls(FieldElement(0), FieldElement(1), FieldElement(1), FieldElement(0))
    
    @classmethod
    def from_compressed(cls, data: bytes) -> 'EdwardsPoint':
        """Decompress a point from 32-byte compressed form"""
        if len(data) != 32:
            raise ValueError("Expected 32 bytes")
        
        y_bytes = bytearray(data)
        sign_bit = (y_bytes[31] & 0x80) != 0
        y_bytes[31] &= 0x7f
        
        y = FieldElement(int.from_bytes(y_bytes, 'little'))
        
        # Check if y is valid (< p)
        if y.value >= ED25519_FIELD_SIZE:
            raise ValueError("y coordinate out of range")
        
        # Recover x coordinate: x² = (y² - 1) / (d*y² + 1)
        y_squared = y.square()
        u = y_squared.subtract(FieldElement(1))
        v = FieldElement(ED25519_D).multiply(y_squared).add(FieldElement(1))
        
        # Compute u/v
        x_squared = u.multiply(v.invert())
        
        # Take square root
        x = cls._sqrt(x_squared)
        if x is None:
            raise ValueError("Point not on curve")
        
        # Adjust sign
        if x.is_negative() != sign_bit:
            x = FieldElement(0).subtract(x)
        
        # Construct extended coordinates
        z = FieldElement(1)
        t = x.multiply(y)
        
        return cls(x, y, z, t)
    
    @staticmethod
    def _sqrt(a: FieldElement) -> Optional[FieldElement]:
        """Compute square root in the Ed25519 field"""
        # For Ed25519, p = 2^255 - 19, so p ≡ 5 (mod 8)
        # We can use the formula: sqrt(a) = a^((p+3)/8) or a^((p+3)/8) * 2^((p-1)/4)
        exponent = (ED25519_FIELD_SIZE + 3) // 8
        candidate = FieldElement(pow(a.value, exponent, ED25519_FIELD_SIZE))
        
        if candidate.square().value == a.value:
            return candidate
        
        # Try the other square root
        i = FieldElement(pow(2, (ED25519_FIELD_SIZE - 1) // 4, ED25519_FIELD_SIZE))
        candidate = candidate.multiply(i)
        
        if candidate.square().value == a.value:
            return candidate
        
        return None
    
    def add(self, other: 'EdwardsPoint') -> 'EdwardsPoint':
        """Add two Edwards points using extended coordinates"""
        # Extended Edwards addition (from RFC 8032)
        a = self.x.multiply(other.x)
        b = self.y.multiply(other.y)
        c = self.z.multiply(other.z)
        d = self.t.multiply(other.t)
        e = FieldElement(ED25519_D).multiply(d)
        f = c.subtract(e)
        g = c.add(e)
        h = self.x.add(self.y).multiply(other.x.add(other.y))
        
        x3 = f.multiply(h.subtract(a).subtract(b))
        y3 = g.multiply(b.subtract(a))
        z3 = f.multiply(g)
        t3 = h.subtract(a).subtract(b).multiply(b.subtract(a))
        
        return EdwardsPoint(x3, y3, z3, t3)
    
    def multiply(self, scalar: Scalar) -> 'EdwardsPoint':
        """Scalar multiplication using double-and-add"""
        result = EdwardsPoint.identity()
        addend = self
        
        s = scalar.value
        while s > 0:
            if s & 1:
                result = result.add(addend)
            addend = addend.double()
            s >>= 1
        
        return result
    
    def double(self) -> 'EdwardsPoint':
        """Point doubling using extended coordinates"""
        a = self.x.square()
        b = self.y.square()
        c = self.z.square().multiply(FieldElement(2))
        d = FieldElement(0).subtract(a)
        e = self.x.add(self.y).square().subtract(a).subtract(b)
        g = d.add(b)
        f = g.subtract(c)
        h = d.subtract(b)
        
        x3 = e.multiply(f)
        y3 = g.multiply(h)
        t3 = e.multiply(h)
        z3 = f.multiply(g)
        
        return EdwardsPoint(x3, y3, z3, t3)
    
    def negate(self) -> 'EdwardsPoint':
        return EdwardsPoint(
            FieldElement(0).subtract(self.x),
            self.y,
            self.z,
            FieldElement(0).subtract(self.t)
        )
    
    def compress(self) -> bytes:
        """Compress point to 32-byte representation"""
        # Convert to affine coordinates
        inv_z = self.z.invert()
        x = self.x.multiply(inv_z)
        y = self.y.multiply(inv_z)
        
        # Encode y coordinate with sign bit
        y_bytes = y.value.to_bytes(32, 'little')
        y_bytes = bytearray(y_bytes)
        
        if x.is_negative():
            y_bytes[31] |= 0x80
        
        return bytes(y_bytes)
    
    @staticmethod
    def vartime_double_scalar_multiply_basepoint(a: Scalar, point_a: 'EdwardsPoint', b: Scalar) -> 'EdwardsPoint':
        """Compute a*A + b*B where B is the basepoint"""
        basepoint = get_ed25519_basepoint()
        return point_a.multiply(a).add(basepoint.multiply(b))

def get_ed25519_basepoint() -> EdwardsPoint:
    """Get the Ed25519 basepoint"""
    # Ed25519 basepoint y coordinate = 4/5 mod p
    # Compressed form has y = 4/5 and x sign bit = 0
    basepoint_bytes = bytes([
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    ])
    try:
        return EdwardsPoint.from_compressed(basepoint_bytes)
    except:
        # Fallback: construct basepoint directly
        # x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        # y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
        x = FieldElement(15112221349535400772501151409588531511454012693041857206046113283949847762202)
        y = FieldElement(46316835694926478169428394003475163141307993866256225615783033603165251855960)
        z = FieldElement(1)
        t = x.multiply(y)
        return EdwardsPoint(x, y, z, t)

class Polynomial:
    def __init__(self, order: int, a0: Scalar):
        self.coefficients = [a0]
        for _ in range(1, order):
            random_bytes = secrets.token_bytes(32)
            self.coefficients.append(Scalar.from_bits(random_bytes))
    
    def evaluate_at(self, x: Scalar) -> Scalar:
        result = self.coefficients[0]
        x_power = SCALAR_ONE
        
        for i in range(1, len(self.coefficients)):
            x_power = x_power.multiply(x)
            result = self.coefficients[i].multiply_and_add(x_power, result)
        
        return result

class ThresholdSigEd25519:
    def __init__(self, t: int, n: int):
        self.t = t  # threshold
        self.n = n  # total number of participants
        self._prefix = b'\xff' * 32
        self._lagrange_cache: Dict[frozenset, List[Scalar]] = {}
        self._cache_lock = Lock()
    
    def generate(self) -> ThresholdSigEd25519Params:
        """Generate threshold signature parameters"""
        # Generate secret key
        secret = secrets.token_bytes(32)
        
        # Create private and public keys
        public_key = self._create_public_key(secret)
        private_key = self._create_private_key(secret)
        
        # Generate private key shares using Shamir's secret sharing
        private_shares = self._shamir_split(private_key, self.n)
        
        return ThresholdSigEd25519Params(
            private_key=private_key,
            public_key=public_key,
            private_shares=private_shares
        )
    
    def _shamir_split(self, secret: Scalar, n: int) -> List[Scalar]:
        """Split secret using Shamir's secret sharing"""
        result = []
        poly = Polynomial(self.t, secret)
        
        for i in range(n):
            x = Scalar.from_bigint(i + 1)
            result.append(poly.evaluate_at(x))
        
        return result
    
    def gather_ri(self, params: ThresholdSigEd25519Params, to_sign: str, nodes: Set[int]) -> List[EdwardsPoint]:
        """Gather R_i values from participating nodes"""
        rs_values = []
        ri_points = []
        
        for i in range(self.n):
            if i in nodes:
                private_share = params.private_shares[i]
                rs = self._compute_rs(private_share, to_sign)
                rs_values.append(rs)
                
                ri = self._mul_basepoint(rs)
                ri_points.append(ri)
        
        params.sig = rs_values
        return ri_points
    
    def compute_ri(self, private_share: Scalar, to_sign: str) -> Scalar:
        """Compute R_i for a single node"""
        return self._compute_rs(private_share, to_sign)
    
    def compute_r(self, ri_points: List[EdwardsPoint]) -> EdwardsPoint:
        """Compute combined R point from R_i values"""
        r = ri_points[0]
        for i in range(1, self.t):
            r = r.add(ri_points[i])
        return r
    
    def compute_k(self, public_key: bytes, r: EdwardsPoint, to_sign: str) -> Scalar:
        """Compute challenge scalar k"""
        hasher = hashlib.sha512()
        hasher.update(r.compress())
        hasher.update(public_key)
        hasher.update(to_sign.encode('utf-8'))
        digest = hasher.digest()
        return Scalar.from_bytes_mod_order_wide(digest)
    
    def gather_signatures(self, params: ThresholdSigEd25519Params, k: Scalar, nodes: Set[int]) -> List[Scalar]:
        """Gather signature shares from participating nodes"""
        result = []
        idx = 0
        
        for i in range(self.n):
            if i in nodes:
                private_share = params.private_shares[i]
                sig = params.sig[idx]
                pt = self._compute_sig(k, i + 1, private_share, sig, nodes)
                result.append(pt)
                idx += 1
        
        return result
    
    def compute_signature_share(self, index: int, private_share: Scalar, sig: Scalar, k: Scalar, nodes: Set[int]) -> Scalar:
        """Compute signature share for a single node"""
        return self._compute_sig(k, index, private_share, sig, nodes)
    
    def compute_final_signature(self, r: EdwardsPoint, signature_shares: List[Scalar]) -> bytes:
        """Compute final signature from signature shares"""
        s = SCALAR_ZERO
        for i in range(self.t):
            s = s.add(signature_shares[i])
        
        # Combine R and s into signature
        result = bytearray()
        result.extend(r.compress())
        result.extend(s.to_bytes())
        return bytes(result)
    
    def _compute_sig(self, k: Scalar, index: int, private_share: Scalar, sig: Scalar, nodes: Set[int]) -> Scalar:
        """Compute signature component"""
        coeff = self._get_lagrange_coeff(self.n, nodes)
        return private_share.multiply(coeff[index - 1]).multiply(k).add(sig)
    
    def _compute_rs(self, private_share: Scalar, to_sign: str) -> Scalar:
        """Compute random scalar for signature"""
        rnd = secrets.token_bytes(64)
        
        hasher = hashlib.sha512()
        hasher.update(self._prefix)
        hasher.update(private_share.to_bytes())
        hasher.update(to_sign.encode('utf-8'))
        hasher.update(rnd)
        
        digest = hasher.digest()
        return Scalar.from_bytes_mod_order_wide(digest)
    
    def _mul_basepoint(self, scalar: Scalar) -> EdwardsPoint:
        """Multiply basepoint by scalar"""
        basepoint = get_ed25519_basepoint()
        return basepoint.multiply(scalar)
    
    def _create_public_key(self, secret: bytes) -> bytes:
        """Create public key from secret"""
        hash_val = hashlib.sha512(secret).digest()
        hash_val = bytearray(hash_val)
        hash_val[0] &= 248
        hash_val[31] &= 127
        hash_val[31] |= 64
        
        s = Scalar.from_bits(bytes(hash_val[:32]))
        return self._mul_basepoint(s).compress()
    
    def _create_private_key(self, secret: bytes) -> Scalar:
        """Create private key scalar from secret"""
        hash_val = hashlib.sha512(secret).digest()
        hash_val = bytearray(hash_val)
        hash_val[0] &= 248
        hash_val[31] &= 127
        hash_val[31] |= 64
        
        return Scalar.from_bits(bytes(hash_val[:32]))
    
    def _get_lagrange_coeff(self, size: int, nodes: Set[int]) -> List[Scalar]:
        """Compute Lagrange coefficients for interpolation"""
        nodes_key = frozenset(nodes)
        
        with self._cache_lock:
            if nodes_key in self._lagrange_cache:
                return self._lagrange_cache[nodes_key]
        
        index = []
        lagrange_coeff = []
        
        for i in range(1, size + 1):
            index.append(Scalar.from_bigint(i))
            lagrange_coeff.append(SCALAR_ONE)
        
        for i in range(1, size + 1):
            prod_diff = SCALAR_ONE
            factor = SCALAR_ONE
            
            for j in range(1, size + 1):
                if i != j and (j - 1) in nodes:
                    dx = index[j - 1].subtract(index[i - 1])
                    factor = factor.multiply(index[j - 1])
                    prod_diff = prod_diff.multiply(dx)
            
            lagrange_coeff[i - 1] = factor.multiply(prod_diff.invert())
        
        with self._cache_lock:
            self._lagrange_cache[nodes_key] = lagrange_coeff
        
        return lagrange_coeff
    
    @staticmethod
    def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
        """Verify Ed25519 signature"""
        if len(signature) != 64 or len(public_key) != 32:
            return False
        
        try:
            r_bytes = signature[:32]
            s_bytes = signature[32:]
            
            # Check if s is in valid range
            s_int = int.from_bytes(s_bytes, 'little')
            if s_int >= ED25519_ORDER:
                return False
            
            # Decompress R point
            try:
                r_point = EdwardsPoint.from_compressed(r_bytes)
            except:
                return False
            
            # Decompress public key
            try:
                a_point = EdwardsPoint.from_compressed(public_key)
            except:
                return False
            
            # Compute challenge
            hasher = hashlib.sha512()
            hasher.update(r_bytes)
            hasher.update(public_key)
            hasher.update(message)
            digest = hasher.digest()
            k = Scalar.from_bytes_mod_order_wide(digest)
            
            # Verify equation: s*B = R + k*A
            s = Scalar.from_bits(s_bytes)
            basepoint = get_ed25519_basepoint()
            
            left = basepoint.multiply(s)
            right = r_point.add(a_point.multiply(k))
            
            return left.compress() == right.compress()
        
        except Exception:
            return False

# Example usage with debugging
def example_usage():
    # Create threshold signature scheme (2-of-3)
    threshold_sig = ThresholdSigEd25519(t=2, n=3)
    
    # Generate parameters
    params = threshold_sig.generate()
    print(f"Generated threshold signature parameters")
    print(f"Public key: {params.public_key.hex()}")
    
    # Test with a simple message first
    message = "test"
    
    # Simulate signing with nodes 0 and 1
    participating_nodes = {0, 1}
    
    print(f"Signing message: '{message}'")
    print(f"Participating nodes: {participating_nodes}")
    
    # Phase 1: Gather R_i values
    ri_points = threshold_sig.gather_ri(params, message, participating_nodes)
    print(f"Generated {len(ri_points)} R_i points")
    
    # Phase 2: Compute combined R
    r = threshold_sig.compute_r(ri_points)
    print(f"Combined R point computed")
    
    # Phase 3: Compute challenge
    k = threshold_sig.compute_k(params.public_key, r, message)
    print(f"Challenge k computed")
    
    # Phase 4: Gather signature shares
    signature_shares = threshold_sig.gather_signatures(params, k, participating_nodes)
    print(f"Generated {len(signature_shares)} signature shares")
    
    # Phase 5: Compute final signature
    signature = threshold_sig.compute_final_signature(r, signature_shares)
    
    print(f"Signature: {signature.hex()}")
    
    # Verify signature
    is_valid = ThresholdSigEd25519.verify(
        params.public_key, 
        signature, 
        message.encode('utf-8')
    )
    print(f"Signature valid: {is_valid}")
    
    # Test with regular Ed25519 for comparison
    import ed25519  # If available
    try:
        # Generate a regular Ed25519 signature for comparison
        import nacl.signing
        import nacl.encoding
        
        signing_key = nacl.signing.SigningKey.generate()
        signed = signing_key.sign(message.encode('utf-8'))
        verify_key = signing_key.verify_key
        
        print(f"\nRegular Ed25519 verification test:")
        try:
            verify_key.verify(signed.message, signed.signature)
            print("Regular Ed25519 signature verified successfully")
        except:
            print("Regular Ed25519 signature verification failed")
            
    except ImportError:
        print("PyNaCl not available for comparison test")

if __name__ == "__main__":
    example_usage()