
from sympy.ntheory.residue_ntheory import primitive_root
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint
from dataclasses import dataclass
from typing import Optional


def get_generator(q):
    return int(primitive_root(q))
    
@dataclass
class ECDSASetup:
    curve: str
    """The name of the elliptic curve."""
    p: Optional[int] = None
    """The finite field of the elliptic curve."""
    q: Optional[int] = None
    """The order of the elliptic curve group."""
    G: Optional[EccPoint] = None
    """A base point on the elliptic curve."""
    h: Optional[int] = None
    """A generator of field :math:`\mathbb{Z}_q`."""

    def generate_ecdsa_setup(self):
        supported_curves = self.supported_curves()
        curve = self.curve
        if curve not in supported_curves:
            raise ValueError("{} is not one of the specified curves. \
                             Please choose one of the following curves:\n \
                             ['P-192', 'P-224', 'P-256', 'P-384', 'P-521']".format(curve))
        p = int(ECC._curves[curve].p)
        q = int(ECC._curves[curve].order)
        G = ECC._curves[curve].G
        h = get_generator(int(q))
        return ECDSASetup(curve, p, q, G, h)
    
    @staticmethod
    def supported_curves():
        return ['P-192', 'P-224', 'P-256', 'P-384', 'P-521']
    
    def print_supported_curves(self):
        supported_curves = self.supported_curves()
        print("Supported Elliptic Curves: ", supported_curves)
