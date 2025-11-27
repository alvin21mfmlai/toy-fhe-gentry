# toy_fhe/params.py

from dataclasses import dataclass

@dataclass
class ToyDGHVParams:
    """
    Parameter container for the toy DGHV-style FHE scheme.

    Attributes
    ----------
    sec_lambda : int
        Conceptual security parameter (for reference only in this toy scheme).
    p_bits : int
        Bit-length of the secret key p (odd integer).
    q_bits : int
        Bit-length of the large multiplier q used in encryption.
    r_bound : int
        Absolute bound on the small noise |r| at encryption time.
    pk_size : int
        Length of the (hypothetical) public key; unused in this minimal version
        but included for completeness.
    """
    sec_lambda: int = 32
    p_bits: int = 32
    q_bits: int = 64
    r_bound: int = 8
    pk_size: int = 32
