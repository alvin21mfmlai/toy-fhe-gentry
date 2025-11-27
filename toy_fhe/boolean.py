# toy_fhe/boolean.py

from .scheme import ToyDGHV

class FHEBoolean:
    """
    Boolean FHE gates on top of the ToyDGHV scheme.

    This class exposes:
    - enc_bit(m): encrypt a plaintext bit m.
    - dec_bit(c): decrypt a ciphertext bit.
    - xor(c1, c2): homomorphic XOR of bits.
    - and_(c1, c2): homomorphic AND.
    - not_(c): homomorphic NOT.

    All operations are built from ToyDGHV.add / ToyDGHV.mul and fresh encryptions.
    """

    def __init__(self, fhe_scheme: ToyDGHV, sk: int):
        """
        Parameters
        ----------
        fhe_scheme : ToyDGHV
            Instance of the ToyDGHV encryption scheme.
        sk : int
            Secret key p (used for encryption in this didactic setting).
        """
        self.fhe = fhe_scheme
        self.sk = sk

    def enc_bit(self, m: int) -> int:
        """
        Encrypt a plaintext bit m in {0,1}.
        """
        return self.fhe.encrypt_with_sk(self.sk, m)

    def dec_bit(self, c: int) -> int:
        """
        Decrypt a ciphertext bit.
        """
        return self.fhe.decrypt(self.sk, c)

    def xor(self, c1: int, c2: int) -> int:
        """
        Homomorphic XOR gate.

        For bits, XOR corresponds to addition mod 2, so we use homomorphic add.
        """
        return self.fhe.add(c1, c2)

    def and_(self, c1: int, c2: int) -> int:
        """
        Homomorphic AND gate, implemented as ciphertext multiplication.
        """
        return self.fhe.mul(c1, c2)

    def not_(self, c: int) -> int:
        """
        Homomorphic NOT gate.

        NOT(m) = 1 - m mod 2, which we implement as 1 XOR m.
        """
        one_enc = self.enc_bit(1)
        return self.xor(one_enc, c)
