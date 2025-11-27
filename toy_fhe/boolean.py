# toy_fhe/boolean.py

from .scheme import ToyDGHV

class FHEBoolean:
    """
    Boolean FHE gates on top of the ToyDGHV scheme.

    This class abstracts:
      - Encryption/decryption of individual bits.
      - Homomorphic bit-wise operations (XOR, AND, NOT).

    These are exactly the basic gates needed to express any Boolean
    circuit, including decryption circuits and small ALU-style logic.
    """

    def __init__(self, fhe_scheme: ToyDGHV, sk: int):
        """
        Parameters
        ----------
        fhe_scheme : ToyDGHV
            Instance of the ToyDGHV encryption scheme.
        sk : int
            Secret key p.

        Note
        ----
        In a real public-key HE setting, encryption would not require sk.
        In this didactic implementation we cheat slightly by using the
        secret key for encryption as well, to keep the focus on:
          - Ciphertext structure
          - Homomorphic evaluation
        rather than key-distribution issues.
        """
        self.fhe = fhe_scheme
        self.sk = sk

    def enc_bit(self, m: int) -> int:
        """
        Encrypt a plaintext bit m in {0,1}.

        This is just a convenience wrapper around encrypt_with_sk.
        """
        return self.fhe.encrypt_with_sk(self.sk, m)

    def dec_bit(self, c: int) -> int:
        """
        Decrypt a ciphertext bit.

        Convenience wrapper around ToyDGHV.decrypt.
        """
        return self.fhe.decrypt(self.sk, c)

    def xor(self, c1: int, c2: int) -> int:
        """
        Homomorphic XOR gate.

        For bits, XOR corresponds to addition mod 2:
            m_xor = m1 XOR m2 = (m1 + m2) mod 2.

        We rely on:
            Decrypt(add(c1,c2)) = (m1 + m2) mod 2
        as long as noise is within bounds.
        """
        return self.fhe.add(c1, c2)

    def and_(self, c1: int, c2: int) -> int:
        """
        Homomorphic AND gate, implemented as ciphertext multiplication.

        For bits:
            m_and = m1 AND m2 = (m1 * m2) mod 2.

        We rely on:
            Decrypt(mul(c1,c2)) = (m1 * m2) mod 2
        assuming noise remains small enough.
        """
        return self.fhe.mul(c1, c2)

    def not_(self, c: int) -> int:
        """
        Homomorphic NOT gate.

        For bits:
            NOT(m) = 1 - m mod 2 = 1 XOR m.

        We encrypt 1 as a ciphertext and XOR with c.
        """
        one_enc = self.enc_bit(1)
        return self.xor(one_enc, c)
