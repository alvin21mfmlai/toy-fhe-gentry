# toy_fhe/scheme.py

import random
from .params import ToyDGHVParams


def random_odd_integer(bitlen: int) -> int:
    """
    Return a random odd integer with exactly 'bitlen' bits (MSB set).
    """
    x = random.getrandbits(bitlen)
    x |= (1 << (bitlen - 1))  # ensure MSB is 1
    if x % 2 == 0:
        x += 1
    return x


def random_integer(bitlen: int) -> int:
    """
    Return a random integer in [0, 2^bitlen).
    """
    return random.getrandbits(bitlen)


def random_small_noise(bound: int) -> int:
    """
    Return a small noise integer r sampled uniformly from [-bound, bound].
    """
    return random.randint(-bound, bound)


class ToyDGHV:
    """
    A toy somewhat homomorphic encryption scheme in the spirit of DGHV.

    Ciphertexts are integers of the form:
        c = m + 2*r + p*q,

    where:
        - p: secret odd integer (secret key),
        - m: plaintext bit in {0,1},
        - r: small noise,
        - q: large random integer.

    Decryption recovers m as:
        m = (c mod p) mod 2,

    as long as |m + 2*r| < p/2. Homomorphic addition and multiplication operate
    directly on ciphertexts in Z, letting noise grow.

    This implementation is purely pedagogical and not secure.
    """

    def __init__(self, params: ToyDGHVParams):
        self.params = params

    # ------------------ Key Generation ------------------

    def keygen(self):
        """
        Generate a secret key p and a minimalistic 'public key' record.

        Returns
        -------
        sk : int
            Secret key p (odd integer).
        pk : dict
            Public parameter record (does not contain a full DGHV public key).
        """
        p = random_odd_integer(self.params.p_bits)
        sk = p
        pk = {
            "p_bits": self.params.p_bits,
            "q_bits": self.params.q_bits,
            "r_bound": self.params.r_bound,
        }
        return sk, pk

    # ------------------ Encryption (didactic) ------------------

    def encrypt_with_sk(self, sk: int, m: int, return_noise: bool = False):
        """
        Encrypt a bit m in {0,1} using the secret key p.

        Parameters
        ----------
        sk : int
            Secret key p.
        m : int
            Plaintext bit in {0,1}.
        return_noise : bool
            If True, return (ciphertext, r) to track the initial noise.

        Returns
        -------
        c : int
            Ciphertext.
        r : int, optional
            Noise term, if return_noise=True.

        Notes
        -----
        The encryption formula is:
            c = m + 2*r + p*q,
        where r is small and q is a large random integer.
        """
        assert m in (0, 1), "ToyDGHV encrypts only bits in {0,1}."

        r = random_small_noise(self.params.r_bound)
        q = random_integer(self.params.q_bits)

        c = m + 2 * r + sk * q
        if return_noise:
            return c, r
        return c

    # ------------------ Decryption ------------------

    def decrypt(self, sk: int, c: int) -> int:
        """
        Decrypt ciphertext c with secret key p.

        Parameters
        ----------
        sk : int
            Secret key p.
        c : int
            Ciphertext.

        Returns
        -------
        m : int
            Decrypted bit in {0,1}.

        Notes
        -----
        Decryption computes:
            x = c mod p, centered into [-p/2, p/2),
            m = x mod 2.

        Correctness requires that |m + 2*r| < p/2 for the corresponding r.
        """
        p = sk
        x = c % p
        # center into [-p/2, p/2)
        if x > p // 2:
            x -= p
        return x & 1  # x mod 2

    # ------------------ Homomorphic Operations ------------------

    def add(self, c1: int, c2: int) -> int:
        """
        Homomorphic addition of ciphertexts.

        Parameters
        ----------
        c1, c2 : int
            Ciphertexts encrypting bits m1, m2.

        Returns
        -------
        c_add : int
            Ciphertext encrypting (m1 + m2) mod 2.

        Notes
        -----
        Addition adds both messages and noises:
            c_add = c1 + c2.
        """
        return c1 + c2

    def mul(self, c1: int, c2: int) -> int:
        """
        Homomorphic multiplication of ciphertexts.

        Parameters
        ----------
        c1, c2 : int
            Ciphertexts encrypting bits m1, m2.

        Returns
        -------
        c_mul : int
            Ciphertext encrypting (m1 * m2) mod 2.

        Notes
        -----
        Multiplication multiplies both messages and noises:
            c_mul = c1 * c2.

        Noise growth is substantial; correctness holds only for shallow circuits.
        """
        return c1 * c2

    # ------------------ Noise Estimation (rough) ------------------

    def estimate_noise_after_add(self, r1: int, r2: int) -> int:
        """
        Rough noise estimate after homomorphic addition:
            r_add ~ r1 + r2.
        """
        return r1 + r2

    def estimate_noise_after_mul(self, r1: int, r2: int) -> int:
        """
        Very rough noise estimate after homomorphic multiplication.

        For demonstration, we approximate the new noise scale as:
            ~ 4|r1|*|r2| + 2(|r1| + |r2|),
        which reflects multiplicative growth and cross-terms.
        """
        return 4 * abs(r1) * abs(r2) + 2 * (abs(r1) + abs(r2))
