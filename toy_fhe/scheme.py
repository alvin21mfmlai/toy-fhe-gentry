# toy_fhe/scheme.py

import random
from .params import ToyDGHVParams


def random_odd_integer(bitlen: int) -> int:
    """
    Return a random odd integer with exactly 'bitlen' bits (MSB set).

    - We force the MSB to be 1 so that we really get a bitlen-bit number.
    - We force the LSB to be 1 (odd) by adding 1 if it is even.
    """
    x = random.getrandbits(bitlen)
    x |= (1 << (bitlen - 1))  # ensure MSB is 1
    if x % 2 == 0:
        x += 1
    return x


def random_integer(bitlen: int) -> int:
    """
    Return a random integer in [0, 2^bitlen).

    This is used for choosing q, the large multiplier inside encryption.
    """
    return random.getrandbits(bitlen)


def random_small_noise(bound: int) -> int:
    """
    Return a small noise integer r sampled uniformly from [-bound, bound].

    In DGHV, this corresponds to the 'error' or 'noise' term.
    The noise must be small enough (compared to p) so that decryption can
    still distinguish m from m + 2*r.
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

    This implementation is purely pedagogical:
        - It is NOT secure (parameters far too small, no proper public key).
        - It is NOT optimized.
        - Its purpose is to illustrate the structure and noise behaviour of
          Gentry/DGHV-style schemes.
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

        In a full DGHV scheme:
            - sk = p (large odd integer).
            - pk would contain many samples of the form x_i = p*q_i + 2*r_i.
        Here we keep pk minimal and only store parameter hints.
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

        Encryption formula (DGHV-style):
            c = m + 2*r + p*q

        Notes
        -----
        - We *do* use the secret key p in encryption here, which is NOT how a
          real public-key HE scheme should behave. A real construction would
          separate public and secret keys properly.
        - This is acceptable for a toy implementation whose goal is to expose
          the mathematical structure of the ciphertexts and noise.
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

        Decryption:
            1) Compute x = c mod p. This removes the p*q term, leaving:
                   x ≈ m + 2*r   (mod p)
               with small |2*r| if encryption/noise growth behaved.
            2) Center x to [-p/2, p/2) to interpret it as a small integer.
            3) Output x mod 2, which recovers m as long as |m+2*r| < p/2.

        This corresponds exactly to the DGHV decryption condition.
        """
        p = sk
        x = c % p
        # Re-interpret x in the centered interval [-p/2, p/2)
        if x > p // 2:
            x -= p
        # Now x ≈ m + 2*r; reduce mod 2 to get m
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

        Explanation
        -----------
        If:
            c1 = m1 + 2*r1 + p*q1
            c2 = m2 + 2*r2 + p*q2

        Then:
            c_add = c1 + c2 = (m1 + m2) + 2*(r1+r2) + p*(q1+q2)

        Decrypt(c_add) thus yields (m1 + m2) mod 2 as long as the new noise
        2*(r1+r2) is still small relative to p.
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

        Explanation
        -----------
        If:
            c1 = m1 + 2*r1 + p*q1
            c2 = m2 + 2*r2 + p*q2

        Then:
            c1 * c2 = m1*m2 + extra_noise_terms + p*something

        After reduction mod p, we get something of the form:
            x ≈ m1*m2 + error

        Decrypting x mod 2 recovers m1*m2 if the error is still small.
        Noise grows quickly here (roughly quadratic in r), so this is
        where multiplicative depth is strongly limited.
        """
        return c1 * c2

    # ------------------ Noise Estimation (rough) ------------------

    def estimate_noise_after_add(self, r1: int, r2: int) -> int:
        """
        Rough noise estimate after homomorphic addition:
            r_add ~ r1 + r2.

        This is *not* a rigorous bound; it is just a simple way to track
        how quickly noise might grow if we chain many additions.
        """
        return r1 + r2

    def estimate_noise_after_mul(self, r1: int, r2: int) -> int:
        """
        Very rough noise estimate after homomorphic multiplication.

        For demonstration, we approximate the new noise scale as:
            ~ 4|r1|*|r2| + 2(|r1| + |r2|),

        which reflects:
            - A cross term 4*r1*r2 from (2*r1)*(2*r2).
            - Linear contributions from (2*r1)*m2 and (2*r2)*m1.

        This is only meant to give you a sense that multiplication grows
        noise much faster than addition.
        """
        return 4 * abs(r1) * abs(r2) + 2 * (abs(r1) + abs(r2))
