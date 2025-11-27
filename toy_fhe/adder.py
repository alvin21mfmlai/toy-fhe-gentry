# toy_fhe/params.py

from dataclasses import dataclass

@dataclass
class ToyDGHVParams:
    """
    Parameter container for the toy DGHV-style FHE scheme.

    This keeps all tunable parameters in one place such that we can:
      - Experiment with different bit-lengths for p and q.
      - Adjust the initial noise bound.
      - Conceptually treat sec_lambda as the security parameter.

    NOTE: In this toy implementation, these parameters are NOT chosen
    to give real cryptographic security. They are just for exploring
    noise growth and correctness properties.
    """
    # Conceptual "security parameter" (not used directly in the toy math).
    sec_lambda: int = 32

    # Bit-length of the secret key p (odd integer). Larger p allows more noise
    # before decryption fails, but also makes operations slower.
    p_bits: int = 32

    # Bit-length of the large multiplier q used in encryption.
    # This controls the magnitude of the "masking term" p*q.
    q_bits: int = 64

    # Absolute bound on the small noise |r| at encryption time.
    # The ciphertext will contain 2*r; if 2*r gets too large compared to p,
    # decryption may fail.
    r_bound: int = 8

    # Hypothetical public key size (not used in this minimal implementation).
    # In a full DGHV construction, pk would contain many samples of the form
    # x_i = p*q_i + 2*r_i. Here we don't build that full public key.
    pk_size: int = 32
