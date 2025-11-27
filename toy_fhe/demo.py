# toy_fhe/demo.py

"""
Demo module for the toy-fhe-gentry project.

This file contains three demo entry points:

1) demo_toy_fhe()
   - Minimal "hello world" for the ToyDGHV scheme:
       * key generation
       * encryption / decryption of single bits
       * homomorphic addition (XOR) and multiplication (AND)
       * rough noise estimates

2) demo_fhe_adder()
   - Demonstrates a 4-bit ripple-carry adder built entirely from
     FHEBoolean gates and ToyDGHV:
       * encrypt A and B as bit-vectors
       * homomorphically compute A+B mod 2^n
       * decrypt sum and carry-out

3) demo_fhe_compare_sub()
   - Demonstrates a 3-bit subtractor and comparator:
       * encrypt A and B as bit-vectors
       * homomorphically compute A-B mod 2^n via two's complement
       * use carry-out to derive [A >= B]
       * decrypt and compare with plaintext arithmetic

The goal of these demos is to give concrete, executable examples of
the concepts discussed in the FHE report:
  - noisy ciphertexts,
  - homomorphic operations,
  - bit-level circuits (full adders, comparators),
  - and noise growth in practice.
"""

from .params import ToyDGHVParams
from .scheme import ToyDGHV
from .boolean import FHEBoolean
from .adder import FHEAdder


def demo_toy_fhe():
    """
    Demo 1: basic ToyDGHV usage (encrypt/decrypt, homomorphic add/mul, noise growth).

    This is the simplest possible demonstration:
      - We generate a secret key p.
      - Encrypt two bits m1 and m2.
      - Decrypt to confirm correctness.
      - Perform homomorphic addition and multiplication on ciphertexts.
      - Observe how noise grows after these operations.

    Conceptual link to report:
      - This corresponds loosely to the "somewhat homomorphic" regime
        discussed in Sections 3–4, where noise grows under operations,
        and correctness depends on staying within a noise budget.
    """
    # Choose parameters with modest p_bits and r_bound so computations
    # are small and decryption remains correct for a few operations.
    params = ToyDGHVParams(
        sec_lambda=32,
        p_bits=32,
        q_bits=64,
        r_bound=8,
        pk_size=32
    )
    scheme = ToyDGHV(params)
    sk, pk = scheme.keygen()

    print("[demo_toy_fhe] Secret key p =", sk)

    # Encrypt two bits m1, m2
    m1, m2 = 1, 1
    c1, r1 = scheme.encrypt_with_sk(sk, m1, return_noise=True)
    c2, r2 = scheme.encrypt_with_sk(sk, m2, return_noise=True)

    print("\nPlaintexts: m1 = {}, m2 = {}".format(m1, m2))
    print("Ciphertext c1 =", c1, "  (initial noise r1 =", r1, ")")
    print("Ciphertext c2 =", c2, "  (initial noise r2 =", r2, ")")

    # Decrypt directly to check we recover the bits correctly.
    print("\nDecrypt c1 ->", scheme.decrypt(sk, c1))
    print("Decrypt c2 ->", scheme.decrypt(sk, c2))

    # Homomorphic addition: this corresponds to XOR on bits.
    c_add = scheme.add(c1, c2)
    m_add = scheme.decrypt(sk, c_add)
    noise_add = scheme.estimate_noise_after_add(r1, r2)
    print("\nHomomorphic addition:")
    print("Expected (m1 + m2) mod 2 =", (m1 + m2) % 2)
    print("Decrypt(c1 + c2)         =", m_add)
    print("Estimated noise after add ~", noise_add)

    # Homomorphic multiplication: this corresponds to AND on bits.
    c_mul = scheme.mul(c1, c2)
    m_mul = scheme.decrypt(sk, c_mul)
    noise_mul = scheme.estimate_noise_after_mul(r1, r2)
    print("\nHomomorphic multiplication:")
    print("Expected (m1 * m2) mod 2 =", (m1 * m2) % 2)
    print("Decrypt(c1 * c2)         =", m_mul)
    print("Estimated noise after mul ~", noise_mul)

    # If desired, you could chain more adds/muls here and watch when
    # decryption starts to fail, illustrating the finite noise budget
    # in a somewhat homomorphic scheme.


def demo_fhe_adder():
    """
    Demo 2: FHE ripple-carry adder on small integers.

    This demo:
      - Uses smaller parameters (16-bit p) for faster experiments.
      - Encrypts two 4-bit integers A and B as lists of encrypted bits.
      - Uses FHEAdder.ripple_add to compute A+B mod 2^4 homomorphically.
      - Decrypts the result to check correctness and prints the carry-out.

    Conceptual link to report:
      - This is a concrete example of a non-trivial circuit (4-bit adder)
        evaluated under encryption.
      - In Gentry/DGHV, decryption and mod-p logic are built from similar
        Boolean/arithmetical subcircuits.
    """
    params = ToyDGHVParams(
        sec_lambda=16,
        p_bits=16,   # smaller secret key for quicker demo
        q_bits=32,
        r_bound=4,
        pk_size=16
    )
    scheme = ToyDGHV(params)
    sk, pk = scheme.keygen()

    print("\n[demo_fhe_adder] Secret key p =", sk)

    # FHEBoolean provides bit-level gates (enc_bit, dec_bit, xor, and_, not_).
    fb = FHEBoolean(scheme, sk)
    # FHEAdder builds full-adders and ripple adders from these gates.
    fadder = FHEAdder(fb)

    # Example inputs for a 4-bit adder:
    A_plain = 5   # binary 0101
    B_plain = 11  # binary 1011
    n_bits = 4

    # Encrypt A and B bitwise as lists of ciphertexts [LSB..MSB]
    A_enc_bits = fadder.enc_int_to_bits(A_plain, n_bits)
    B_enc_bits = fadder.enc_int_to_bits(B_plain, n_bits)

    # Homomorphic addition using a ripple-carry full-adder chain.
    S_enc_bits, carry_enc = fadder.ripple_add(A_enc_bits, B_enc_bits)
    S_plain = fadder.dec_bits_to_int(S_enc_bits)
    carry_plain = fb.dec_bit(carry_enc)

    print("\nPlain A =", A_plain, ", B =", B_plain)
    print("A + B (plain)      =", A_plain + B_plain)
    print("Homomorphic A+B (mod 2^{}) = {}".format(n_bits, S_plain))
    print("Carry out (cipher) ->", carry_plain,
          "(expected 1 if A+B >= 2^{})".format(n_bits))

    # For A=5, B=11:
    #   A+B = 16 = 0 mod 16, carry_out = 1
    # so S_plain should be 0 and carry_plain should be 1.
    # This illustrates that the adder circuit is working under encryption.


def demo_fhe_compare_sub():
    """
    Demo 3: FHE subtraction and comparison on small integers (3-bit).

    This demo:
      - Chooses several 3-bit (A,B) pairs (0 <= A,B < 8).
      - Encodes and encrypts A and B as bit-vectors.
      - Uses FHEAdder.ripple_sub to compute (A - B) mod 2^3.
      - Uses the final carry-out from ripple_sub to derive A >= B.
      - Also uses FHEAdder.geq directly.
      - Decrypts and compares all results with plaintext arithmetic.

    Conceptual link to report:
      - Subtraction and comparison circuits (A-B, A >= B) are the kinds
        of "control-flow" building blocks used in a decryption circuit
        (e.g., implementing c mod p).
      - This illustrates how one could build fragments of a bootstrapping
        circuit, at least for tiny parameters.
    """
    params = ToyDGHVParams(
        sec_lambda=16,
        p_bits=16,
        q_bits=32,
        r_bound=4,
        pk_size=16
    )
    scheme = ToyDGHV(params)
    sk, pk = scheme.keygen()

    print("\n[demo_fhe_compare_sub] Secret key p =", sk)

    fb = FHEBoolean(scheme, sk)
    fadder = FHEAdder(fb)

    # We work with 3-bit integers (0..7) to keep circuits small and noise low.
    n_bits = 3
    tests = [
        (0, 0),
        (0, 1),
        (1, 0),
        (3, 2),
        (2, 3),
        (5, 1),
        (7, 7),
    ]

    for (A_plain, B_plain) in tests:
        assert 0 <= A_plain < (1 << n_bits)
        assert 0 <= B_plain < (1 << n_bits)

        # Encrypt A and B bitwise
        A_enc_bits = fadder.enc_int_to_bits(A_plain, n_bits)
        B_enc_bits = fadder.enc_int_to_bits(B_plain, n_bits)

        # A - B mod 2^n with ripple_sub (two's complement)
        S_enc_bits, carry_enc = fadder.ripple_sub(A_enc_bits, B_enc_bits)
        S_plain = fadder.dec_bits_to_int(S_enc_bits)
        carry_plain = fb.dec_bit(carry_enc)

        expected_sub = (A_plain - B_plain) % (1 << n_bits)
        expected_geq = int(A_plain >= B_plain)

        # A >= B comparator via geq()
        geq_enc = fadder.geq(A_enc_bits, B_enc_bits)
        geq_plain = fb.dec_bit(geq_enc)

        print("\nA = {}, B = {} ({}-bit)".format(A_plain, B_plain, n_bits))
        print("A - B mod 2^{}  : expected {}, got {}".format(
            n_bits, expected_sub, S_plain))
        print("carry_out (A-B) :", carry_plain,
              "(expected 1 if A >= B else 0)")
        print("A >= B          : expected {}, got {}".format(
            expected_geq, geq_plain))

        # Note: For tiny parameters, if you extend this to larger circuits
        # or chain operations repeatedly, noise may eventually exceed the
        # decryptable range and some results will be wrong. This is the
        # "somewhat" aspect of the scheme.


if __name__ == "__main__":
    # When run as a script (python3 -m toy_fhe.demo),
    # execute all three demos in sequence so you can see:
    #  - basic FHE operations and noise,
    #  - a homomorphic adder circuit,
    #  - a homomorphic subtract/compare circuit.
    print("\n------------ Running Demo 1 ------------")
    demo_toy_fhe() ## To perform Demo 1 
    print("\n------------ Running Demo 2 ------------")
    demo_fhe_adder() ## To perform Demo 2 
    print("\n------------ Running Demo 3 ------------")
    demo_fhe_compare_sub() ## To perform Demo 3
    print("\n------------Completed Demo ------------")
