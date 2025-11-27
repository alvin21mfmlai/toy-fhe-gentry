# toy_fhe/demo.py

from .params import ToyDGHVParams
from .scheme import ToyDGHV
from .boolean import FHEBoolean
from .adder import FHEAdder


def demo_toy_fhe():
    """
    Demo 1: basic ToyDGHV usage (encrypt/decrypt, homomorphic add/mul, noise growth).
    """
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

    # Encrypt two bits
    m1, m2 = 1, 1
    c1, r1 = scheme.encrypt_with_sk(sk, m1, return_noise=True)
    c2, r2 = scheme.encrypt_with_sk(sk, m2, return_noise=True)

    print("\nPlaintexts: m1 = {}, m2 = {}".format(m1, m2))
    print("Ciphertext c1 =", c1, "  (initial noise r1 =", r1, ")")
    print("Ciphertext c2 =", c2, "  (initial noise r2 =", r2, ")")

    # Decrypt directly
    print("\nDecrypt c1 ->", scheme.decrypt(sk, c1))
    print("Decrypt c2 ->", scheme.decrypt(sk, c2))

    # Homomorphic addition (XOR over bits)
    c_add = scheme.add(c1, c2)
    m_add = scheme.decrypt(sk, c_add)
    noise_add = scheme.estimate_noise_after_add(r1, r2)
    print("\nHomomorphic addition:")
    print("Expected (m1 + m2) mod 2 =", (m1 + m2) % 2)
    print("Decrypt(c1 + c2) =", m_add)
    print("Estimated noise after add ~", noise_add)

    # Homomorphic multiplication (AND over bits)
    c_mul = scheme.mul(c1, c2)
    m_mul = scheme.decrypt(sk, c_mul)
    noise_mul = scheme.estimate_noise_after_mul(r1, r2)
    print("\nHomomorphic multiplication:")
    print("Expected (m1 * m2) mod 2 =", (m1 * m2) % 2)
    print("Decrypt(c1 * c2) =", m_mul)
    print("Estimated noise after mul ~", noise_mul)


def demo_fhe_adder():
    """
    Demo 2: FHE ripple-carry adder on small integers.
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

    print("\n[demo_fhe_adder] Secret key p =", sk)

    fb = FHEBoolean(scheme, sk)
    fadder = FHEAdder(fb)

    A_plain = 5   # 0101
    B_plain = 11  # 1011
    n_bits = 4

    # Encrypt bitwise
    A_enc_bits = fadder.enc_int_to_bits(A_plain, n_bits)
    B_enc_bits = fadder.enc_int_to_bits(B_plain, n_bits)

    # Homomorphic addition
    S_enc_bits, carry_enc = fadder.ripple_add(A_enc_bits, B_enc_bits)
    S_plain = fadder.dec_bits_to_int(S_enc_bits)
    carry_plain = fb.dec_bit(carry_enc)

    print("\nPlain A =", A_plain, ", B =", B_plain)
    print("A + B =", A_plain + B_plain)
    print("Homomorphic A+B (mod 2^{}) = {}".format(n_bits, S_plain))
    print("Carry out =", carry_plain)


def demo_fhe_compare_sub():
    """
    Demo 3: FHE subtraction and comparison on small integers (3-bit).

    Tests:
      - A - B mod 2^n via ripple_sub.
      - Comparison A >= B via the carry-out bit of A-B.
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

        A_enc_bits = fadder.enc_int_to_bits(A_plain, n_bits)
        B_enc_bits = fadder.enc_int_to_bits(B_plain, n_bits)

        # A - B mod 2^n
        S_enc_bits, carry_enc = fadder.ripple_sub(A_enc_bits, B_enc_bits)
        S_plain = fadder.dec_bits_to_int(S_enc_bits)
        carry_plain = fb.dec_bit(carry_enc)

        expected_sub = (A_plain - B_plain) % (1 << n_bits)
        expected_geq = int(A_plain >= B_plain)

        # A >= B?
        geq_enc = fadder.geq(A_enc_bits, B_enc_bits)
        geq_plain = fb.dec_bit(geq_enc)

        print("\nA = {}, B = {} ({}-bit)".format(A_plain, B_plain, n_bits))
        print("A - B mod 2^{}  : expected {}, got {}".format(n_bits, expected_sub, S_plain))
        print("carry_out (A-B) :", carry_plain, "(expected 1 if A>=B else 0)")
        print("A >= B          : expected {}, got {}".format(expected_geq, geq_plain))


if __name__ == "__main__":
    demo_toy_fhe()
    demo_fhe_adder()
    demo_fhe_compare_sub()
