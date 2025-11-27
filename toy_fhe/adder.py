# toy_fhe/adder.py

from .boolean import FHEBoolean

class FHEAdder:
    """
    FHE full adder, ripple-carry adder, subtractor, and comparator.

    These circuits are built entirely from the FHEBoolean gates
    (XOR, AND, NOT) and thus operate on ciphertexts.

    Conceptually:
      - full_adder  = 1-bit addition under encryption.
      - ripple_add  = n-bit addition under encryption.
      - ripple_sub  = n-bit subtraction via two's complement.
      - geq / lt    = comparators (control-flow primitives).

    In a bootstrapping setting, such circuits would be used to implement
    small fragments of the decryption algorithm (e.g., computing c mod p).
    """

    def __init__(self, fhe_bool: FHEBoolean):
        self.fb = fhe_bool

    # ---------- Core: 1-bit full adder ----------

    def full_adder(self, a: int, b: int, carry_in: int):
        """
        1-bit full adder under FHE.

        Inputs
        ------
        a, b, carry_in : int
            Ciphertexts encrypting bits a, b, carry_in.

        Returns
        -------
        (sum_bit, carry_out) : (int, int)
            Ciphertexts encrypting:
              sum_bit  = a XOR b XOR carry_in
              carry_out = majority(a, b, carry_in)

        Boolean logic
        -------------
        sum = a XOR b XOR carry_in
        carry_out = (a AND b) OR (carry_in AND (a XOR b))

        OR is implemented via XOR and AND:
            x OR y = x XOR y XOR (x AND y)
        """
        # sum = a XOR b XOR carry_in
        t = self.fb.xor(a, b)
        sum_bit = self.fb.xor(t, carry_in)

        # carry_out = (a & b) OR (carry_in & (a XOR b))
        a_and_b = self.fb.and_(a, b)
        cin_and_t = self.fb.and_(carry_in, t)
        # OR(x,y) = x XOR y XOR (x AND y)
        x = a_and_b
        y = cin_and_t
        x_and_y = self.fb.and_(x, y)
        carry_out = self.fb.xor(self.fb.xor(x, y), x_and_y)

        return sum_bit, carry_out

    # ---------- Ripple-carry addition ----------

    def ripple_add(self, A_bits, B_bits):
        """
        Ripple-carry addition: compute A + B mod 2^n.

        Parameters
        ----------
        A_bits, B_bits : list[int]
            Ciphertexts encrypting bits [LSB .. MSB] of A and B.

        Returns
        -------
        (S_bits, carry_out) : (list[int], int)
            S_bits : ciphertext bits of (A+B) mod 2^n
            carry_out : ciphertext bit of the final carry.

        Algorithm
        ---------
        - Initialise carry = 0.
        - For i in [0..n-1]:
            (S[i], carry) = FullAdder(A[i], B[i], carry)
        - Output S_bits and final carry.
        """
        n = len(A_bits)
        assert len(B_bits) == n

        carry = self.fb.enc_bit(0)
        S_bits = []
        for i in range(n):
            s, carry = self.full_adder(A_bits[i], B_bits[i], carry)
            S_bits.append(s)
        return S_bits, carry

    # ---------- Encoding/decoding integers to/from bit vectors ----------

    def enc_int_to_bits(self, x: int, n_bits: int):
        """
        Encrypt an integer x as a list of ciphertext bits [LSB..MSB].

        Parameters
        ----------
        x : int
            Plain integer, 0 <= x < 2^n_bits.
        n_bits : int
            Number of bits used for the representation.

        Returns
        -------
        list[int]
            Ciphertexts encrypting bits of x.

        Implementation
        --------------
        - Compute the bit representation of x.
        - Encrypt each bit with FHEBoolean.enc_bit.
        """
        assert 0 <= x < (1 << n_bits)
        bits = [(x >> i) & 1 for i in range(n_bits)]
        return [self.fb.enc_bit(b) for b in bits]

    def dec_bits_to_int(self, C_bits):
        """
        Decrypt a list of ciphertext bits [LSB..MSB] to an integer.

        This is the inverse of enc_int_to_bits; useful for sanity checks.
        """
        val = 0
        for i, c in enumerate(C_bits):
            bit = self.fb.dec_bit(c)
            val |= (bit << i)
        return val

    # ---------- Ripple-carry subtraction & comparator ----------

    def ripple_sub(self, A_bits, B_bits):
        """
        Ripple-carry subtraction: compute A - B (mod 2^n) via two's complement.

        A_bits, B_bits : lists of ciphertext bits [LSB..MSB].

        Returns
        -------
        (S_bits, carry_out) : (list[int], int)
            S_bits : ciphertext bits of (A - B) mod 2^n
            carry_out : ciphertext bit indicating "no borrow":
                carry_out = 1  <=> A >= B
                carry_out = 0  <=> A <  B

        Algorithm
        ---------
        - Compute ~B (bitwise NOT) homomorphically.
        - Add (~B + 1) to A with ripple_add (two's complement).
        - The result is A - B modulo 2^n.
        - The final carry_out acts as the inverse of the borrow flag.
        """
        n = len(A_bits)
        assert len(B_bits) == n

        # bitwise NOT of B
        B_not_bits = [self.fb.not_(b) for b in B_bits]

        # two's complement: ~B + 1
        carry = self.fb.enc_bit(1)
        S_bits = []
        for i in range(n):
            s, carry = self.full_adder(A_bits[i], B_not_bits[i], carry)
            S_bits.append(s)

        return S_bits, carry

    def geq(self, A_bits, B_bits):
        """
        Homomorphic comparator: return ciphertext bit of [A >= B].

        Implementation:
          - Compute A - B via ripple_sub.
          - Interpret the final carry_out as "no borrow".
          - carry_out = 1  <=> A >= B
          - carry_out = 0  <=> A <  B
        """
        _, carry = self.ripple_sub(A_bits, B_bits)
        return carry

    def lt(self, A_bits, B_bits):
        """
        Homomorphic comparator: return ciphertext bit of [A < B].

        Implemented as NOT(geq(A,B)).
        """
        geq_bit = self.geq(A_bits, B_bits)
        return self.fb.not_(geq_bit)
