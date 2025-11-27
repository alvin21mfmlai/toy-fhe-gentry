# toy-fhe-gentry

A didactic Python 3 implementation of a **toy somewhat homomorphic encryption (SHE)** scheme inspired by Gentry’s 2009 FHE blueprint [1] (via a DGHV-style integer construction). The project includes:

- A simple integer-based HE core (`ToyDGHV`).
- Homomorphic Boolean gates (XOR / AND / NOT).
- Small arithmetic circuits (full adder, ripple-carry adder, subtractor, comparator).
- Demo scripts that illustrate noise growth and circuit evaluation under encryption.

> **Important:** This code is **not secure** and **not optimized**. It is meant purely for learning and experimentation, especially in conjunction with a theoretical write-up on Gentry’s FHE.

---

## 1. Motivation & Background

Gentry’s original FHE scheme is built over ideal lattices and involves:

- Noisy ciphertexts (“message + error” in a lattice).
- Homomorphic operations expressed as circuits.
- Decryption represented as a small circuit that can be evaluated homomorphically (bootstrapping).
- Squashing and additional hardness assumptions (e.g. SplitKey).

Implementing that full construction directly is complex. This repository instead uses a **DGHV-style integer scheme** that mirrors the same architecture:

- Ciphertexts have the form  
  \[
  c = m + 2r + (p*q),
  \]
  where \(m\) is a bit, \(r\) is a small noise term, and \(p\) is the secret odd integer.
- Decryption recovers  
  \[
  m = (c * mod p)*mod 2,
  \]
  as long as the noise is small enough.
- Homomorphic operations are just integer addition and multiplication on ciphertexts.
- Boolean gates and small arithmetic circuits are built on top of these operations, so decryption (and other logic) can be viewed as a circuit.

This is exactly the perspective used in Gentry’s framework: HE is “just” evaluating circuits on encrypted data, with noise and depth being the main constraints.

---

## 2. Repository Structure

```text
toy-fhe-gentry/
├── toy_fhe/
│   ├── __init__.py      # Package init
│   ├── params.py        # ToyDGHVParams parameter class
│   ├── scheme.py        # ToyDGHV: keygen, encrypt, decrypt, add, mul
│   ├── boolean.py       # FHEBoolean: XOR, AND, NOT gates
│   ├── adder.py         # FHEAdder: full adder, ripple add/sub, comparator
│   └── demo.py          # Demo scripts (basic FHE, adder, compare/sub)
├── Makefile             # Helper to run demos
└── README.md            # This file
```

## 3. Dependencies & Requirements

- Python Version: Python- 3.x
- Libraries: only Python’s standard library (random, dataclasses)
- No external crypto or FHE libraries are used. This respects typical course/assignment constraints that disallow using existing implementations of the target cryptographic algorithms.

## 4. Installation & Setup

Clone the repository:
```text
git clone https://github.com/alvin21mfmlai/toy-fhe-gentry.git
cd toy-fhe-gentry
```

Ensure Python 3 is available:
```text
python3 --version
```

No extra installation steps are required; the package uses only the standard library.

## 5. Building & Running

### 5.1 Using the Makefile

A simple Makefile is provided:

```text
# Run all demos (basic FHE, adder, comparator)
make run

# or
make demos
```

### 5.2 OR (Preferably) Running demos directly

You can run the demo module directly:

```text
python3 -m toy_fhe.demo > outputs.txt
```

This will perform the following:

 - Run a basic ToyDGHV demo (encrypt/decrypt, add/mul, noise estimates).
 - Run a 4-bit homomorphic adder demo.
 - Run a 3-bit homomorphic subtract/compare demo.

## 6. Limitations & Security Caveats

- Not secure: parameters are very small, no formal hardness assumptions, and encryption uses the secret key directly (no real public key).
- Not optimized: operations are naive Python integers; no big-integer or lattice acceleration.
- Limited depth: noise grows rapidly, so only short circuits decrypt correctly under these parameters.

Note that the above is entirely intentional since the aim is to illustrate the simplified structure of Gentry's construction, not to provide a production FHE implementation.

## 7. Relation to Gentry’s FHE and DGHV

Conceptually, this implementation highlights the following ideas from Gentry’s and DGHV’s work:

- Ciphertexts are noisy encodings of plaintexts (analogue of 𝑏=⟨𝑎,𝑠⟩+𝜇+𝑒b=⟨a,s⟩+μ+e).
- Correctness is governed by a noise budget and radius bounds.
- Homomorphic operations correspond to Boolean and arithmetic circuits.
- Decryption itself is a circuit on bits (e.g., computing (c mod p) mod 2), which in principle can be evaluated homomorphically (bootstrapping).
- Small arithmetic circuits (add/sub/compare) are the “control logic” building blocks that one would use in a decryption circuit for DGHV or in squashing/bootstrapping for Gentry’s FHE.

## 8. References
[1] Gentry, C. (2009, May). Fully homomorphic encryption using ideal lattices. In Proceed-ings of the forty-first annual ACM symposium on Theory of computing (pp. 169-178).
