# toy_fhe/__init__.py

"""
toy_fhe: a didactic toy FHE library inspired by the DGHV and Gentry blueprints.

This package provides:
- A simple DGHV-style somewhat homomorphic encryption scheme over the integers.
- Boolean FHE gates on top of that scheme (XOR, AND, NOT).
- Composite circuits (full adder, ripple-carry adder, subtractor, comparator).

It is NOT secure and NOT optimized; it is purely for educational use.
"""

from .params import ToyDGHVParams
from .scheme import ToyDGHV
from .boolean import FHEBoolean
from .adder import FHEAdder
