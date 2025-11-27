# Makefile for toy-fhe-gentry

PYTHON := python3

.PHONY: all run demos lint clean

# Default target: run all demos
all: run

# Alias for running all demos
run: demos

# Run the Python demo module (basic FHE, adder, comparator)
demos:
	$(PYTHON) -m toy_fhe.demo

# Placeholder for optional linting (flake8, pylint, etc.)
lint:
	@echo "No linter configured. Install flake8/pylint and add commands here."

# Nothing to clean for pure Python source, but keep the target for completeness
clean:
	@echo "Nothing to clean for pure Python source."
