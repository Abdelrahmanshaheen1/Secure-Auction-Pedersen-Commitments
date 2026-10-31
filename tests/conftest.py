import os
import sys

# Make the project modules (ec.py, commitments.py, ...) importable from the tests.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
