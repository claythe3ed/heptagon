"""
Run a demo of the incident_response symbolic model.
Usage:  python examples/run_demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.core.symbolic import demo

if __name__ == "__main__":
    demo(seed=7, verbose=True)
