"""
Tests for Dexter AI Pentest core components.
Run with:  python -m pytest tests/ -v
"""
import pytest
import sys
from pathlib import Path

# Make sure the package root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))