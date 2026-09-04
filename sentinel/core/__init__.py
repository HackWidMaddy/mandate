"""Sentinel core: the deterministic authority engine.

PURITY CONTRACT (enforced by tests/test_core_purity.py):
  * standard library only, from a fixed allowlist
  * no file I/O, no network, no subprocess, no environment access
  * no imports from the rest of the sentinel package

Anything in this package must be mechanically portable to another language.
The JSON conformance vectors in vectors/ are the cross-language contract.
"""
