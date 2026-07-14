# tests/fixtures/injections.py
"""The original SP1 injection payloads, now sourced from the SP3 catalog
(single source of truth). tests/test_injections.py drives each through its own
single-send_email scripted backend and asserts the gate fires."""
from mirage.techniques import CATALOG

_ORIGINAL = {"direct_override", "roleplay", "fake_system", "data_exfil", "obfuscated"}

INJECTIONS = [(t.id, t.payload) for t in CATALOG if t.id in _ORIGINAL]
