# tests/test_techniques.py
from mirage.techniques import CATALOG, Technique, AttackStep
from mirage.phases import Phase


def test_catalog_has_15_plus_unique():
    assert len(CATALOG) >= 15
    ids = [t.id for t in CATALOG]
    assert len(ids) == len(set(ids))


def test_every_technique_wellformed():
    for t in CATALOG:
        assert isinstance(t, Technique)
        assert t.payload and t.name and t.family
        assert t.steps and t.expected_kill_chain
        for s in t.steps:
            assert isinstance(s, AttackStep)
            assert isinstance(s.expected_phase, Phase)


def test_migrated_five_present():
    ids = {t.id for t in CATALOG}
    assert {"direct_override", "roleplay", "fake_system", "data_exfil", "obfuscated"} <= ids
