from mirage.types import Message, Provenance
from mirage.provenance import ProvenanceResolver


def resolve(messages):
    return ProvenanceResolver().resolve(messages)


def test_role_heuristic_defaults():
    pmap = resolve([
        Message(role="system", content="s"),
        Message(role="user", content="u"),
        Message(role="assistant", content="a"),
        Message(role="tool", content="t"),
    ])
    assert pmap.entries == [
        Provenance.TRUSTED, Provenance.TRUSTED,
        Provenance.TRUSTED, Provenance.UNTRUSTED,
    ]


def test_explicit_marker_is_authoritative():
    pmap = resolve([Message(role="user", content="web page", provenance=Provenance.UNTRUSTED)])
    assert pmap.entries == [Provenance.UNTRUSTED]


def test_marker_never_upgraded_by_heuristic():
    pmap = resolve([Message(role="function", content="x")])  # unknown role
    assert pmap.entries == [Provenance.UNTRUSTED]


def test_tainted_and_first_untrusted():
    pmap = resolve([
        Message(role="user", content="u"),
        Message(role="tool", content="t"),
    ])
    assert pmap.tainted is True
    assert pmap.first_untrusted() == 1

    clean = resolve([Message(role="user", content="u")])
    assert clean.tainted is False
    assert clean.first_untrusted() is None
