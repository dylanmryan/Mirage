# tests/test_harness.py
import pytest

from mirage.techniques import CATALOG
from mirage.harness import DeterministicRunner
from mirage.phases import Phase


@pytest.mark.parametrize("t", CATALOG, ids=[t.id for t in CATALOG])
def test_deterministic_mirage_contains_and_traps(t):
    traj = DeterministicRunner("mirage").run(t)
    assert traj.contained is True
    assert traj.trapped is True
    assert traj.kill_chain == t.expected_kill_chain
    # tokens issued iff the technique reads secrets (that shadow executor mints)
    if any(s.tool == "read_secrets" for s in t.steps):
        assert traj.tokens_issued
    else:
        assert traj.tokens_issued == []


@pytest.mark.parametrize("t", CATALOG, ids=[t.id for t in CATALOG])
def test_deterministic_deny_blocks(t):
    traj = DeterministicRunner("deny").run(t)
    assert traj.contained is True
    assert traj.trapped is False
    assert traj.tokens_issued == []
    expected = [Phase.BLOCKED if p == Phase.TRAPPED else p for p in t.expected_kill_chain]
    assert traj.kill_chain == expected
