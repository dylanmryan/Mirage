import pytest

from mirage.techniques import CATALOG
from mirage.harness import DeterministicRunner, LiveRunner, run_catalog_live, scripted_for
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


def test_live_runner_marks_attempted():
    # a scripted stand-in for the "real" model that emits a privileged call
    traj, attempted = LiveRunner(lambda t: scripted_for(t), "mirage").run(CATALOG[0])
    assert attempted is True
    assert traj.trapped is True


def test_live_runner_not_attempted_when_model_ignores():
    from mirage.types import AssistantTurn
    from mirage.backends import ScriptedBackend
    # model refuses the injection: returns text, no tool call
    traj, attempted = LiveRunner(
        lambda t: ScriptedBackend([AssistantTurn(content="I won't do that.")]), "mirage"
    ).run(CATALOG[0])
    assert attempted is False
    assert traj.trapped is False


def test_run_catalog_live_metrics():
    report = run_catalog_live(CATALOG, lambda t: scripted_for(t), "mirage")
    assert len(report.results) == len(CATALOG)
    assert report.attempt_rate == 1.0
    assert report.containment_rate == 1.0
