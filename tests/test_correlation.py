from sentinel.correlation import Correlator
import pytest
import sqlite3


def test_fleet_boost_requires_min_agents():
    c = Correlator(rising_threshold=0.5, min_agents=3)
    assert c.record("a1", 0.7).boost == 0
    assert c.record("a2", 0.7).boost == 0
    sig = c.record("a3", 0.7)
    assert sig.boost >= 1 and sig.agents_rising == 3


def test_fleet_wide_gives_two_rungs():
    c = Correlator(rising_threshold=0.5, min_agents=3)
    for i in range(6):
        sig = c.record(f"a{i}", 0.8)
    assert sig.boost == 2


def test_sqlite_shared_state(tmp_path):
    p = str(tmp_path / "fleet.db")
    c1, c2 = Correlator(min_agents=2, path=p), Correlator(min_agents=2, path=p)
    c1.record("a1", 0.9)
    assert c2.record("a2", 0.9).boost >= 1


@pytest.mark.parametrize("persistent", [False, True])
def test_valid_high_signal_survives_more_than_64_clean_events(tmp_path, persistent):
    c = Correlator(path=str(tmp_path / "fleet.db") if persistent else None)
    c.record("a", 0.9, ts=1000)
    for i in range(1, 70):
        signal = c.record("a", 0.0, ts=1000 + i)
    assert signal.agents_rising == 1


@pytest.mark.parametrize("persistent", [False, True])
def test_future_events_are_not_counted_in_an_earlier_window(tmp_path, persistent):
    c = Correlator(path=str(tmp_path / "fleet.db") if persistent else None)
    c.record("future", 0.9, ts=5000)
    c.record("a", 0.9, ts=1000)
    signal = c.record("b", 0.9, ts=1001)
    assert signal.agents_rising == 2
    assert signal.boost == 0


@pytest.mark.parametrize("persistent", [False, True])
@pytest.mark.parametrize("elapsed,expected", [(899, 1), (900, 1), (901, 0)])
def test_window_includes_exact_lower_boundary_and_timestamp_zero(tmp_path, persistent, elapsed, expected):
    c = Correlator(path=str(tmp_path / "fleet.db") if persistent else None)
    c.record("a", 0.9, ts=0)
    assert c.record("b", 0.0, ts=elapsed).agents_rising == expected


@pytest.mark.parametrize("persistent", [False, True])
def test_out_of_order_event_cannot_prune_another_events_window(tmp_path, persistent):
    c = Correlator(path=str(tmp_path / "fleet.db") if persistent else None)
    c.record("a", 0.9, ts=1000)
    c.record("b", 0.9, ts=1001)
    c.record("out-of-order", 0.0, ts=1000000)
    signal = c.record("c", 0.9, ts=1002)
    assert signal.agents_rising == 3
    assert signal.boost >= 1


@pytest.mark.parametrize("persistent", [False, True])
def test_future_event_rejected_before_mutating_evidence(tmp_path, persistent):
    c = Correlator(path=str(tmp_path / "fleet.db") if persistent else None, clock=lambda: 1002)
    c.record("a", 0.9, ts=1000)
    c.record("b", 0.9, ts=1001)
    with pytest.raises(ValueError, match="future"):
        c.record("future", 0.0, ts=1000000)
    assert c.record("c", 0.9, ts=1002).agents_rising == 3


@pytest.mark.parametrize("persistent", [False, True])
def test_retention_uses_trusted_ingestion_clock_not_event_time(tmp_path, persistent):
    now = [1000.0]
    c = Correlator(path=str(tmp_path / "fleet.db") if persistent else None, clock=lambda: now[0])
    c.record("a", 0.9, ts=1000)
    now[0] += 3600
    assert c.record("b", 0.0, ts=1001).agents_rising == 1
    now[0] += 1
    assert c.record("c", 0.0, ts=1002).agents_rising == 0


def test_existing_sqlite_evidence_survives_ingestion_timestamp_migration(tmp_path):
    path = str(tmp_path / "fleet.db")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE coord (agent TEXT, ts REAL, score REAL)")
        db.execute("INSERT INTO coord VALUES ('a', 1000, 0.9)")
    c = Correlator(path=path, clock=lambda: 10000)
    assert c.record("b", 0.9, ts=1001).agents_rising == 2
    other = Correlator(path=path, clock=lambda: 10000)
    assert other.record("c", 0.9, ts=1002).agents_rising == 3
