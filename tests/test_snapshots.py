import pytest

from agent_memory_guard.storage.snapshots import SnapshotStore


def test_capture_and_retrieve():
    s = SnapshotStore()
    snap = s.capture({"a": 1}, label="t1")
    assert s.get(snap.snapshot_id) is snap
    assert s.latest().snapshot_id == snap.snapshot_id


def test_ring_buffer_evicts_oldest():
    s = SnapshotStore(max_snapshots=2)
    a = s.capture({"a": 1})
    b = s.capture({"b": 2})
    c = s.capture({"c": 3})
    assert s.get(a.snapshot_id) is None
    assert s.get(b.snapshot_id) is b
    assert s.get(c.snapshot_id) is c


def test_restore_data_is_isolated_copy():
    s = SnapshotStore()
    snap = s.capture({"k": [1, 2, 3]})
    restored = s.restore_data(snap.snapshot_id)
    restored["k"].append(99)
    assert snap.data["k"] == [1, 2, 3]


def test_restore_unknown_raises():
    with pytest.raises(KeyError):
        SnapshotStore().restore_data("nope")
