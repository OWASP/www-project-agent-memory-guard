"""A detector that raises must not fail open silently.

`MemoryGuard._run_detectors` swallows detector exceptions on purpose so a broken
detector can't stop the agent. Without an event, that fail-open is invisible:
guard.events looks clean even though the detector never ran. These tests pin that
a swallowed exception produces a low-severity operational event carrying the
detector name and the exception type.
"""

from agent_memory_guard import MemoryGuard, Policy
from agent_memory_guard.events import Action, Severity


class _Boom:
    name = "boom"

    def inspect(self, key, value, *, operation):
        raise RuntimeError("kaboom")


def _guard_with_boom():
    guard = MemoryGuard(policy=Policy.strict())
    guard._detectors.append(_Boom())
    return guard


def test_raising_detector_emits_a_visible_event():
    guard = _guard_with_boom()
    guard.write("notes.summary", "hello", source_class="user_input")

    errors = [e for e in guard.events if e.metadata.get("detector_error")]
    assert len(errors) == 1
    event = errors[0]
    assert event.detector == "boom"
    assert event.severity == Severity.LOW
    assert event.metadata["error_type"] == "RuntimeError"


def test_raising_detector_still_does_not_break_the_write():
    guard = _guard_with_boom()
    # The write goes through; the broken detector must not raise out of write().
    guard.write("notes.summary", "hello", source_class="user_input")
    assert guard.read("notes.summary") == "hello"


def test_the_error_event_reports_the_operation():
    guard = _guard_with_boom()
    guard.write("notes.summary", "hello", source_class="user_input")
    error = next(e for e in guard.events if e.metadata.get("detector_error"))
    assert error.operation == "write"
    assert error.action == Action.ALLOW


def test_no_error_event_when_detectors_behave():
    guard = MemoryGuard(policy=Policy.strict())
    guard.write("notes.summary", "hello", source_class="user_input")
    assert not any(e.metadata.get("detector_error") for e in guard.events)
