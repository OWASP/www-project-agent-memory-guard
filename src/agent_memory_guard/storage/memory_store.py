from __future__ import annotations

from typing import Any, Iterator, Protocol


class MemoryStore(Protocol):
    """Minimal key/value contract a guarded backend must satisfy."""

    def get(self, key: str, default: Any = None) -> Any: ...
    def set(self, key: str, value: Any) -> None: ...
    def delete(self, key: str) -> None: ...
    def keys(self) -> Iterator[str]: ...
    def items(self) -> Iterator[tuple[str, Any]]: ...
    def __contains__(self, key: str) -> bool: ...


class InMemoryStore:
    """Reference dict-backed implementation used by tests and examples."""

    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = dict(initial or {})

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def keys(self) -> Iterator[str]:
        return iter(list(self._data.keys()))

    def items(self) -> Iterator[tuple[str, Any]]:
        return iter(list(self._data.items()))

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def snapshot(self) -> dict[str, Any]:
        import copy

        return copy.deepcopy(self._data)

    def restore(self, data: dict[str, Any]) -> None:
        import copy

        self._data = copy.deepcopy(data)
