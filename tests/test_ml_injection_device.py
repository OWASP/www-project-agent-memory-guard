"""Tests for device selection in MLInjectionDetector.

``transformers`` and ``torch`` are replaced by small fakes, so these tests need
neither package, nor a GPU, and never download a model.
"""
from __future__ import annotations

import logging
import sys
import types

import pytest

from agent_memory_guard.detectors.ml_injection import FALLBACK_MODEL, MLInjectionDetector

TEXT = "Some memory text that is long enough to be inspected."


def install_fake_torch(monkeypatch, *, cuda=False, mps=False, has_mps_backend=True):
    torch = types.ModuleType("torch")
    torch.cuda = types.SimpleNamespace(is_available=lambda: cuda)
    torch.backends = types.SimpleNamespace()
    if has_mps_backend:
        torch.backends.mps = types.SimpleNamespace(is_available=lambda: mps)
    monkeypatch.setitem(sys.modules, "torch", torch)


def install_fake_transformers(monkeypatch, *, fail_models=()):
    """Fake ``pipeline`` that records (model, device) and can fail for some models."""
    calls = []

    def pipeline(task, model, **kwargs):
        calls.append((model, kwargs.get("device")))
        if model in fail_models:
            raise OSError(f"cannot load {model}")
        return lambda text: [{"label": "SAFE", "score": 0.99}]

    transformers = types.ModuleType("transformers")
    transformers.pipeline = pipeline
    monkeypatch.setitem(sys.modules, "transformers", transformers)
    return calls


@pytest.mark.parametrize(
    "cuda, mps, expected",
    [
        (True, True, "cuda"),  # CUDA wins over MPS
        (True, False, "cuda"),
        (False, True, "mps"),
        (False, False, -1),  # -1 is CPU for transformers.pipeline
    ],
)
def test_auto_picks_best_available_device(monkeypatch, cuda, mps, expected):
    install_fake_torch(monkeypatch, cuda=cuda, mps=mps)
    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(device="auto", lazy_load=False)

    assert [device for _, device in calls] == [expected]


def test_auto_without_mps_backend_falls_back_to_cpu(monkeypatch):
    # Older torch versions have no ``torch.backends.mps``.
    install_fake_torch(monkeypatch, has_mps_backend=False)
    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(device="auto", lazy_load=False)

    assert [device for _, device in calls] == [-1]


def test_auto_without_torch_falls_back_to_cpu(monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", None)  # makes ``import torch`` fail
    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(device="auto", lazy_load=False)

    assert [device for _, device in calls] == [-1]


def test_auto_when_torch_import_raises_oserror_falls_back_to_cpu(monkeypatch):
    original_import = __import__

    def raise_oserror(name, *args, **kwargs):
        if name == "torch":
            raise OSError("broken torch installation")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", raise_oserror)
    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(device="auto", lazy_load=False)

    assert [device for _, device in calls] == [-1]


def test_auto_when_cuda_check_raises_falls_back_to_cpu(monkeypatch):
    torch = types.ModuleType("torch")

    def raise_oserror():
        raise OSError("CUDA initialization failed")

    torch.cuda = types.SimpleNamespace(is_available=raise_oserror)
    torch.backends = types.SimpleNamespace(
        mps=types.SimpleNamespace(is_available=lambda: True)
    )
    monkeypatch.setitem(sys.modules, "torch", torch)

    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(device="auto", lazy_load=False)

    assert [device for _, device in calls] == [-1]


@pytest.mark.parametrize("device", ["cpu", "cuda", "mps"])
def test_explicit_device_is_passed_through_unchanged(monkeypatch, device):
    # Even if torch says CUDA is available, an explicit choice is respected.
    install_fake_torch(monkeypatch, cuda=True, mps=True)
    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(device=device, lazy_load=False)

    assert [d for _, d in calls] == [device]


def test_default_device_is_still_cpu(monkeypatch):
    install_fake_torch(monkeypatch, cuda=True)
    calls = install_fake_transformers(monkeypatch)

    MLInjectionDetector(lazy_load=False)

    assert [d for _, d in calls] == ["cpu"]


def test_fallback_model_uses_the_same_resolved_device(monkeypatch):
    install_fake_torch(monkeypatch, cuda=True)
    primary = MLInjectionDetector().__dict__["_model_name"]
    calls = install_fake_transformers(monkeypatch, fail_models=(primary,))

    detector = MLInjectionDetector(device="auto", lazy_load=False)

    assert calls == [(primary, "cuda"), (FALLBACK_MODEL, "cuda")]
    assert detector.is_available


def test_auto_is_resolved_when_the_model_is_loaded_not_at_init(monkeypatch):
    install_fake_torch(monkeypatch, mps=True)
    calls = install_fake_transformers(monkeypatch)

    detector = MLInjectionDetector(device="auto")  # lazy_load=True by default
    assert calls == []

    detector.inspect("key", TEXT, operation="write")
    assert [device for _, device in calls] == ["mps"]


@pytest.mark.parametrize(
    "cuda, mps, label",
    [(True, False, "cuda"), (False, True, "mps"), (False, False, "cpu")],
)
def test_resolved_device_is_logged_at_info_level(monkeypatch, caplog, cuda, mps, label):
    install_fake_torch(monkeypatch, cuda=cuda, mps=mps)
    install_fake_transformers(monkeypatch)

    with caplog.at_level(logging.INFO, logger="agent_memory_guard.ml"):
        MLInjectionDetector(device="auto", lazy_load=False)

    assert any(
        record.levelno == logging.INFO and f"on {label}" in record.getMessage()
        for record in caplog.records
    )


def test_missing_transformers_still_disables_the_detector(monkeypatch):
    install_fake_torch(monkeypatch, cuda=True)
    monkeypatch.setitem(sys.modules, "transformers", None)

    detector = MLInjectionDetector(device="auto", lazy_load=False)

    assert not detector.is_available
    assert not detector.inspect("key", TEXT, operation="write").matched
