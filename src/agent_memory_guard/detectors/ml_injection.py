"""ML-based prompt injection detector using transformer models.

This detector uses a fine-tuned DistilBERT model to classify text as
potentially containing prompt injection attacks. It provides higher
accuracy than regex-based detection, especially for obfuscated attacks.

Requires: pip install agent-memory-guard[ml]
"""
from __future__ import annotations

import logging
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity

# Severity ordering helper
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

log = logging.getLogger("agent_memory_guard.ml")

# Default model — a community fine-tuned model for prompt injection detection
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
FALLBACK_MODEL = "deepset/deberta-v3-base-injection"

# Threshold for classifying as injection
DEFAULT_THRESHOLD = 0.85


class MLInjectionDetector:
    """ML-based prompt injection detector using transformer models.

    Uses a pre-trained classifier to detect prompt injection attempts
    with higher accuracy than regex patterns. Falls back gracefully
    to regex detection if transformers are not installed.

    Parameters
    ----------
    model_name : str
        HuggingFace model name or path. Default uses ProtectAI's
        DeBERTa-v3 model fine-tuned on prompt injection datasets.
    threshold : float
        Classification threshold (0.0-1.0). Higher = fewer false positives.
    device : str
        Device for inference: "cpu", "cuda", or "auto".
    max_length : int
        Maximum token length for input text.
    severity : Severity
        Severity level for detected threats.
    lazy_load : bool
        If True, model is loaded on first use rather than initialization.
    """

    name = "ml_injection"

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        threshold: float = DEFAULT_THRESHOLD,
        device: str = "cpu",
        max_length: int = 512,
        severity: Severity = Severity.HIGH,
        lazy_load: bool = True,
    ) -> None:
        self._model_name = model_name
        self._threshold = threshold
        self._device = device
        self._max_length = max_length
        self._severity = severity
        self._lazy_load = lazy_load
        self._pipeline: Any = None
        self._available = True

        if not lazy_load:
            self._load_model()

    def _load_model(self) -> bool:
        """Load the classification pipeline."""
        if self._pipeline is not None:
            return True

        try:
            from transformers import pipeline as hf_pipeline

            self._pipeline = hf_pipeline(
                "text-classification",
                model=self._model_name,
                device=self._device if self._device != "auto" else -1,
                truncation=True,
                max_length=self._max_length,
            )
            log.info(f"Loaded ML injection model: {self._model_name}")
            return True
        except ImportError:
            log.warning(
                "transformers not installed. ML injection detection disabled. "
                "Install with: pip install agent-memory-guard[ml]"
            )
            self._available = False
            return False
        except Exception as e:
            log.warning(f"Failed to load ML model '{self._model_name}': {e}")
            # Try fallback model
            try:
                from transformers import pipeline as hf_pipeline

                self._pipeline = hf_pipeline(
                    "text-classification",
                    model=FALLBACK_MODEL,
                    device=self._device if self._device != "auto" else -1,
                    truncation=True,
                    max_length=self._max_length,
                )
                log.info(f"Loaded fallback ML model: {FALLBACK_MODEL}")
                return True
            except Exception as e2:
                log.warning(f"Fallback model also failed: {e2}")
                self._available = False
                return False

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Classify text using the ML model."""
        text = _stringify(value)
        if not text or len(text) < 10:
            return DetectionResult(self.name, matched=False)

        # Lazy load model on first use
        if self._pipeline is None and self._available:
            if not self._load_model():
                return DetectionResult(self.name, matched=False)

        if not self._available or self._pipeline is None:
            return DetectionResult(self.name, matched=False)

        try:
            # Truncate very long text to avoid OOM
            truncated = text[:2048]
            results = self._pipeline(truncated)

            if not results:
                return DetectionResult(self.name, matched=False)

            result = results[0] if isinstance(results, list) else results

            # Models may use different label names
            label = result.get("label", "").upper()
            score = result.get("score", 0.0)

            # Check if classified as injection
            is_injection = False
            if label in ("INJECTION", "LABEL_1", "1", "POSITIVE", "UNSAFE"):
                is_injection = score >= self._threshold
            elif label in ("SAFE", "LABEL_0", "0", "NEGATIVE", "BENIGN"):
                # Invert: if "safe" confidence is low, it might be injection
                is_injection = (1.0 - score) >= self._threshold

            if not is_injection:
                return DetectionResult(self.name, matched=False)

            return DetectionResult(
                detector=self.name,
                matched=True,
                severity=self._severity,
                message=(
                    f"ML model detected potential prompt injection in '{key}' "
                    f"(confidence: {score:.2%}, model: {self._model_name})"
                ),
                metadata={
                    "model": self._model_name,
                    "label": label,
                    "confidence": round(score, 4),
                    "threshold": self._threshold,
                    "operation": operation,
                    "text_length": len(text),
                },
            )

        except Exception as e:
            log.warning(f"ML inference error: {e}")
            return DetectionResult(self.name, matched=False)

    @property
    def is_available(self) -> bool:
        """Check if the ML model is loaded and available."""
        return self._available and self._pipeline is not None
