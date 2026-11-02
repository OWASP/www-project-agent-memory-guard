# Contributing

Agent Memory Guard is an OWASP Lab Project and welcomes contributions from the community.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/OWASP/www-project-agent-memory-guard.git
cd www-project-agent-memory-guard

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/
```

## Development Setup

Requirements:

- Python 3.9+
- pip or uv
- Git

## Project Structure

```
src/agent_memory_guard/
├── __init__.py          # Public API exports
├── guard.py             # MemoryGuard core class
├── cli.py               # CLI (amg command)
├── server.py            # FastAPI REST server
├── scanner/             # File scanner module
├── detectors/           # Detection modules
│   ├── base.py          # Detector interface
│   ├── injection.py     # Prompt injection
│   ├── leakage.py       # Sensitive data
│   ├── privilege_escalation.py
│   ├── tool_abuse.py
│   ├── excessive_autonomy.py
│   ├── cross_task.py
│   ├── self_reinforcement.py
│   ├── ml_injection.py  # ML-based (optional)
│   ├── anomaly.py       # Size/rate anomalies
│   └── protected_keys.py
├── integrations/        # Framework integrations
│   ├── langchain.py
│   ├── crewai.py
│   └── llamaindex.py
├── policies/            # Policy engine
├── storage/             # Memory store backends
├── events.py            # SecurityEvent model
├── classification.py    # Memory classification
├── integrity.py         # Hash-based integrity
└── metrics.py           # Prometheus metrics
```

## Adding a New Detector

1. Create a new file in `src/agent_memory_guard/detectors/`
2. Implement the `Detector` interface:

```python
from agent_memory_guard.detectors.base import Detector, DetectionResult

class MyNewDetector(Detector):
    name = "MyNewDetector"

    def detect(self, key: str, value: any, **context) -> DetectionResult:
        # Your detection logic here
        if is_threat(value):
            return DetectionResult(
                is_threat=True,
                detector=self.name,
                severity="high",
                message="Description of what was detected",
            )
        return DetectionResult(is_threat=False, detector=self.name)
```

3. Register in `src/agent_memory_guard/detectors/__init__.py`
4. Add tests in `tests/`
5. Add documentation in `docs/detectors/`

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=agent_memory_guard --cov-report=html

# Specific test file
pytest tests/test_detectors.py -v
```

## Code Style

- Format with `ruff format`
- Lint with `ruff check`
- Type check with `mypy src/`
- All public functions must have docstrings

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-detector`)
3. Write tests for new functionality
4. Ensure all tests pass and linting is clean
5. Submit a PR with a clear description

## Reporting Security Issues

For security vulnerabilities, please use [GitHub Security Advisories](https://github.com/OWASP/www-project-agent-memory-guard/security/advisories) rather than public issues.

## License

Apache 2.0 — see [LICENSE](https://github.com/OWASP/www-project-agent-memory-guard/blob/main/LICENSE) for details.
