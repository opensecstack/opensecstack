"""Make `training` importable as a package when running pytest from this dir."""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TRAINING = _HERE.parent
_PARENT = _TRAINING.parent

# Allow `import training.data.loader` and `from data.loader import ...`.
for path in (str(_PARENT), str(_TRAINING)):
    if path not in sys.path:
        sys.path.insert(0, path)
