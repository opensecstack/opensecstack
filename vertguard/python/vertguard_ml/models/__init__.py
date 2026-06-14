"""Model backends for the inference service.

The base ABC defines the score contract; concrete backends (stub,
distilbert) plug in via env-var selection at server startup.
"""

from vertguard_ml.models.base import Feature, Model, ScoreResult

__all__ = ["Feature", "Model", "ScoreResult"]
