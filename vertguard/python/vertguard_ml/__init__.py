"""VertGuard ML inference service.

The Go scanners use rule-based prefilters; ambiguous inputs are routed
here for ML refinement. The default backend is a deterministic stub so
the wiring can be exercised end-to-end before real weights exist.
"""

__version__ = "0.1.0"
