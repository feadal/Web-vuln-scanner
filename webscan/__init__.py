"""webscan — an active web vulnerability scanner for authorized testing."""

__version__ = "0.3.0"

from webscan.models import Finding, InjectionPoint, ScanContext, ScanResult, Severity

__all__ = [
    "__version__",
    "Finding",
    "Severity",
    "InjectionPoint",
    "ScanContext",
    "ScanResult",
]
