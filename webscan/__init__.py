"""webscan — a lightweight passive web vulnerability scanner for authorized testing."""

__version__ = "0.1.0"

from webscan.models import Finding, ScanContext, ScanResult, Severity

__all__ = ["__version__", "Finding", "Severity", "ScanContext", "ScanResult"]
