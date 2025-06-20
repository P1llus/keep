"""
GitHub Code Scanning Provider Package.
"""

from .github_code_scanning_provider import (
    GithubCodeScanningProvider,
    GithubCodeScanningProviderAuthConfig,
)

__all__ = ["GithubCodeScanningProvider", "GithubCodeScanningProviderAuthConfig"]
