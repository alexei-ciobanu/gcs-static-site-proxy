"""Renewable local proxy for a private GCS static-site prefix."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gcs-static-site-proxy")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["__version__"]
