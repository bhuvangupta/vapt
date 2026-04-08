"""Scanner registry — auto-discovers all scanner modules."""

from vapt.scanners.base import BaseScanner

# Registry populated by scanner imports
SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Decorator to register a scanner class."""
    SCANNER_REGISTRY[cls.name] = cls
    return cls


def get_scanner(name: str) -> type[BaseScanner] | None:
    return SCANNER_REGISTRY.get(name)


def all_scanners() -> list[type[BaseScanner]]:
    return list(SCANNER_REGISTRY.values())


def import_all_scanners():
    """Import all scanner modules to trigger registration."""
    from vapt.scanners import (  # noqa: F401
        recon, network, ssl_tls, headers, webapp,
        injection, auth, authz, api, logic,
        cloud, websocket_scan, graphql, ssrf, zap_scan,
    )
