from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse


@dataclass
class TargetConfig:
    """Configuration for a single scan target."""

    url: str
    name: str = ""
    scope: list[str] = field(default_factory=list)
    auth: dict | None = None  # login_url, username, password, auth_type, token_header, cookies, api_key
    exclude_paths: list[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        """Extract the domain (hostname) from the target URL."""
        return urlparse(self.url).hostname or ""

    @property
    def base_url(self) -> str:
        """Return scheme + netloc (e.g. https://www.yourdomain.com)."""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def has_auth(self) -> bool:
        """Return True if authentication details are configured."""
        return self.auth is not None and bool(self.auth)

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL falls within the configured scope.

        Rules:
        - If no scope is defined, only the target domain is in scope.
        - Scope entries are glob patterns matched against the hostname
          (e.g. ``*.yourdomain.com`` matches ``admin.yourdomain.com``).
        - Exclude paths are checked after the domain passes.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Domain check — always include the target's own domain alongside scope patterns
        allowed_domains = list(self.scope) if self.scope else []
        if self.domain and self.domain not in allowed_domains:
            allowed_domains.append(self.domain)
        domain_ok = any(
            fnmatch.fnmatch(hostname, pattern) for pattern in allowed_domains
        )
        if not domain_ok:
            return False

        # Exclude path check — normalize to defeat encoding/case/traversal bypasses
        raw_path = parsed.path or "/"
        # URL-decode (%61dmin → admin), collapse traversals (/foo/../admin → /admin)
        normalized = posixpath.normpath(unquote(raw_path))
        # normpath strips trailing slash; ensure leading slash
        if not normalized.startswith("/"):
            normalized = "/" + normalized

        for excluded in self.exclude_paths:
            excluded_norm = posixpath.normpath(unquote(excluded))
            if not excluded_norm.startswith("/"):
                excluded_norm = "/" + excluded_norm
            # Case-insensitive comparison
            if normalized.lower().startswith(excluded_norm.lower()):
                return False

        return True
