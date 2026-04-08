"""External tool detection and fallback registry."""

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str = ""
    version: str = ""
    tier: str = "optional"  # core, recommended, optional


# Tool definitions: name -> (tier, version_flag)
TOOL_DEFS = {
    # Core (required for full coverage, but we always have fallbacks)
    "curl": ("core", "--version"),
    "openssl": ("core", "version"),
    "dig": ("core", "-v"),
    "whois": ("core", None),
    # Recommended
    "nmap": ("recommended", "--version"),
    "sqlmap": ("recommended", "--version"),
    "nuclei": ("recommended", "-version"),
    "nikto": ("recommended", "-Version"),
    "ffuf": ("recommended", "-V"),
    "testssl.sh": ("recommended", "--version"),
    "subfinder": ("recommended", "-version"),
    # Optional
    "whatweb": ("optional", "--version"),
    "sslscan": ("optional", "--version"),
    "wpscan": ("optional", "--version"),
    "hydra": ("optional", "-h"),
    "gobuster": ("optional", "version"),
    "dalfox": ("optional", "version"),
    "websocat": ("optional", "--version"),
}


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolStatus] = {}
        self._scan()

    def _scan(self):
        for name, (tier, ver_flag) in TOOL_DEFS.items():
            path = shutil.which(name)
            version = ""
            if path and ver_flag:
                try:
                    result = subprocess.run(
                        [path, ver_flag], capture_output=True, text=True, timeout=5
                    )
                    output = result.stdout or result.stderr
                    # Extract first line as version
                    version = output.strip().split("\n")[0][:80] if output else ""
                except Exception:
                    version = "unknown"
            self._tools[name] = ToolStatus(
                name=name, available=bool(path), path=path or "", version=version, tier=tier
            )

    def available(self, name: str) -> bool:
        return self._tools.get(name, ToolStatus(name=name, available=False)).available

    def get(self, name: str) -> ToolStatus:
        return self._tools.get(name, ToolStatus(name=name, available=False))

    def report(self) -> dict[str, list[ToolStatus]]:
        """Return tools grouped by tier."""
        result = {"core": [], "recommended": [], "optional": []}
        for tool in self._tools.values():
            result[tool.tier].append(tool)
        return result

    def summary_lines(self) -> list[str]:
        """Return human-readable summary lines for terminal output."""
        lines = []
        for tier in ("core", "recommended", "optional"):
            tools = [t for t in self._tools.values() if t.tier == tier]
            available = [t.name for t in tools if t.available]
            missing = [t.name for t in tools if not t.available]
            status = f"  {tier.upper()}: "
            if available:
                status += f"✓ {', '.join(available)}"
            if missing:
                status += f"  ✗ {', '.join(missing)}"
            lines.append(status)
        return lines
