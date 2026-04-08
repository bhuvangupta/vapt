"""Configuration loader for the VAPT suite.

Reads a YAML config file, expands environment variables, validates targets,
applies defaults, and returns a fully-parsed configuration dictionary.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from vapt.models.target import TargetConfig

# ── defaults ────────────────────────────────────────────────────────────────

_DEFAULT_SETTINGS: dict[str, Any] = {
    "timeout": 10,
    "max_concurrent": 5,
    "rate_limit": 2,
    "user_agent": "VAPT-Scanner/1.0",
    "follow_redirects": True,
}

_DEFAULT_REPORTING: dict[str, Any] = {
    "formats": ["html"],
    "output_dir": "./reports",
    "severity_threshold": "info",
}

_DEFAULT_SCANNERS: dict[str, Any] = {
    "skip": [],
    "enabled": [],
}

_DEFAULT_AUTHORIZATION: dict[str, Any] = {}


# ── helpers ─────────────────────────────────────────────────────────────────

def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ``${VAR}`` references in string values."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("${") and stripped.endswith("}"):
            env_key = stripped[2:-1]
            return os.environ.get(env_key, value)
        return value
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


def _deep_merge(base: dict, overrides: dict) -> dict:
    """Recursively merge *overrides* into *base* (mutates *base*)."""
    for key, val in overrides.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def _parse_targets(raw_targets: list[dict]) -> list[TargetConfig]:
    """Convert raw dicts into validated ``TargetConfig`` objects."""
    targets: list[TargetConfig] = []
    for idx, entry in enumerate(raw_targets):
        if "url" not in entry:
            raise ValueError(
                f"Target at index {idx} is missing the required 'url' field."
            )
        targets.append(
            TargetConfig(
                url=entry["url"],
                name=entry.get("name", ""),
                scope=entry.get("scope", []),
                auth=entry.get("auth"),
                exclude_paths=entry.get("exclude_paths", []),
            )
        )
    return targets


# ── public API ──────────────────────────────────────────────────────────────

def load_config(path: str, cli_overrides: dict | None = None) -> dict:
    """Load a YAML configuration file and return a parsed config dict.

    Parameters
    ----------
    path:
        Filesystem path to the YAML configuration file.
    cli_overrides:
        Optional dictionary of overrides that take precedence over the
        values found in the YAML file.

    Returns
    -------
    dict with keys:
        targets        – list[TargetConfig]
        settings       – dict
        scanners       – dict  (skip / enabled lists)
        reporting      – dict  (formats / output_dir / severity_threshold)
        authorization  – dict
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        raw: dict = yaml.safe_load(fh) or {}

    # Merge CLI overrides (if any) on top of the YAML data.
    if cli_overrides:
        raw = _deep_merge(raw, cli_overrides)

    # Expand environment variables throughout the entire tree.
    raw = _expand_env_vars(raw)

    # ── targets ─────────────────────────────────────────────────────────
    raw_targets = raw.get("targets")
    if not raw_targets or not isinstance(raw_targets, list):
        raise ValueError("Configuration must contain a non-empty 'targets' list.")
    targets = _parse_targets(raw_targets)

    # Handle extra targets from CLI --target flags
    extra_targets = raw.get("extra_targets", [])
    if extra_targets:
        for url in extra_targets:
            targets.append(TargetConfig(url=url, name=url))

    # ── settings ────────────────────────────────────────────────────────
    settings = {**_DEFAULT_SETTINGS, **raw.get("settings", {})}

    # ── scanners ────────────────────────────────────────────────────────
    scanners = {**_DEFAULT_SCANNERS, **raw.get("scanners", {})}

    # ── reporting ───────────────────────────────────────────────────────
    reporting = {**_DEFAULT_REPORTING, **raw.get("reporting", {})}

    # ── authorization ───────────────────────────────────────────────────
    authorization = {**_DEFAULT_AUTHORIZATION, **raw.get("authorization", {})}

    return {
        "targets": targets,
        "settings": settings,
        "scanners": scanners,
        "reporting": reporting,
        "authorization": authorization,
    }
