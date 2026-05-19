"""
utils/config_loader.py
======================
AI Red Team Harness v3 — YAML Configuration Loader

Responsibilities:
  - Load and validate YAML config files from the config/ directory
  - Merge environment variable overrides (12-factor app style)
  - Cache parsed configs to avoid repeated disk reads
  - Provide typed accessors with safe defaults
  - Detect and report malformed config early (fail-fast)

Config files:
  config/settings.yaml  — orchestrator runtime settings
  config/targets.yaml   — LLM endpoints under test
  config/safety.yaml    — allowlist + sandbox restrictions

Environment variable overrides:
  Any YAML key can be overridden with an env var using the pattern:
    RTH_<SECTION>_<KEY>=value
  Example: RTH_SETTINGS_MAX_ITERATIONS=50

Author: AI Red Team Harness v3
Python: 3.10+
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Safe YAML loader (no arbitrary Python object deserialisation)
# ---------------------------------------------------------------------------

def _safe_load(text: str) -> Any:
    if _YAML_AVAILABLE:
        return yaml.safe_load(text)
    # Minimal fallback: JSON is valid YAML for simple configs
    import json
    return json.loads(text)


# ---------------------------------------------------------------------------
# Default Configurations
# ---------------------------------------------------------------------------

_DEFAULTS: dict[str, dict[str, Any]] = {
    "settings.yaml": {
        "max_iterations":   100,
        "concurrency":       4,
        "timeout_seconds":  30.0,
        "dry_run":          False,
        "verbose":          False,
        "mode":             "standard",
        "log_level":        "INFO",
    },
    "targets.yaml": {
        "targets": [
            {
                "id":           "local-ollama",
                "type":         "ollama",
                "endpoint":     "http://localhost:11434",
                "model":        "llama3",
                "attack_types": [
                    "prompt_injection",
                    "jailbreak",
                    "rag_poisoning",
                    "token_fuzzing",
                ],
            }
        ]
    },
    "safety.yaml": {
        "allowlist": {
            "targets": [
                {
                    "id":              "local-ollama",
                    "endpoint_prefix": "http://localhost",
                }
            ],
            "blocked_prefixes":  ["https://api.openai.com", "https://anthropic.com"],
            "allow_local_only":  True,
            "require_https":     False,
        },
        "sandbox": {
            "require_lab_marker":  True,
            "check_dns_isolation": False,
        },
        "prompt_guard": {
            "enabled":         True,
            "strict_mode":     False,
            "blocked_patterns": [],
        },
    },
}


# ---------------------------------------------------------------------------
# Config Loader
# ---------------------------------------------------------------------------

class ConfigLoader:
    """
    YAML configuration loader with caching and env-var override support.

    Usage:
        loader = ConfigLoader(config_dir=Path("config"))
        settings = loader.load("settings.yaml")
        targets  = loader.load("targets.yaml")
    """

    ENV_PREFIX = "RTH_"

    def __init__(self, config_dir: Path = Path("config")) -> None:
        self._config_dir = config_dir
        self._cache:      dict[str, dict[str, Any]] = {}

        if not _YAML_AVAILABLE:
            logger.warning(
                "PyYAML not installed — using JSON fallback. "
                "Run: pip install pyyaml"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, filename: str) -> dict[str, Any]:
        """
        Load a config file, apply env-var overrides, and cache the result.

        Args:
            filename: Config filename (e.g., 'settings.yaml').

        Returns:
            Parsed config dict, merged with defaults.
        """
        if filename in self._cache:
            return self._cache[filename]

        config = self._load_from_disk(filename)
        config = self._apply_env_overrides(config, filename)
        self._cache[filename] = config

        logger.debug("Config loaded | file=%s keys=%d", filename, len(config))
        return config

    def reload(self, filename: str) -> dict[str, Any]:
        """Force-reload a config file (clears cache entry)."""
        self._cache.pop(filename, None)
        return self.load(filename)

    def get(self, filename: str, key: str, default: Any = None) -> Any:
        """Convenience accessor for a single key."""
        return self.load(filename).get(key, default)

    def validate_all(self) -> list[str]:
        """
        Load all known config files and return a list of validation errors.
        Empty list means all configs are valid.
        """
        errors: list[str] = []
        for filename in _DEFAULTS:
            try:
                cfg = self.load(filename)
                errs = self._validate(filename, cfg)
                errors.extend(errs)
            except Exception as exc:
                errors.append(f"{filename}: load error — {exc}")
        return errors

    # ------------------------------------------------------------------
    # Internal Loading
    # ------------------------------------------------------------------

    def _load_from_disk(self, filename: str) -> dict[str, Any]:
        """Read YAML from disk, falling back to defaults if file missing."""
        path = self._config_dir / filename
        defaults = _DEFAULTS.get(filename, {})

        if not path.exists():
            logger.warning(
                "Config file '%s' not found — using built-in defaults. "
                "Create config/%s to customise.",
                filename, filename,
            )
            return dict(defaults)

        try:
            text = path.read_text(encoding="utf-8")
            parsed = _safe_load(text) or {}
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected a YAML mapping, got {type(parsed).__name__}")

            # Deep-merge with defaults (defaults fill missing keys only)
            merged = self._deep_merge(defaults, parsed)
            logger.info("Config loaded from disk | file=%s", filename)
            return merged

        except Exception as exc:
            logger.error(
                "Failed to parse config '%s': %s — using defaults.", filename, exc
            )
            return dict(defaults)

    def _apply_env_overrides(
        self, config: dict[str, Any], filename: str
    ) -> dict[str, Any]:
        """
        Apply environment variable overrides.
        Pattern: RTH_SETTINGS_MAX_ITERATIONS=50
                 → config["max_iterations"] = 50  (for settings.yaml)

        Only top-level keys are supported via env vars.
        """
        # Derive section name from filename: "settings.yaml" → "SETTINGS"
        section = filename.replace(".yaml", "").replace("-", "_").upper()
        prefix  = f"{self.ENV_PREFIX}{section}_"

        overridden = 0
        for env_key, env_val in os.environ.items():
            if not env_key.startswith(prefix):
                continue
            config_key = env_key[len(prefix):].lower()
            # Attempt type coercion
            coerced = self._coerce(env_val, config.get(config_key))
            config[config_key] = coerced
            overridden += 1
            logger.info(
                "Config override via env | key=%s value=%r", config_key, coerced
            )

        return config

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, filename: str, config: dict[str, Any]) -> list[str]:
        errors: list[str] = []

        if filename == "settings.yaml":
            if not isinstance(config.get("max_iterations"), int):
                errors.append("settings.yaml: max_iterations must be an integer")
            if not isinstance(config.get("concurrency"), int):
                errors.append("settings.yaml: concurrency must be an integer")
            if config.get("mode") not in ("standard", "aggressive", "stealth"):
                errors.append(
                    f"settings.yaml: mode must be standard|aggressive|stealth, "
                    f"got '{config.get('mode')}'"
                )

        elif filename == "targets.yaml":
            targets = config.get("targets", [])
            if not targets:
                errors.append("targets.yaml: no targets defined")
            for t in targets:
                if not t.get("id"):
                    errors.append("targets.yaml: each target must have an 'id'")
                if not t.get("endpoint"):
                    errors.append(f"targets.yaml: target '{t.get('id')}' missing endpoint")

        elif filename == "safety.yaml":
            allowlist = config.get("allowlist", {})
            if not allowlist.get("targets"):
                errors.append("safety.yaml: allowlist.targets is empty")

        return errors

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Merge override into base; override wins on conflict."""
        result = dict(base)
        for key, val in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(val, dict):
                result[key] = ConfigLoader._deep_merge(result[key], val)
            else:
                result[key] = val
        return result

    @staticmethod
    def _coerce(value: str, existing: Any) -> Any:
        """Coerce a string env var value to match the type of the existing config value."""
        if isinstance(existing, bool):
            return value.lower() in ("true", "1", "yes")
        if isinstance(existing, int):
            try:
                return int(value)
            except ValueError:
                return value
        if isinstance(existing, float):
            try:
                return float(value)
            except ValueError:
                return value
        return value