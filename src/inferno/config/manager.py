"""
Centralized configuration manager for Inferno.

This module provides a singleton configuration manager that handles
loading, caching, and providing access to all configuration settings.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING

import structlog

from inferno.config.environment import (
    EnvironmentInfo,
    OperationContext,
    discover_security_tools,
    get_environment_info,
    setup_logging,
    setup_operation_context,
    validate_environment,
)
from inferno.config.settings import InfernoSettings

if TYPE_CHECKING:
    from inferno.config.environment import SecurityTool

logger = structlog.get_logger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""

    pass


class ConfigManager:
    """
    Centralized configuration manager.

    Provides a singleton pattern for accessing configuration throughout
    the application. Handles environment validation, tool discovery,
    and operation context management.
    """

    _instance: ConfigManager | None = None
    _lock: Lock = Lock()

    def __new__(cls) -> ConfigManager:
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the configuration manager."""
        if self._initialized:
            return

        self._settings: InfernoSettings | None = None
        self._environment_info: EnvironmentInfo | None = None
        self._security_tools: dict[str, SecurityTool] | None = None
        self._current_context: OperationContext | None = None
        self._initialized = True

    @property
    def settings(self) -> InfernoSettings:
        """
        Get the current settings.

        Raises:
            ConfigurationError: If settings have not been loaded.
        """
        if self._settings is None:
            raise ConfigurationError(
                "Settings not loaded. Call load_settings() first."
            )
        return self._settings

    @property
    def environment(self) -> EnvironmentInfo:
        """Get environment information."""
        if self._environment_info is None:
            self._environment_info = get_environment_info()
        return self._environment_info

    @property
    def security_tools(self) -> dict[str, SecurityTool]:
        """Get discovered security tools."""
        if self._security_tools is None:
            self._security_tools = discover_security_tools()
        return self._security_tools

    @property
    def context(self) -> OperationContext | None:
        """Get the current operation context."""
        return self._current_context

    def load_settings(
        self,
        env_file: Path | None = None,
        **overrides: object,
    ) -> InfernoSettings:
        """
        Load settings from environment and optional file.

        Args:
            env_file: Optional path to a .env file.
            **overrides: Override specific settings.

        Returns:
            Loaded InfernoSettings object.

        Raises:
            ConfigurationError: If required settings are missing.
        """
        # Set env file path if provided
        if env_file and env_file.exists():
            os.environ["INFERNO_ENV_FILE"] = str(env_file)

        try:
            self._settings = InfernoSettings(**overrides)
        except Exception as e:
            raise ConfigurationError(f"Failed to load settings: {e}") from e

        # Setup logging based on settings
        setup_logging(self._settings)

        logger.info(
            "settings_loaded",
            model=self._settings.model.model_id.value,
            memory_backend="qdrant",
            tool_search=self._settings.tools.search_variant.value,
        )

        return self._settings

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate the current configuration and environment.

        Returns:
            Tuple of (is_valid, error_messages).
        """
        if self._settings is None:
            return False, ["Settings not loaded"]

        return validate_environment(self._settings)

    def create_operation(
        self,
        target: str,
        objective: str,
        operation_id: str | None = None,
    ) -> OperationContext:
        """
        Create a new operation context.

        Args:
            target: Target for the assessment.
            objective: Assessment objective.
            operation_id: Optional custom operation ID.

        Returns:
            New OperationContext object.
        """
        if self._settings is None:
            raise ConfigurationError("Settings not loaded")

        self._current_context = setup_operation_context(
            settings=self._settings,
            target=target,
            objective=objective,
            operation_id=operation_id,
        )

        return self._current_context

    def get_available_tools(self) -> list[str]:
        """Get list of available security tool names."""
        return [
            name for name, tool in self.security_tools.items()
            if tool.available
        ]

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        tool = self.security_tools.get(tool_name)
        return tool is not None and tool.available

    def get_tool_path(self, tool_name: str) -> Path | None:
        """Get the path to a security tool."""
        tool = self.security_tools.get(tool_name)
        if tool and tool.available:
            return tool.path
        return None

    def reset(self) -> None:
        """Reset the configuration manager state."""
        self._settings = None
        self._environment_info = None
        self._security_tools = None
        self._current_context = None
        logger.debug("config_manager_reset")


@lru_cache(maxsize=1)
def get_config_manager() -> ConfigManager:
    """
    Get the singleton ConfigManager instance.

    Returns:
        The ConfigManager singleton.
    """
    return ConfigManager()


def get_settings() -> InfernoSettings:
    """
    Convenience function to get current settings.

    Returns:
        Current InfernoSettings.

    Raises:
        ConfigurationError: If settings not loaded.
    """
    return get_config_manager().settings
