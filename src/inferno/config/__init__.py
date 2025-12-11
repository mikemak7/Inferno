"""
Inferno configuration module.

This module provides centralized configuration management, environment
validation, and settings handling for the pentesting agent.
"""

from inferno.config.environment import (
    EnvironmentInfo,
    OperationContext,
    SecurityTool,
    discover_security_tools,
    generate_operation_id,
    get_environment_info,
    setup_logging,
    setup_operation_context,
    validate_environment,
)
from inferno.config.manager import (
    ConfigManager,
    ConfigurationError,
    get_config_manager,
    get_settings,
)
from inferno.config.settings import (
    BETA_HEADERS,
    CODE_EXECUTION_VERSION,
    AnthropicToolType,
    BetaFeature,
    ExecutionConfig,
    InfernoSettings,
    MemoryConfig,
    ModelConfig,
    ModelProvider,
    ModelTier,
    ObservabilityConfig,
    OutputConfig,
    ToolConfig,
    ToolSearchVariant,
    get_beta_headers,
)

__all__ = [
    # Settings
    "InfernoSettings",
    "ModelConfig",
    "MemoryConfig",
    "ToolConfig",
    "ExecutionConfig",
    "ObservabilityConfig",
    "OutputConfig",
    # Enums
    "AnthropicToolType",
    "BetaFeature",
    "ModelProvider",
    "ModelTier",
    "ToolSearchVariant",
    # Constants
    "BETA_HEADERS",
    "CODE_EXECUTION_VERSION",
    # Functions
    "get_beta_headers",
    # Manager
    "ConfigManager",
    "ConfigurationError",
    "get_config_manager",
    "get_settings",
    # Environment
    "EnvironmentInfo",
    "OperationContext",
    "SecurityTool",
    "discover_security_tools",
    "generate_operation_id",
    "get_environment_info",
    "setup_logging",
    "setup_operation_context",
    "validate_environment",
]
