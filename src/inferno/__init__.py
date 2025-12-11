"""
Inferno-AI: Autonomous Penetration Testing Agent powered by Claude.

Copyright (c) 2024-2025 Adem Kök. All Rights Reserved.

This software is proprietary and confidential. Unauthorized copying, modification,
distribution, or use of this software, via any medium, is strictly prohibited.
See LICENSE file for details.

This package provides an autonomous security assessment agent built on the Claude Agent SDK,
featuring advanced tool use capabilities including Tool Search, Programmatic Tool Calling,
and Tool Use Examples for maximum efficiency and accuracy.
"""

from importlib.metadata import version

__version__ = version("inferno")
__all__ = ["__version__"]
