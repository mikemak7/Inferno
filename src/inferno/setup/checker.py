"""
Setup checker for Inferno.

This module validates that all required dependencies are installed
and configured correctly before running assessments.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ComponentStatus(str, Enum):
    """Status of a setup component."""

    OK = "ok"
    MISSING = "missing"
    ERROR = "error"
    NOT_RUNNING = "not_running"


@dataclass
class ComponentCheck:
    """Result of checking a component."""

    name: str
    status: ComponentStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ok(self) -> bool:
        return self.status == ComponentStatus.OK


@dataclass
class SetupStatus:
    """Overall setup status."""

    docker: ComponentCheck
    qdrant: ComponentCheck
    credentials: ComponentCheck
    python_deps: ComponentCheck
    security_tools: list[ComponentCheck] = field(default_factory=list)

    @property
    def is_ready(self) -> bool:
        """Check if setup is complete and ready to run."""
        return (
            self.docker.is_ok
            and self.qdrant.is_ok
            and self.credentials.is_ok
            and self.python_deps.is_ok
        )

    @property
    def needs_setup(self) -> bool:
        """Check if initial setup is needed."""
        return not self.docker.is_ok or not self.qdrant.is_ok

    @property
    def needs_auth(self) -> bool:
        """Check if authentication is needed."""
        return not self.credentials.is_ok


class SetupChecker:
    """
    Checks and validates the Inferno setup.

    This class provides methods to verify that all required
    components are installed and running correctly.
    """

    def __init__(self, project_root: Path | None = None) -> None:
        """
        Initialize the setup checker.

        Args:
            project_root: Root directory of the project.
        """
        self._project_root = project_root or self._find_project_root()

    def _find_project_root(self) -> Path:
        """Find the project root directory."""
        # Look for pyproject.toml
        current = Path.cwd()
        for parent in [current, *current.parents]:
            if (parent / "pyproject.toml").exists():
                return parent
        return current

    def check_all(self) -> SetupStatus:
        """
        Run all setup checks.

        Returns:
            SetupStatus with results of all checks.
        """
        return SetupStatus(
            docker=self.check_docker(),
            qdrant=self.check_qdrant(),
            credentials=self.check_credentials(),
            python_deps=self.check_python_deps(),
            security_tools=self.check_security_tools(),
        )

    def check_docker(self) -> ComponentCheck:
        """Check if Docker is installed and running."""
        # Check if docker command exists
        docker_path = shutil.which("docker")
        if not docker_path:
            return ComponentCheck(
                name="Docker",
                status=ComponentStatus.MISSING,
                message="Docker is not installed",
                details={"install_url": "https://docs.docker.com/get-docker/"},
            )

        # Check if Docker daemon is running
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return ComponentCheck(
                    name="Docker",
                    status=ComponentStatus.NOT_RUNNING,
                    message="Docker daemon is not running",
                    details={"hint": "Start Docker Desktop or run 'sudo systemctl start docker'"},
                )

            # Get Docker version
            version_result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version = version_result.stdout.strip() if version_result.returncode == 0 else "unknown"

            return ComponentCheck(
                name="Docker",
                status=ComponentStatus.OK,
                message="Docker is installed and running",
                details={"version": version, "path": docker_path},
            )
        except subprocess.TimeoutExpired:
            return ComponentCheck(
                name="Docker",
                status=ComponentStatus.ERROR,
                message="Docker command timed out",
                details={"hint": "Docker may be unresponsive"},
            )
        except Exception as e:
            return ComponentCheck(
                name="Docker",
                status=ComponentStatus.ERROR,
                message=f"Error checking Docker: {e}",
            )

    def check_qdrant(self) -> ComponentCheck:
        """Check if Qdrant is running."""
        import httpx

        # Try default Qdrant port (newer versions use /healthz)
        qdrant_url = "http://localhost:6333/healthz"

        try:
            response = httpx.get(qdrant_url, timeout=5.0)
            if response.status_code == 200:
                return ComponentCheck(
                    name="Qdrant",
                    status=ComponentStatus.OK,
                    message="Qdrant is running",
                    details={"url": "http://localhost:6333"},
                )
            else:
                return ComponentCheck(
                    name="Qdrant",
                    status=ComponentStatus.ERROR,
                    message=f"Qdrant returned status {response.status_code}",
                )
        except httpx.ConnectError:
            return ComponentCheck(
                name="Qdrant",
                status=ComponentStatus.NOT_RUNNING,
                message="Qdrant is not running",
                details={"hint": "Will be started automatically"},
            )
        except Exception as e:
            return ComponentCheck(
                name="Qdrant",
                status=ComponentStatus.ERROR,
                message=f"Error checking Qdrant: {e}",
            )

    def check_credentials(self) -> ComponentCheck:
        """Check if authentication is configured."""
        # Use CredentialManager which checks all providers in order:
        # 1. Keychain (Claude Code OAuth) - macOS only
        # 2. OAuth tokens (saved)
        # 3. Environment variable (ANTHROPIC_API_KEY)
        # 4. Credentials file (~/.inferno/credentials.json)
        try:
            from inferno.auth.credentials import CredentialError, CredentialManager

            manager = CredentialManager()
            cred = manager.get_credential()

            # Determine friendly message based on source
            source = cred.source
            if source == "keychain:claude-code":
                message = "Claude Code credentials"
                details = {"type": "oauth", "source": "Claude Code (macOS Keychain)"}
            elif source == "oauth:anthropic":
                message = "OAuth authenticated"
                details = {"type": "oauth", "source": "saved token"}
            elif source.startswith("env:"):
                # Mask the key for display
                masked = f"{cred.value[:10]}...{cred.value[-4:]}" if len(cred.value) > 14 else "***"
                message = "API key configured"
                details = {"type": "api_key", "key": masked}
            elif source.startswith("file:"):
                message = "Credentials from file"
                details = {"type": "api_key", "source": source}
            else:
                message = f"Authenticated ({source})"
                details = {"source": source}

            return ComponentCheck(
                name="Credentials",
                status=ComponentStatus.OK,
                message=message,
                details=details,
            )
        except CredentialError:
            pass
        except Exception:
            pass

        return ComponentCheck(
            name="Credentials",
            status=ComponentStatus.MISSING,
            message="No authentication configured",
            details={
                "hint": "Run 'login' or set ANTHROPIC_API_KEY",
                "options": ["Claude Code (easiest)", "oauth", "api_key"],
            },
        )

    def check_python_deps(self) -> ComponentCheck:
        """Check if Python dependencies are installed."""
        missing = []

        required_packages = [
            ("anthropic", "anthropic"),
            ("httpx", "httpx"),
            ("typer", "typer"),
            ("rich", "rich"),
            ("pydantic", "pydantic"),
            ("structlog", "structlog"),
        ]

        for import_name, package_name in required_packages:
            try:
                __import__(import_name)
            except ImportError:
                missing.append(package_name)

        if missing:
            return ComponentCheck(
                name="Python Dependencies",
                status=ComponentStatus.MISSING,
                message=f"Missing packages: {', '.join(missing)}",
                details={"missing": missing, "hint": "Run 'pip install -e .'"},
            )

        return ComponentCheck(
            name="Python Dependencies",
            status=ComponentStatus.OK,
            message="All dependencies installed",
        )

    def check_security_tools(self) -> list[ComponentCheck]:
        """Check which security tools are available."""
        tools = [
            ("nmap", "Network scanner"),
            ("sqlmap", "SQL injection tool"),
            ("nikto", "Web server scanner"),
            ("gobuster", "Directory/DNS bruteforcer"),
            ("nuclei", "Vulnerability scanner"),
            ("subfinder", "Subdomain discovery"),
            ("httpx", "HTTP toolkit"),
            ("curl", "HTTP client"),
            ("dig", "DNS lookup"),
            ("whois", "WHOIS lookup"),
        ]

        results = []
        for tool, description in tools:
            path = shutil.which(tool)
            if path:
                results.append(ComponentCheck(
                    name=tool,
                    status=ComponentStatus.OK,
                    message=description,
                    details={"path": path},
                ))
            else:
                results.append(ComponentCheck(
                    name=tool,
                    status=ComponentStatus.MISSING,
                    message=f"{description} (not installed)",
                ))

        return results

    def get_env_file_path(self) -> Path:
        """Get the path to the .env file."""
        return self._project_root / ".env"

    def env_file_exists(self) -> bool:
        """Check if .env file exists."""
        return self.get_env_file_path().exists()

    def create_env_file(self) -> Path:
        """Create .env file from .env.example if it doesn't exist."""
        env_path = self.get_env_file_path()
        example_path = self._project_root / ".env.example"

        if not env_path.exists() and example_path.exists():
            env_path.write_text(example_path.read_text())
            logger.info("env_file_created", path=str(env_path))

        return env_path
