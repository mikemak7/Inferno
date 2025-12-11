"""
Inferno Benchmarks Module.

Provides benchmarking infrastructure for evaluating agent
performance on security assessment tasks.

Inspired by CAIBench integration patterns.
"""

from inferno.benchmarks.runner import (
    BenchmarkRunner,
    BenchmarkConfig,
    BenchmarkResult,
    BenchmarkSuite,
    get_benchmark_runner,
)
from inferno.benchmarks.metrics import (
    BenchmarkMetrics,
    MetricsCollector,
    AccuracyMetrics,
    PerformanceMetrics,
)
from inferno.benchmarks.tasks import (
    BenchmarkTask,
    TaskCategory,
    TaskDifficulty,
    create_task,
)

__all__ = [
    "BenchmarkRunner",
    "BenchmarkConfig",
    "BenchmarkResult",
    "BenchmarkSuite",
    "get_benchmark_runner",
    "BenchmarkMetrics",
    "MetricsCollector",
    "AccuracyMetrics",
    "PerformanceMetrics",
    "BenchmarkTask",
    "TaskCategory",
    "TaskDifficulty",
    "create_task",
]
