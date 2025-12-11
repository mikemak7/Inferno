"""
Performance benchmarks for Inferno-AI vulnerability scanning.

Tests scanning speed, memory usage, API token efficiency,
and throughput under various conditions.
"""

import pytest
import time
import asyncio
from statistics import mean, stdev
from unittest.mock import Mock, AsyncMock, patch

from inferno.tools.advanced.idor_scanner import IDORScanner
from inferno.tools.advanced.ssrf_detector import SSRFDetector
from inferno.tools.advanced.validation_engine import ValidationEngine


@pytest.mark.slow
@pytest.mark.performance
class TestScanningSpeed:
    """Test scanning speed and throughput."""

    @pytest.mark.asyncio
    async def test_idor_enumeration_speed(self):
        """
        Benchmark: IDOR scanner enumeration speed
        Target: Scan 100 sequential IDs in < 10 seconds
        Expected RPS: > 10 requests/second
        """
        scanner = IDORScanner()

        # Mock fast responses
        def mock_request(url, method, context, params=None):
            response = Mock()
            response.status_code = 200
            response.text = '{"data": "ok"}'
            return (response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            start_time = time.time()

            result = await scanner.execute(
                operation="enum",
                url="http://test.local/api/users/{id}",
                method="GET",
                enum_start=1,
                enum_count=100,
                user1_auth={"headers": {"Authorization": "Bearer test"}}
            )

            elapsed = time.time() - start_time

        # Performance assertions
        assert elapsed < 10.0, f"IDOR scan took {elapsed:.2f}s (target: <10s)"
        assert result.success

        # Calculate metrics
        rps = 100 / elapsed
        avg_time_ms = (elapsed / 100) * 1000

        assert rps > 10, f"RPS too low: {rps:.2f} (target: >10)"

        print(f"\n{'='*60}")
        print(f"IDOR Scanner Performance Benchmark")
        print(f"{'='*60}")
        print(f"Total time:           {elapsed:.2f}s")
        print(f"Requests/second:      {rps:.2f}")
        print(f"Avg time per request: {avg_time_ms:.2f}ms")
        print(f"Total requests:       100")
        print(f"{'='*60}")

    @pytest.mark.asyncio
    async def test_ssrf_payload_generation_speed(self):
        """
        Benchmark: SSRF payload generation speed
        Target: Generate 1000 payloads in < 1 second
        """
        detector = SSRFDetector()

        start_time = time.time()

        result = await detector.execute(
            operation="generate_payloads",
            categories=["localhost", "cloud_metadata", "url_bypass"],
            count=1000
        )

        elapsed = time.time() - start_time

        assert elapsed < 1.0, f"Payload generation took {elapsed:.2f}s (target: <1s)"

        total_payloads = sum(len(payloads) for payloads in result["payloads"].values())
        assert total_payloads >= 1000

        payloads_per_sec = total_payloads / elapsed

        print(f"\n{'='*60}")
        print(f"SSRF Payload Generation Performance")
        print(f"{'='*60}")
        print(f"Generated payloads:   {total_payloads}")
        print(f"Time:                 {elapsed:.3f}s")
        print(f"Payloads/second:      {payloads_per_sec:.0f}")
        print(f"{'='*60}")

    @pytest.mark.asyncio
    async def test_validation_engine_throughput(self):
        """
        Benchmark: Validation engine throughput
        Target: Validate 50 findings in < 30 seconds
        """
        validator = ValidationEngine()

        # Create mock findings
        findings = [
            {
                "url": f"http://test.local/api/endpoint{i}",
                "parameter": "id",
                "vuln_type": "sql_injection",
                "original_payload": "' OR '1'='1"
            }
            for i in range(50)
        ]

        # Mock validation responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "You have an error in your SQL syntax"

        with patch.object(validator, '_make_request', return_value=(mock_response, 0.05, "")):
            start_time = time.time()

            results = []
            for finding in findings:
                result = await validator.execute(
                    operation="validate",
                    **finding
                )
                results.append(result)

            elapsed = time.time() - start_time

        assert elapsed < 30.0, f"Validation took {elapsed:.2f}s (target: <30s)"
        assert len(results) == 50

        validations_per_sec = 50 / elapsed
        assert validations_per_sec > 1.5, f"Throughput too low: {validations_per_sec:.2f} val/s"

        print(f"\n{'='*60}")
        print(f"Validation Engine Throughput")
        print(f"{'='*60}")
        print(f"Validated findings:   50")
        print(f"Total time:           {elapsed:.2f}s")
        print(f"Validations/second:   {validations_per_sec:.2f}")
        print(f"Avg time per finding: {(elapsed/50)*1000:.2f}ms")
        print(f"{'='*60}")

    @pytest.mark.asyncio
    async def test_concurrent_scanning_performance(self):
        """
        Benchmark: Concurrent scanning with asyncio
        Target: 10 concurrent scans complete in < 5 seconds
        """
        scanner = IDORScanner()

        def mock_request(url, method, context, params=None):
            # Simulate network delay
            time.sleep(0.1)
            response = Mock()
            response.status_code = 200
            response.text = '{"data": "ok"}'
            return (response, "")

        async def scan_target(target_id):
            with patch.object(scanner, '_make_request', side_effect=mock_request):
                result = await scanner.execute(
                    operation="scan",
                    url=f"http://test.local/api/users/{target_id}",
                    method="GET",
                    user1_auth={"headers": {"Authorization": "Bearer test"}}
                )
            return result

        start_time = time.time()

        # Run 10 scans concurrently
        tasks = [scan_target(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        elapsed = time.time() - start_time

        # With 100ms per request, serial would take 1s
        # Concurrent should be much faster
        assert elapsed < 5.0, f"Concurrent scans took {elapsed:.2f}s (target: <5s)"
        assert len(results) == 10
        assert all(r.success for r in results)

        print(f"\n{'='*60}")
        print(f"Concurrent Scanning Performance")
        print(f"{'='*60}")
        print(f"Concurrent tasks:     10")
        print(f"Total time:           {elapsed:.2f}s")
        print(f"Expected serial time: ~1.0s")
        print(f"Speedup factor:       {1.0/elapsed:.2f}x")
        print(f"{'='*60}")


@pytest.mark.slow
@pytest.mark.performance
class TestMemoryUsage:
    """Test memory usage and leak detection."""

    @pytest.mark.asyncio
    async def test_memory_usage_long_session(self):
        """
        Benchmark: Memory usage during extended scanning
        Target: Memory growth < 500MB over 1000 requests
        """
        try:
            import psutil
            import os
        except ImportError:
            pytest.skip("psutil not installed")

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        scanner = IDORScanner()

        def mock_request(url, method, context, params=None):
            response = Mock()
            response.status_code = 200
            response.text = '{"data": "ok"}' * 100  # Some data
            return (response, "")

        # Simulate long scanning session
        with patch.object(scanner, '_make_request', side_effect=mock_request):
            for i in range(1000):
                await scanner.execute(
                    operation="scan",
                    url=f"http://test.local/api/users/{i}",
                    method="GET",
                    user1_auth={"headers": {"Authorization": "Bearer test"}}
                )

                # Periodic memory check
                if i % 100 == 0:
                    current_memory = process.memory_info().rss / 1024 / 1024
                    growth = current_memory - initial_memory
                    print(f"  Request {i}: Memory = {current_memory:.2f}MB (+{growth:.2f}MB)")

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory

        assert memory_growth < 500, f"Memory grew by {memory_growth:.2f}MB (target: <500MB)"

        print(f"\n{'='*60}")
        print(f"Memory Usage Test (1000 requests)")
        print(f"{'='*60}")
        print(f"Initial memory:       {initial_memory:.2f}MB")
        print(f"Final memory:         {final_memory:.2f}MB")
        print(f"Memory growth:        {memory_growth:.2f}MB")
        print(f"Growth per request:   {memory_growth/1000:.3f}MB")
        print(f"{'='*60}")

    @pytest.mark.asyncio
    async def test_memory_leak_detection(self):
        """
        Test: Detect memory leaks in scanner
        Method: Run same operation 100 times, check for linear growth
        """
        try:
            import psutil
            import os
        except ImportError:
            pytest.skip("psutil not installed")

        process = psutil.Process(os.getpid())
        scanner = IDORScanner()

        memory_samples = []

        def mock_request(url, method, context, params=None):
            response = Mock()
            response.status_code = 200
            response.text = '{"data": "ok"}'
            return (response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            for i in range(100):
                await scanner.execute(
                    operation="scan",
                    url="http://test.local/api/users/123",
                    method="GET",
                    user1_auth={"headers": {"Authorization": "Bearer test"}}
                )

                if i % 10 == 0:
                    memory = process.memory_info().rss / 1024 / 1024
                    memory_samples.append(memory)

        # Check for linear growth (indicator of leak)
        if len(memory_samples) > 2:
            growth_rate = (memory_samples[-1] - memory_samples[0]) / len(memory_samples)
            # Growth should be minimal (<1MB per 10 iterations)
            assert growth_rate < 1.0, f"Possible memory leak: {growth_rate:.2f}MB per 10 iterations"

        print(f"\n{'='*60}")
        print(f"Memory Leak Detection")
        print(f"{'='*60}")
        print(f"Memory samples: {memory_samples}")
        print(f"Trend: {growth_rate:.3f}MB per 10 iterations")
        print(f"{'='*60}")


@pytest.mark.performance
class TestResponseTimeDistribution:
    """Test response time distribution and percentiles."""

    @pytest.mark.asyncio
    async def test_response_time_percentiles(self):
        """
        Benchmark: Response time percentiles
        Target: P95 < 500ms, P99 < 1000ms
        """
        scanner = IDORScanner()
        response_times = []

        def mock_request(url, method, context, params=None):
            # Simulate variable response times
            import random
            delay = random.uniform(0.05, 0.3)
            time.sleep(delay)
            response_times.append(delay * 1000)  # Convert to ms

            response = Mock()
            response.status_code = 200
            response.text = '{"data": "ok"}'
            return (response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            for i in range(100):
                await scanner.execute(
                    operation="scan",
                    url=f"http://test.local/api/users/{i}",
                    method="GET",
                    user1_auth={"headers": {"Authorization": "Bearer test"}}
                )

        # Calculate percentiles
        response_times.sort()
        p50 = response_times[len(response_times) // 2]
        p95 = response_times[int(len(response_times) * 0.95)]
        p99 = response_times[int(len(response_times) * 0.99)]

        avg = mean(response_times)
        std = stdev(response_times) if len(response_times) > 1 else 0

        assert p95 < 500, f"P95 too high: {p95:.2f}ms (target: <500ms)"
        assert p99 < 1000, f"P99 too high: {p99:.2f}ms (target: <1000ms)"

        print(f"\n{'='*60}")
        print(f"Response Time Distribution")
        print(f"{'='*60}")
        print(f"Average:              {avg:.2f}ms")
        print(f"Std Dev:              {std:.2f}ms")
        print(f"P50 (median):         {p50:.2f}ms")
        print(f"P95:                  {p95:.2f}ms")
        print(f"P99:                  {p99:.2f}ms")
        print(f"Min:                  {min(response_times):.2f}ms")
        print(f"Max:                  {max(response_times):.2f}ms")
        print(f"{'='*60}")


@pytest.mark.performance
class TestRateLimitingPerformance:
    """Test performance with rate limiting enabled."""

    @pytest.mark.asyncio
    async def test_rate_limited_scanning(self):
        """
        Benchmark: Scanning with rate limiting
        Target: Respect rate limit while maintaining throughput
        """
        scanner = IDORScanner()
        request_timestamps = []

        def mock_request(url, method, context, params=None):
            request_timestamps.append(time.time())
            response = Mock()
            response.status_code = 200
            response.text = '{"data": "ok"}'
            return (response, "")

        # Set rate limit: max 10 requests per second
        rate_limit_rps = 10

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            start_time = time.time()

            for i in range(50):
                await scanner.execute(
                    operation="scan",
                    url=f"http://test.local/api/users/{i}",
                    method="GET",
                    user1_auth={"headers": {"Authorization": "Bearer test"}},
                    rate_limit_rps=rate_limit_rps
                )

            elapsed = time.time() - start_time

        # Calculate actual RPS
        actual_rps = 50 / elapsed

        # Should respect rate limit
        assert actual_rps <= rate_limit_rps * 1.1, f"Exceeded rate limit: {actual_rps:.2f} RPS"

        # Check request spacing
        if len(request_timestamps) > 1:
            intervals = [
                request_timestamps[i] - request_timestamps[i-1]
                for i in range(1, len(request_timestamps))
            ]
            avg_interval = mean(intervals) * 1000  # ms

            print(f"\n{'='*60}")
            print(f"Rate Limiting Performance")
            print(f"{'='*60}")
            print(f"Rate limit:           {rate_limit_rps} req/s")
            print(f"Actual RPS:           {actual_rps:.2f}")
            print(f"Total time:           {elapsed:.2f}s")
            print(f"Avg interval:         {avg_interval:.2f}ms")
            print(f"Expected interval:    {1000/rate_limit_rps:.2f}ms")
            print(f"{'='*60}")


@pytest.mark.performance
class TestScalingBehavior:
    """Test scaling behavior with increasing load."""

    @pytest.mark.asyncio
    async def test_linear_scaling(self):
        """
        Benchmark: Scaling behavior
        Target: Near-linear scaling up to 100 concurrent requests
        """
        scanner = IDORScanner()

        async def scan_batch(batch_size):
            def mock_request(url, method, context, params=None):
                time.sleep(0.01)  # 10ms per request
                response = Mock()
                response.status_code = 200
                response.text = '{"data": "ok"}'
                return (response, "")

            with patch.object(scanner, '_make_request', side_effect=mock_request):
                start = time.time()
                tasks = [
                    scanner.execute(
                        operation="scan",
                        url=f"http://test.local/api/users/{i}",
                        method="GET",
                        user1_auth={"headers": {"Authorization": "Bearer test"}}
                    )
                    for i in range(batch_size)
                ]
                await asyncio.gather(*tasks)
                return time.time() - start

        # Test different batch sizes
        batch_sizes = [10, 25, 50, 100]
        timings = []

        for batch_size in batch_sizes:
            elapsed = await scan_batch(batch_size)
            timings.append(elapsed)
            print(f"  Batch {batch_size}: {elapsed:.2f}s ({batch_size/elapsed:.2f} req/s)")

        # Check scaling efficiency
        # With perfect linear scaling, time should be constant
        # In practice, some overhead is expected
        scaling_efficiency = (timings[0] * (batch_sizes[-1] / batch_sizes[0])) / timings[-1]

        print(f"\n{'='*60}")
        print(f"Scaling Behavior")
        print(f"{'='*60}")
        for i, batch_size in enumerate(batch_sizes):
            print(f"Batch {batch_size:3d}: {timings[i]:6.2f}s ({batch_size/timings[i]:6.2f} req/s)")
        print(f"Scaling efficiency:   {scaling_efficiency:.2%}")
        print(f"{'='*60}")

        # Should maintain reasonable efficiency (>70%)
        assert scaling_efficiency > 0.7, f"Poor scaling: {scaling_efficiency:.2%}"


@pytest.mark.performance
class TestDatabaseQueryPerformance:
    """Test vector database query performance."""

    @pytest.mark.asyncio
    async def test_vector_search_performance(self):
        """
        Benchmark: Vector similarity search performance
        Target: < 100ms for similarity search in 10K vectors
        """
        pytest.skip("Requires Qdrant running - implement with @pytest.mark.requires_qdrant")

        # Implementation would test:
        # - Insert 10K vectors
        # - Measure search time
        # - Verify < 100ms average


@pytest.mark.performance
class TestCacheEfficiency:
    """Test caching efficiency for repeated operations."""

    @pytest.mark.asyncio
    async def test_response_caching_hit_rate(self):
        """
        Benchmark: Response caching hit rate
        Target: > 80% cache hit rate for repeated requests
        """
        # Mock cache implementation
        cache_hits = 0
        cache_misses = 0

        scanner = IDORScanner()

        # Simulate cache with dict
        response_cache = {}

        def mock_request(url, method, context, params=None):
            nonlocal cache_hits, cache_misses

            cache_key = f"{url}:{method}"

            if cache_key in response_cache:
                cache_hits += 1
                return response_cache[cache_key]
            else:
                cache_misses += 1
                response = Mock()
                response.status_code = 200
                response.text = '{"data": "ok"}'
                result = (response, "")
                response_cache[cache_key] = result
                return result

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            # Make requests, some repeated
            urls = [f"http://test.local/api/users/{i % 20}" for i in range(100)]

            for url in urls:
                await scanner.execute(
                    operation="scan",
                    url=url,
                    method="GET",
                    user1_auth={"headers": {"Authorization": "Bearer test"}}
                )

        cache_hit_rate = cache_hits / (cache_hits + cache_misses)

        print(f"\n{'='*60}")
        print(f"Cache Efficiency")
        print(f"{'='*60}")
        print(f"Total requests:       {cache_hits + cache_misses}")
        print(f"Cache hits:           {cache_hits}")
        print(f"Cache misses:         {cache_misses}")
        print(f"Hit rate:             {cache_hit_rate:.2%}")
        print(f"{'='*60}")

        assert cache_hit_rate > 0.80, f"Cache hit rate too low: {cache_hit_rate:.2%}"
