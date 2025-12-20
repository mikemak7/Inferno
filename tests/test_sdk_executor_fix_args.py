import asyncio
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from inferno.agent.sdk_executor import SDKAgentExecutor

class TestSDKExecutorFix(unittest.TestCase):
    def setUp(self):
        self.mock_settings = MagicMock()
        self.mock_settings.output.base_dir = Path("/tmp/inferno_test")
        # Ensure settings object doesn't have target/objective
        del self.mock_settings.target
        del self.mock_settings.objective
        
        # Mock ReportGenerator
        self.patcher_rg = patch("inferno.agent.sdk_executor.ReportGenerator")
        self.MockReportGenerator = self.patcher_rg.start()
        self.mock_report_generator = self.MockReportGenerator.return_value
        self.mock_report = MagicMock()
        self.mock_report_generator.create_report.return_value = self.mock_report
        
        # Mock other dependencies
        self.patcher_guardrails = patch("inferno.agent.sdk_executor.get_guardrail_engine", side_effect=ImportError)
        self.patcher_guardrails.start()
        
        self.patcher_memory = patch("inferno.agent.sdk_executor.MemoryToolWithFallback", side_effect=ImportError)
        self.patcher_memory.start()

    def tearDown(self):
        patch.stopall()

    def test_initialization_args(self):
        """Test that create_report is called with correct arguments."""
        executor = SDKAgentExecutor(settings=self.mock_settings)
        
        self.MockReportGenerator.assert_called_once()
        
        # Verify create_report called with correct args
        call_args = self.mock_report_generator.create_report.call_args
        self.assertIsNotNone(call_args)
        
        kwargs = call_args[1]
        self.assertIn("operation_id", kwargs)
        self.assertEqual(kwargs["target"], "unknown")
        self.assertEqual(kwargs["objective"], "unknown")
        self.assertNotIn("assessor", kwargs)  # Should NOT be present
        
        # Verify operation_id matches agent_id
        self.assertEqual(kwargs["operation_id"], executor._agent_id)

if __name__ == "__main__":
    unittest.main()
