"""
Unit tests for ApplicationModel.

Tests endpoint management, parameter inference, response anomaly detection,
workflow building, and attack surface reporting.
"""

import pytest
from datetime import datetime

from inferno.core.application_model import (
    ApplicationModel,
    AuthType,
    EndpointModel,
    ParameterModel,
    ParameterRole,
    ResponsePattern,
    SecurityControl,
    WorkflowModel,
    WorkflowStep,
)


class TestEndpointManagement:
    """Test adding and managing endpoints."""

    @pytest.mark.asyncio
    async def test_add_endpoint(self):
        """Test adding an endpoint to the model."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(
            path="/api/users/:id",
            methods={"GET", "PUT"},
            auth_required=True,
        )

        await model.add_endpoint(endpoint)

        assert "/api/users/:id" in model.endpoints
        assert model.endpoints["/api/users/:id"].auth_required is True

    @pytest.mark.asyncio
    async def test_add_endpoint_with_parameters(self):
        """Test adding endpoint with parameters."""
        model = ApplicationModel("https://api.example.com")

        param1 = ParameterModel(
            name="id",
            location="path",
            data_type="integer",
        )
        param2 = ParameterModel(
            name="username",
            location="body",
            data_type="string",
        )

        endpoint = EndpointModel(
            path="/api/users/:id",
            methods={"GET"},
            parameters=[param1, param2],
        )

        await model.add_endpoint(endpoint)

        # Should infer roles automatically
        stored_endpoint = model.endpoints["/api/users/:id"]
        assert len(stored_endpoint.parameters) == 2

        # Check role inference
        id_param = stored_endpoint.get_parameter_by_name("id")
        assert id_param is not None
        assert id_param.role == ParameterRole.IDENTITY

    @pytest.mark.asyncio
    async def test_endpoint_priority_calculation(self):
        """Test automatic priority calculation for endpoints."""
        model = ApplicationModel("https://api.example.com")

        # High priority endpoint with auth and identity param
        id_param = ParameterModel(name="user_id", location="path", data_type="integer")
        endpoint = EndpointModel(
            path="/api/users/:id",
            methods={"DELETE"},
            auth_required=True,
            parameters=[id_param],
        )

        await model.add_endpoint(endpoint)

        stored_endpoint = model.endpoints["/api/users/:id"]
        assert stored_endpoint.testing_priority > 5  # Should have elevated priority


class TestParameterInference:
    """Test parameter role inference."""

    def test_identity_parameter_inference(self):
        """Test IDENTITY role inference."""
        param = ParameterModel(
            name="user_id",
            location="path",
            data_type="integer",
        )
        param.infer_role()

        assert param.role == ParameterRole.IDENTITY
        assert len(param.testing_recommendations) > 0
        assert any("IDOR" in rec for rec in param.testing_recommendations)

    def test_credential_parameter_inference(self):
        """Test CREDENTIAL role inference."""
        param = ParameterModel(
            name="password",
            location="body",
            data_type="string",
        )
        param.infer_role()

        assert param.role == ParameterRole.CREDENTIAL
        assert any("password" in rec.lower() for rec in param.testing_recommendations)

    def test_content_parameter_inference(self):
        """Test CONTENT role inference."""
        param = ParameterModel(
            name="comment",
            location="body",
            data_type="string",
        )
        param.infer_role()

        assert param.role == ParameterRole.CONTENT
        assert any("XSS" in rec for rec in param.testing_recommendations)

    def test_query_parameter_inference(self):
        """Test QUERY role inference."""
        param = ParameterModel(
            name="search",
            location="query",
            data_type="string",
        )
        param.infer_role()

        assert param.role == ParameterRole.QUERY
        assert any("SQL" in rec or "SQLi" in rec for rec in param.testing_recommendations)

    def test_file_parameter_inference(self):
        """Test FILE role inference."""
        param = ParameterModel(
            name="file",
            location="body",
            data_type="string",
        )
        param.infer_role()

        assert param.role == ParameterRole.FILE
        assert any("LFI" in rec or "RFI" in rec for rec in param.testing_recommendations)

    def test_redirect_parameter_inference(self):
        """Test REDIRECT role inference."""
        param = ParameterModel(
            name="redirect_to",
            location="query",
            data_type="string",
        )
        param.infer_role()

        assert param.role == ParameterRole.REDIRECT
        assert any("redirect" in rec.lower() for rec in param.testing_recommendations)

    def test_callback_parameter_inference(self):
        """Test CALLBACK role inference."""
        param = ParameterModel(
            name="webhook",
            location="body",
            data_type="string",
        )
        param.infer_role()

        assert param.role == ParameterRole.CALLBACK
        assert any("SSRF" in rec for rec in param.testing_recommendations)

    def test_pagination_parameter_inference(self):
        """Test PAGINATION role inference."""
        param = ParameterModel(
            name="page",
            location="query",
            data_type="integer",
        )
        param.infer_role()

        assert param.role == ParameterRole.PAGINATION


class TestResponseAnomalyDetection:
    """Test response anomaly detection."""

    @pytest.mark.asyncio
    async def test_record_baseline_response(self):
        """Test recording baseline response patterns."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(path="/api/users")
        await model.add_endpoint(endpoint)

        response = {
            "status_code": 200,
            "content_length": 1024,
            "content_type": "application/json",
            "body": '{"users": [{"id": 1, "name": "John"}]}',
        }

        is_anomalous = await model.record_response("/api/users", response)

        # First response shouldn't be anomalous
        assert not is_anomalous

        # Should have created baseline pattern
        endpoint = model.endpoints["/api/users"]
        assert len(endpoint.response_patterns) > 0

    @pytest.mark.asyncio
    async def test_detect_status_code_anomaly(self):
        """Test detection of status code anomaly."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(path="/api/users")
        await model.add_endpoint(endpoint)

        # Establish baseline with 200
        for _ in range(3):
            baseline_response = {
                "status_code": 200,
                "content_length": 1024,
                "content_type": "application/json",
                "body": '{"users": []}',
            }
            await model.record_response("/api/users", baseline_response)

        # Test with different status code
        anomalous_response = {
            "status_code": 500,
            "content_length": 100,
            "content_type": "application/json",
            "body": '{"error": "Internal Server Error"}',
        }

        is_anomalous, reason = model.detect_response_anomaly("/api/users", anomalous_response)

        assert is_anomalous
        assert "status" in reason.lower() or "500" in reason

    @pytest.mark.asyncio
    async def test_detect_content_length_anomaly(self):
        """Test detection of content length anomaly."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(path="/api/users")
        await model.add_endpoint(endpoint)

        # Establish baseline
        baseline_response = {
            "status_code": 200,
            "content_length": 1000,
            "content_type": "application/json",
            "body": '{"users": []}',
        }
        await model.record_response("/api/users", baseline_response)

        # Response with very different length
        anomalous_response = {
            "status_code": 200,
            "content_length": 10000,  # 10x larger
            "content_type": "application/json",
            "body": "a" * 10000,
        }

        is_anomalous, reason = model.detect_response_anomaly("/api/users", anomalous_response)

        assert is_anomalous
        assert "length" in reason.lower()

    @pytest.mark.asyncio
    async def test_detect_content_type_anomaly(self):
        """Test detection of content type anomaly."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(path="/api/users")
        await model.add_endpoint(endpoint)

        # Establish JSON baseline
        baseline_response = {
            "status_code": 200,
            "content_length": 100,
            "content_type": "application/json",
            "body": '{"users": []}',
        }
        await model.record_response("/api/users", baseline_response)

        # Response with different content type
        anomalous_response = {
            "status_code": 200,
            "content_length": 100,
            "content_type": "text/html",
            "body": "<html><body>Error</body></html>",
        }

        is_anomalous, reason = model.detect_response_anomaly("/api/users", anomalous_response)

        assert is_anomalous
        assert "content type" in reason.lower()


class TestWorkflowBuilding:
    """Test workflow creation and management."""

    @pytest.mark.asyncio
    async def test_add_workflow(self):
        """Test adding a workflow to the model."""
        model = ApplicationModel("https://api.example.com")

        step1 = WorkflowStep(
            step_number=1,
            endpoint="/api/register",
            method="POST",
            description="Register new user",
            extracts={"user_id": "response.id"},
        )
        step2 = WorkflowStep(
            step_number=2,
            endpoint="/api/verify",
            method="POST",
            description="Verify email",
            required_state={"user_id": "previous"},
        )

        workflow = WorkflowModel(
            workflow_id="registration_flow",
            name="User Registration Flow",
            steps=[step1, step2],
        )

        await model.add_workflow(workflow)

        assert "registration_flow" in model.workflows
        assert len(model.workflows["registration_flow"].steps) == 2

    @pytest.mark.asyncio
    async def test_workflow_priority_calculation(self):
        """Test workflow priority calculation."""
        model = ApplicationModel("https://api.example.com")

        # Long workflow with sensitive operations
        steps = [
            WorkflowStep(i, f"/api/step{i}", "POST", f"Step {i}")
            for i in range(1, 6)
        ]

        workflow = WorkflowModel(
            workflow_id="payment_flow",
            name="Payment Processing Flow",
            steps=steps,
        )

        await model.add_workflow(workflow)

        stored_workflow = model.workflows["payment_flow"]
        # Should have elevated priority due to length and sensitive name
        assert stored_workflow.testing_priority > 5

    def test_high_value_workflow_identification(self):
        """Test identification of high-value workflows."""
        model = ApplicationModel("https://api.example.com")

        # Add normal workflow
        normal_workflow = WorkflowModel(
            workflow_id="normal",
            name="Normal Flow",
            steps=[],
            testing_priority=5,
        )
        model.workflows["normal"] = normal_workflow

        # Add high-priority workflow
        high_value_workflow = WorkflowModel(
            workflow_id="payment",
            name="Payment Flow",
            steps=[],
            testing_priority=9,
        )
        model.workflows["payment"] = high_value_workflow

        high_value = model.get_high_value_workflows(priority_min=7)

        assert len(high_value) == 1
        assert high_value[0].workflow_id == "payment"


class TestAttackSurfaceReport:
    """Test attack surface report generation."""

    @pytest.mark.asyncio
    async def test_generate_attack_surface_report(self):
        """Test generating comprehensive attack surface report."""
        model = ApplicationModel("https://api.example.com")

        # Add endpoints with different priorities
        id_param = ParameterModel(name="user_id", location="path", data_type="integer")
        high_priority_endpoint = EndpointModel(
            path="/api/users/:id",
            methods={"DELETE"},
            auth_required=True,
            parameters=[id_param],
        )
        await model.add_endpoint(high_priority_endpoint)

        low_priority_endpoint = EndpointModel(
            path="/api/health",
            methods={"GET"},
            auth_required=False,
        )
        await model.add_endpoint(low_priority_endpoint)

        report = model.generate_attack_surface_report()

        assert "Attack Surface Report" in report
        assert "https://api.example.com" in report
        assert "/api/users/:id" in report
        assert "Priority" in report

    def test_get_identity_parameters(self):
        """Test getting all identity parameters."""
        model = ApplicationModel("https://api.example.com")

        # Add endpoint with identity param
        id_param = ParameterModel(name="user_id", location="path", data_type="integer")
        id_param.role = ParameterRole.IDENTITY

        endpoint = EndpointModel(
            path="/api/users/:id",
            parameters=[id_param],
        )
        model.endpoints["/api/users/:id"] = endpoint

        # Add global identity param
        global_param = ParameterModel(name="account_id", location="query", data_type="string")
        global_param.role = ParameterRole.IDENTITY
        model.global_parameters.append(global_param)

        identity_params = model.get_identity_parameters()

        assert len(identity_params) == 2
        assert any(p.name == "user_id" for p in identity_params)
        assert any(p.name == "account_id" for p in identity_params)

    def test_get_untested_endpoints(self):
        """Test getting untested endpoints."""
        model = ApplicationModel("https://api.example.com")

        tested_endpoint = EndpointModel(path="/api/tested", tested=True, testing_priority=8)
        model.endpoints["/api/tested"] = tested_endpoint

        untested_high = EndpointModel(path="/api/untested_high", tested=False, testing_priority=9)
        model.endpoints["/api/untested_high"] = untested_high

        untested_low = EndpointModel(path="/api/untested_low", tested=False, testing_priority=3)
        model.endpoints["/api/untested_low"] = untested_low

        untested = model.get_untested_endpoints(priority_min=7)

        assert len(untested) == 1
        assert untested[0].path == "/api/untested_high"


class TestTargetSuggestions:
    """Test next target suggestions."""

    def test_suggest_next_targets_after_idor(self):
        """Test suggestions after IDOR finding."""
        model = ApplicationModel("https://api.example.com")

        # Add endpoints with identity params
        id_param1 = ParameterModel(name="user_id", location="path", data_type="integer")
        id_param1.role = ParameterRole.IDENTITY

        endpoint1 = EndpointModel(
            path="/api/users/:id",
            parameters=[id_param1],
            tested=False,
        )
        model.endpoints["/api/users/:id"] = endpoint1

        id_param2 = ParameterModel(name="order_id", location="path", data_type="integer")
        id_param2.role = ParameterRole.IDENTITY

        endpoint2 = EndpointModel(
            path="/api/orders/:id",
            parameters=[id_param2],
            tested=False,
        )
        model.endpoints["/api/orders/:id"] = endpoint2

        suggestions = model.suggest_next_targets(["IDOR"])

        # Should suggest other identity parameters
        assert len(suggestions) > 0
        assert "/api/orders/:id" in suggestions or "/api/users/:id" in suggestions

    def test_suggest_next_targets_after_sqli(self):
        """Test suggestions after SQLi finding."""
        model = ApplicationModel("https://api.example.com")

        query_param = ParameterModel(name="search", location="query", data_type="string")
        query_param.role = ParameterRole.QUERY

        endpoint = EndpointModel(
            path="/api/search",
            parameters=[query_param],
            tested=False,
        )
        model.endpoints["/api/search"] = endpoint

        suggestions = model.suggest_next_targets(["SQL Injection"])

        # Should suggest other query parameters
        assert len(suggestions) > 0

    def test_suggest_fallback_when_no_findings(self):
        """Test fallback suggestions when no findings."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(path="/api/test", testing_priority=8, tested=False)
        model.endpoints["/api/test"] = endpoint

        suggestions = model.suggest_next_targets([])

        # Should suggest highest priority untested endpoints
        assert len(suggestions) > 0
        assert "/api/test" in suggestions


class TestSerialization:
    """Test model serialization and deserialization."""

    @pytest.mark.asyncio
    async def test_to_dict(self):
        """Test converting model to dictionary."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(
            path="/api/users",
            methods={"GET"},
        )
        await model.add_endpoint(endpoint)

        data = model.to_dict()

        assert data["target"] == "https://api.example.com"
        assert "endpoints" in data
        assert "/api/users" in data["endpoints"]

    @pytest.mark.asyncio
    async def test_from_dict(self):
        """Test loading model from dictionary."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(
            path="/api/users",
            methods={"GET"},
            auth_required=True,
        )
        await model.add_endpoint(endpoint)

        data = model.to_dict()

        # Create new model from data
        loaded_model = ApplicationModel.from_dict(data)

        assert loaded_model.target == "https://api.example.com"
        assert "/api/users" in loaded_model.endpoints
        assert loaded_model.endpoints["/api/users"].auth_required is True

    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path):
        """Test saving and loading model to/from file."""
        model = ApplicationModel("https://api.example.com")

        endpoint = EndpointModel(
            path="/api/users",
            methods={"GET"},
        )
        await model.add_endpoint(endpoint)

        # Save to file
        filepath = tmp_path / "model.json"
        model.save(str(filepath))

        # Load from file
        loaded_model = ApplicationModel.load(str(filepath))

        assert loaded_model.target == model.target
        assert len(loaded_model.endpoints) == len(model.endpoints)


class TestEndpointParameters:
    """Test endpoint parameter management."""

    def test_get_parameter_by_name(self):
        """Test getting parameter by name."""
        param1 = ParameterModel(name="id", location="path", data_type="integer")
        param2 = ParameterModel(name="name", location="body", data_type="string")

        endpoint = EndpointModel(
            path="/api/users/:id",
            parameters=[param1, param2],
        )

        found_param = endpoint.get_parameter_by_name("id")
        assert found_param is not None
        assert found_param.name == "id"

        not_found = endpoint.get_parameter_by_name("nonexistent")
        assert not_found is None

    def test_add_parameter_to_endpoint(self):
        """Test adding parameter to endpoint."""
        endpoint = EndpointModel(path="/api/users")

        param = ParameterModel(name="id", location="path", data_type="integer")
        endpoint.add_parameter(param)

        assert len(endpoint.parameters) == 1
        assert endpoint.get_parameter_by_name("id") is not None

        # Should not add duplicate
        endpoint.add_parameter(param)
        assert len(endpoint.parameters) == 1


class TestResponsePattern:
    """Test ResponsePattern matching."""

    def test_response_pattern_matches(self):
        """Test response pattern matching."""
        pattern = ResponsePattern(
            status_code=200,
            content_length_range=(900, 1100),
            content_type="application/json",
            key_indicators=["users", "total"],
        )

        # Matching response
        assert pattern.matches(
            status_code=200,
            content_length=1000,
            content_type="application/json",
            body='{"users": [], "total": 0}',
        )

        # Non-matching status code
        assert not pattern.matches(
            status_code=404,
            content_length=1000,
            content_type="application/json",
            body='{"users": [], "total": 0}',
        )

        # Non-matching length
        assert not pattern.matches(
            status_code=200,
            content_length=2000,
            content_type="application/json",
            body='{"users": [], "total": 0}',
        )

        # Missing indicators
        assert not pattern.matches(
            status_code=200,
            content_length=1000,
            content_type="application/json",
            body='{"data": []}',  # Missing "users" and "total"
        )
