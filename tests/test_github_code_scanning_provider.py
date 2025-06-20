from unittest.mock import MagicMock, patch
import pytest
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.github_code_scanning_provider.github_code_scanning_provider import GithubCodeScanningProvider
from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus


@pytest.fixture
def github_code_scanning_provider():
    """Create a GitHub Code Scanning provider instance for testing"""
    context_manager = ContextManager(
        tenant_id="test-tenant", workflow_id="test-workflow"
    )
    config = ProviderConfig(
        id="github-code-scanning-test",
        description="GitHub Code Scanning Provider",
        authentication={
            "github_token": "test_token_123",
            "repository_owner": "octocat",
            "repository_name": "hello-world",
        },
    )
    return GithubCodeScanningProvider(
        context_manager, provider_id="github-code-scanning-test", config=config
    )


@pytest.fixture
def mock_alerts_response():
    """Mock response for GitHub Code Scanning alerts API"""
    return [
        {
            "number": 4,
            "created_at": "2020-02-13T12:29:18Z",
            "url": "https://api.github.com/repos/octocat/hello-world/code-scanning/alerts/4",
            "html_url": "https://github.com/octocat/hello-world/code-scanning/4",
            "state": "open",
            "fixed_at": None,
            "dismissed_by": None,
            "dismissed_at": None,
            "dismissed_reason": None,
            "dismissed_comment": None,
            "rule": {
                "id": "js/zipslip",
                "severity": "error",
                "tags": ["security", "external/cwe/cwe-022"],
                "description": "Arbitrary file write during zip extraction",
                "name": "js/zipslip"
            },
            "tool": {
                "name": "CodeQL",
                "guid": None,
                "version": "2.4.0"
            },
            "most_recent_instance": {
                "ref": "refs/heads/main",
                "analysis_key": ".github/workflows/codeql-analysis.yml:CodeQL-Build",
                "category": ".github/workflows/codeql-analysis.yml:CodeQL-Build",
                "environment": "{}",
                "state": "open",
                "commit_sha": "39406e42cb832f683daa691dd652a8dc36ee8930",
                "message": {
                    "text": "This path depends on a user-provided value."
                },
                "location": {
                    "path": "spec-main/api-session-spec.ts",
                    "start_line": 917,
                    "end_line": 917,
                    "start_column": 7,
                    "end_column": 18
                },
                "classifications": ["test"]
            },
            "instances_url": "https://api.github.com/repos/octocat/hello-world/code-scanning/alerts/4/instances"
        },
        {
            "number": 3,
            "created_at": "2020-02-13T12:29:18Z",
            "url": "https://api.github.com/repos/octocat/hello-world/code-scanning/alerts/3",
            "html_url": "https://github.com/octocat/hello-world/code-scanning/3",
            "state": "dismissed",
            "fixed_at": None,
            "dismissed_by": {
                "login": "octocat",
                "id": 1,
                "node_id": "MDQ6VXNlcjE=",
                "avatar_url": "https://github.com/images/error/octocat_happy.gif",
                "gravatar_id": "",
                "url": "https://api.github.com/users/octocat",
                "html_url": "https://github.com/octocat",
                "followers_url": "https://api.github.com/users/octocat/followers",
                "following_url": "https://api.github.com/users/octocat/following{/other_user}",
                "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
                "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
                "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
                "organizations_url": "https://api.github.com/users/octocat/orgs",
                "repos_url": "https://api.github.com/users/octocat/repos",
                "events_url": "https://api.github.com/users/octocat/events{/privacy}",
                "received_events_url": "https://api.github.com/users/octocat/received_events",
                "type": "User",
                "site_admin": False
            },
            "dismissed_at": "2020-02-14T12:29:18Z",
            "dismissed_reason": "false positive",
            "dismissed_comment": "This alert is not actually correct, because there's a sanitizer included in the library.",
            "rule": {
                "id": "js/zipslip",
                "severity": "error",
                "tags": ["security", "external/cwe/cwe-022"],
                "description": "Arbitrary file write during zip extraction",
                "name": "js/zipslip"
            },
            "tool": {
                "name": "CodeQL",
                "guid": None,
                "version": "2.4.0"
            },
            "most_recent_instance": {
                "ref": "refs/heads/main",
                "analysis_key": ".github/workflows/codeql-analysis.yml:CodeQL-Build",
                "category": ".github/workflows/codeql-analysis.yml:CodeQL-Build",
                "environment": "{}",
                "state": "open",
                "commit_sha": "39406e42cb832f683daa691dd652a8dc36ee8930",
                "message": {
                    "text": "This path depends on a user-provided value."
                },
                "location": {
                    "path": "lib/ab12-gen.js",
                    "start_line": 917,
                    "end_line": 917,
                    "start_column": 7,
                    "end_column": 18
                },
                "classifications": []
            },
            "instances_url": "https://api.github.com/repos/octocat/hello-world/code-scanning/alerts/3/instances"
        }
    ]


@pytest.fixture
def mock_webhook_payload():
    """Mock webhook payload for GitHub Code Scanning alert"""
    return {
        "action": "created",
        "alert": {
            "number": 5,
            "created_at": "2023-06-15T10:30:00Z",
            "updated_at": "2023-06-15T10:30:00Z",
            "html_url": "https://github.com/octocat/hello-world/code-scanning/5",
            "state": "open",
            "fixed_at": None,
            "dismissed_by": None,
            "dismissed_at": None,
            "dismissed_reason": None,
            "dismissed_comment": None,
            "rule": {
                "id": "py/sql-injection",
                "severity": "warning",
                "tags": ["security", "external/cwe/cwe-089"],
                "description": "SQL injection vulnerability",
                "name": "py/sql-injection"
            },
            "tool": {
                "name": "CodeQL",
                "guid": "codeql-python",
                "version": "2.8.0"
            },
            "most_recent_instance": {
                "ref": "refs/heads/main",
                "analysis_key": ".github/workflows/codeql.yml:analyze",
                "category": ".github/workflows/codeql.yml:analyze",
                "environment": "{}",
                "state": "open",
                "commit_sha": "a1b2c3d4e5f6789012345678901234567890abcd",
                "message": {
                    "text": "Potential SQL injection from user input"
                },
                "location": {
                    "path": "src/database.py",
                    "start_line": 42,
                    "end_line": 42,
                    "start_column": 15,
                    "end_column": 25
                },
                "classifications": []
            }
        },
        "repository": {
            "id": 123456789,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": {
                "login": "octocat",
                "id": 1,
                "type": "User"
            }
        },
        "sender": {
            "login": "octocat",
            "id": 1,
            "type": "User"
        }
    }


@pytest.fixture
def mock_dismissed_webhook_payload():
    """Mock webhook payload for dismissed GitHub Code Scanning alert"""
    return {
        "action": "dismissed",
        "alert": {
            "number": 6,
            "created_at": "2023-06-14T09:20:00Z",
            "updated_at": "2023-06-15T14:45:00Z",
            "html_url": "https://github.com/octocat/hello-world/code-scanning/6",
            "state": "dismissed",
            "fixed_at": None,
            "dismissed_by": {
                "login": "octocat",
                "id": 1
            },
            "dismissed_at": "2023-06-15T14:45:00Z",
            "dismissed_reason": "won't fix",
            "dismissed_comment": "This is acceptable for our use case",
            "rule": {
                "id": "js/unused-local-variable",
                "severity": "note",
                "tags": ["maintainability"],
                "description": "Unused local variable",
                "name": "js/unused-local-variable"
            },
            "tool": {
                "name": "CodeQL",
                "guid": "codeql-javascript",
                "version": "2.8.0"
            },
            "most_recent_instance": {
                "ref": "refs/heads/main",
                "analysis_key": ".github/workflows/codeql.yml:analyze",
                "category": ".github/workflows/codeql.yml:analyze",
                "environment": "{}",
                "state": "dismissed",
                "commit_sha": "b1c2d3e4f5g6789012345678901234567890bcde",
                "message": {
                    "text": "Variable 'temp' is declared but never used"
                },
                "location": {
                    "path": "src/utils.js",
                    "start_line": 10,
                    "end_line": 10,
                    "start_column": 5,
                    "end_column": 9
                },
                "classifications": []
            }
        },
        "repository": {
            "id": 123456789,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": {
                "login": "octocat",
                "id": 1,
                "type": "User"
            }
        },
        "sender": {
            "login": "octocat",
            "id": 1,
            "type": "User"
        }
    }


@pytest.fixture
def mock_success_response():
    """Create a mock successful HTTP response"""
    response = MagicMock()
    response.ok = True
    response.status_code = 200
    response.raise_for_status.return_value = None
    return response


@patch("requests.request")
def test_query_alerts(mock_request, github_code_scanning_provider, mock_alerts_response, mock_success_response):
    """Test querying GitHub Code Scanning alerts"""
    # Setup mock response
    mock_success_response.json.return_value = mock_alerts_response
    mock_request.return_value = mock_success_response

    # Test basic query
    result = github_code_scanning_provider._query()

    # Verify the request was made correctly
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[1]["method"] == "GET"
    assert "/repos/octocat/hello-world/code-scanning/alerts" in call_args[1]["url"]
    assert call_args[1]["headers"]["Authorization"] == "Bearer test_token_123"

    # Verify the results
    assert len(result) == 2
    assert all(isinstance(alert, AlertDto) for alert in result)
    
    # Check first alert (open)
    first_alert = result[0]
    assert first_alert.name == "Arbitrary file write during zip extraction"
    assert first_alert.status == "firing"
    assert first_alert.severity == "critical"
    assert first_alert.source == ["github_code_scanning"]
    assert first_alert.url == "https://github.com/octocat/hello-world/code-scanning/4"
    assert first_alert.tool_name == "CodeQL"
    assert first_alert.repository_owner == "octocat"
    assert first_alert.repository_name == "hello-world"
    
    # Check second alert (dismissed)
    second_alert = result[1]
    assert second_alert.name == "Arbitrary file write during zip extraction"
    assert second_alert.status == "resolved"
    assert second_alert.severity == "critical"


@patch("requests.request")
def test_query_alerts_with_filters(mock_request, github_code_scanning_provider, mock_alerts_response, mock_success_response):
    """Test querying GitHub Code Scanning alerts with filters"""
    # Setup mock response
    mock_success_response.json.return_value = mock_alerts_response
    mock_request.return_value = mock_success_response

    # Test query with filters
    result = github_code_scanning_provider._query(
        tool_name="CodeQL",
        state="open",
        severity="error",
        ref="refs/heads/main"
    )

    # Verify the request parameters
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    params = call_args[1]["params"]
    assert params["tool_name"] == "CodeQL"
    assert params["state"] == "open"
    assert params["severity"] == "error"
    assert params["ref"] == "refs/heads/main"
    assert params["per_page"] == 100
    assert params["sort"] == "created"
    assert params["direction"] == "desc"

    # Verify results
    assert len(result) == 2


@patch("requests.request")
def test_get_alerts_with_pagination(mock_request, github_code_scanning_provider, mock_alerts_response, mock_success_response):
    """Test _get_alerts method with pagination"""
    # Setup mock responses for pagination
    first_page = mock_alerts_response[:1]  # First alert
    second_page = mock_alerts_response[1:]  # Second alert
    empty_page = []

    responses = [
        MagicMock(json=lambda: first_page),
        MagicMock(json=lambda: second_page),
        MagicMock(json=lambda: empty_page)
    ]
    
    for response in responses:
        response.ok = True
        response.status_code = 200
        response.raise_for_status.return_value = None
    
    mock_request.side_effect = responses

    # Test _get_alerts
    result = github_code_scanning_provider._get_alerts()

    # Verify multiple requests were made (pagination)
    assert mock_request.call_count == 3
    
    # Check that pagination parameters were used correctly
    first_call_params = mock_request.call_args_list[0][1]["params"]
    assert first_call_params["page"] == 1
    assert first_call_params["per_page"] == 100
    
    second_call_params = mock_request.call_args_list[1][1]["params"]
    assert second_call_params["page"] == 2
    
    # Verify results
    assert len(result) == 2
    assert all(isinstance(alert, AlertDto) for alert in result)


def test_format_alert(github_code_scanning_provider, mock_alerts_response):
    """Test _format_alert method"""
    alert_data = mock_alerts_response[0]  # Open alert
    
    result = github_code_scanning_provider._format_alert(alert_data)
    
    assert isinstance(result, AlertDto)
    assert result.name == "Arbitrary file write during zip extraction"
    assert result.status == "firing"
    assert result.severity == "critical"
    assert result.source == ["github_code_scanning"]
    assert result.url == "https://github.com/octocat/hello-world/code-scanning/4"
    assert result.description == "This path depends on a user-provided value."
    assert result.tool_name == "CodeQL"
    assert result.repository_owner == "octocat"
    assert result.repository_name == "hello-world"
    assert result.lastReceived == "2020-02-13T12:29:18.000Z"


def test_format_alert_dismissed(github_code_scanning_provider, mock_alerts_response):
    """Test _format_alert method with dismissed alert"""
    alert_data = mock_alerts_response[1]  # Dismissed alert
    
    result = github_code_scanning_provider._format_alert(alert_data)
    
    assert isinstance(result, AlertDto)
    assert result.status == "resolved"
    assert result.severity == "critical"


def test_format_webhook_alert_created(github_code_scanning_provider, mock_webhook_payload):
    """Test _format_webhook_alert method with created action"""
    result = github_code_scanning_provider._format_webhook_alert(
        mock_webhook_payload, "octocat", "hello-world"
    )
    
    assert isinstance(result, AlertDto)
    assert result.name == "SQL injection vulnerability"
    assert result.status == "firing"
    assert result.severity == "warning"
    assert result.source == ["github_code_scanning"]
    assert result.url == "https://github.com/octocat/hello-world/code-scanning/5"
    assert result.description == "Potential SQL injection from user input"
    assert result.tool_name == "CodeQL"
    assert result.repository_owner == "octocat"
    assert result.repository_name == "hello-world"
    assert result.action == "created"


def test_format_webhook_alert_dismissed(github_code_scanning_provider, mock_dismissed_webhook_payload):
    """Test _format_webhook_alert method with dismissed action"""
    result = github_code_scanning_provider._format_webhook_alert(
        mock_dismissed_webhook_payload, "octocat", "hello-world"
    )
    
    assert isinstance(result, AlertDto)
    assert result.name == "Unused local variable"
    assert result.status == "suppressed"
    assert result.severity == "info"
    assert result.action == "dismissed"


def test_format_alert_webhook_detection(github_code_scanning_provider, mock_webhook_payload):
    """Test that _format_alert correctly detects and delegates webhook payloads"""
    result = github_code_scanning_provider._format_alert(mock_webhook_payload)
    
    # Should be processed as webhook
    assert isinstance(result, AlertDto)
    assert result.action == "created"
    assert result.name == "SQL injection vulnerability"


def test_format_alert_malformed_webhook(github_code_scanning_provider):
    """Test _format_webhook_alert with malformed webhook payload"""
    malformed_payload = {
        "action": "created",
        "repository": {"owner": {"login": "test"}, "name": "repo"}
        # Missing 'alert' key
    }
    
    result = github_code_scanning_provider._format_webhook_alert(
        malformed_payload, "default_owner", "default_repo"
    )
    
    assert isinstance(result, AlertDto)
    assert result.name == "Malformed Webhook Event"
    assert result.source == ["github_code_scanning"]


@patch("requests.request")
def test_update_code_scanning_alert_dismiss(mock_request, github_code_scanning_provider, mock_success_response):
    """Test updating a code scanning alert to dismissed state"""
    # Setup mock response
    updated_alert = {"number": 4, "state": "dismissed", "dismissed_reason": "false positive"}
    mock_success_response.json.return_value = updated_alert
    mock_request.return_value = mock_success_response

    # Test dismissing an alert
    result = github_code_scanning_provider.update_code_scanning_alert(
        alert_number=4,
        state="dismissed",
        dismissed_reason="false positive",
        dismissed_comment="This is not a real issue"
    )

    # Verify the request
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[1]["method"] == "PATCH"
    assert "/repos/octocat/hello-world/code-scanning/alerts/4" in call_args[1]["url"]
    
    # Check the payload
    payload = call_args[1]["json"]
    assert payload["state"] == "dismissed"
    assert payload["dismissed_reason"] == "false positive"
    assert payload["dismissed_comment"] == "This is not a real issue"

    # Verify the result
    assert result == updated_alert


@patch("requests.request")
def test_update_code_scanning_alert_reopen(mock_request, github_code_scanning_provider, mock_success_response):
    """Test updating a code scanning alert to open state"""
    # Setup mock response
    updated_alert = {"number": 4, "state": "open"}
    mock_success_response.json.return_value = updated_alert
    mock_request.return_value = mock_success_response

    # Test reopening an alert
    result = github_code_scanning_provider.update_code_scanning_alert(
        alert_number=4,
        state="open"
    )

    # Verify the request
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    
    # Check the payload
    payload = call_args[1]["json"]
    assert payload["state"] == "open"
    assert "dismissed_reason" not in payload
    assert "dismissed_comment" not in payload

    # Verify the result
    assert result == updated_alert


def test_update_code_scanning_alert_invalid_state(github_code_scanning_provider):
    """Test update_code_scanning_alert with invalid state"""
    with pytest.raises(ValueError, match="State must be either 'open' or 'dismissed'"):
        github_code_scanning_provider.update_code_scanning_alert(
            alert_number=4,
            state="invalid"
        )


def test_update_code_scanning_alert_invalid_dismissed_reason(github_code_scanning_provider):
    """Test update_code_scanning_alert with invalid dismissed_reason"""
    with pytest.raises(ValueError, match="dismissed_reason must be one of"):
        github_code_scanning_provider.update_code_scanning_alert(
            alert_number=4,
            state="dismissed",
            dismissed_reason="invalid reason"
        )


@patch("requests.request")
def test_setup_webhook(mock_request, github_code_scanning_provider, mock_success_response):
    """Test setting up a webhook"""
    # Setup mock response
    webhook_data = {
        "id": 12345,
        "name": "web",
        "active": True,
        "events": ["code_scanning_alert"],
        "config": {
            "url": "https://example.com/webhook",
            "content_type": "json"
        }
    }
    mock_success_response.json.return_value = webhook_data
    mock_request.return_value = mock_success_response

    # Test webhook setup
    result = github_code_scanning_provider.setup_webhook(
        webhook_url="https://example.com/webhook",
        description="Test webhook"
    )

    # Verify the request
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[1]["method"] == "POST"
    assert "/repos/octocat/hello-world/hooks" in call_args[1]["url"]
    
    # Check the payload
    payload = call_args[1]["json"]
    assert payload["name"] == "web"
    assert payload["active"] is True
    assert payload["events"] == ["code_scanning_alert"]
    assert payload["config"]["url"] == "https://example.com/webhook"
    assert payload["config"]["content_type"] == "json"

    # Verify the result
    assert result == webhook_data


@patch("requests.request")
def test_validate_scopes(mock_request, github_code_scanning_provider):
    """Test validate_scopes method"""
    # Mock successful responses for both scopes
    success_response = MagicMock()
    success_response.raise_for_status.return_value = None
    mock_request.return_value = success_response

    result = github_code_scanning_provider.validate_scopes()

    # Should make two requests to validate both scopes
    assert mock_request.call_count == 2
    
    # Check that both scopes are validated as True
    assert result["security_events"] is True
    assert result["admin:repo_hook"] is True

    # Verify the correct endpoints were called
    call_urls = [call[1]["url"] for call in mock_request.call_args_list]
    assert any("/code-scanning/alerts" in url for url in call_urls)
    assert any("/hooks" in url for url in call_urls)