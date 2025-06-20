"""
Github Code Scanning Provider.

This provider allows Keep to interact with Github Code Scanning to fetch and manage code scanning alerts.
"""

import dataclasses
import logging
import hashlib
import uuid
from typing import Any, Dict, List, Optional

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod

logger = logging.getLogger(__name__)


@pydantic.dataclasses.dataclass
class GithubCodeScanningProviderAuthConfig:
    """Github Code Scanning authentication configuration."""

    github_token: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "GitHub Personal Access Token (PAT) for Code Scanning API access.",
            "sensitive": True,
        }
    )
    repository_owner: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Owner of the GitHub repository (e.g., 'keephq').",
        }
    )
    repository_name: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Name of the GitHub repository (e.g., 'keep').",
        }
    )


class GithubCodeScanningProvider(BaseProvider):
    """Github Code Scanning provider for fetching and managing alerts."""

    PROVIDER_DISPLAY_NAME = "GitHub Code Scanning"
    PROVIDER_CATEGORY = ["Developer Tools", "Security"]
    PROVIDER_TAGS = ["alert", "data"]
    FINGERPRINT_FIELDS = ["html_url"]

    PROVIDER_SCOPES = [
        ProviderScope(
            name="security_events",
            description="Grants read and write access to security events, including CodeQL alerts. Required for reading and updating alerts.",
            mandatory=True,
            mandatory_for_webhook=False,
            documentation_url="https://docs.github.com/en/rest/overview/permissions-required-for-github-apps?tool=curl#repository-permissions-for-code-scanning",
            alias="Code Scanning Events (Read/Write)",
        ),
        ProviderScope(
            name="admin:repo_hook",
            description="Grants full control of repository webhooks, required for webhook setup.",
            mandatory=False,
            mandatory_for_webhook=True,
            documentation_url="https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps#adminrepo_hook",
            alias="Webhook Administration",
        ),
    ]

    PROVIDER_METHODS = [
        ProviderMethod(
            name="Update Code Scanning Alert",
            func_name="update_code_scanning_alert",
            scopes=["security_events"],
            description="Update the state of a GitHub Code Scanning alert (e.g., dismiss or reopen).",
            type="action",
        ),
    ]

    BASE_GITHUB_API_URL = "https://api.github.com"

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
       
        self.repository_owner = self.authentication_config.repository_owner
        self.repository_name = self.authentication_config.repository_name

    def _get_headers(self) -> Dict[str, str]:
        """Constructs headers for GitHub API requests."""
        return {
            "Authorization": f"Bearer {self.authentication_config.github_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _make_request(
        self, method: str, url_path: str, params: Optional[Dict] = None, json_data: Optional[Dict] = None
    ) -> requests.Response:
        """Helper function to make requests to GitHub API."""
        full_url = f"{self.BASE_GITHUB_API_URL}{url_path}"
        headers = self._get_headers()
        self.logger.debug(f"Making {method} request to {full_url} with params {params} and data {json_data}")
        try:
            response = requests.request(
                method=method, url=full_url, headers=headers, params=params, json=json_data
            )
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            self.logger.error(
                f"HTTP error occurred: {e.response.status_code} - {e.response.text}"
            )
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request exception occurred: {e}")
            raise

    def validate_config(self):
        """Validates required configuration for GitHub Code Scanning provider."""
        if not self.config.authentication:
            raise ValueError("Authentication configuration is missing.")
        self.authentication_config = GithubCodeScanningProviderAuthConfig(
            **self.config.authentication
        )

    def dispose(self):
        """Cleanup any resources when provider is disposed."""
        pass

    def validate_scopes(self) -> Dict[str, Any]:
        """Validates that the provider has the required scopes."""
        scopes_status = {}
        # Validate 'security_events' scope
        try:
            self._make_request(
                method="GET",
                url_path=f"/repos/{self.repository_owner}/{self.repository_name}/code-scanning/alerts",
                params={"per_page": 1}
            )
            scopes_status["security_events"] = True
        except Exception as e:
            self.logger.warning(f"Failed to validate 'security_events' scope: {e}")
            scopes_status["security_events"] = str(e)

        # Validate 'admin:repo_hook' scope
        try:
            self._make_request(
                method="GET",
                url_path=f"/repos/{self.repository_owner}/{self.repository_name}/hooks",
                params={"per_page": 1}
            )
            scopes_status["admin:repo_hook"] = True
        except Exception as e:
            self.logger.warning(f"Failed to validate 'admin:repo_hook' scope: {e}")
            scopes_status["admin:repo_hook"] = str(e)
        
        return scopes_status

    def _format_webhook_alert(self, webhook_event: dict, default_repository_owner: str, default_repository_name: str) -> AlertDto:
        """Formats a GitHub Code Scanning webhook payload into a Keep AlertDto."""
        logger.debug("Formatting webhook payload to AlertDto.")
        
        alert_data = webhook_event.get("alert")
        if not alert_data or not isinstance(alert_data, dict):
            logger.warning(f"Webhook event missing 'alert' data or 'alert' is not a dict: {webhook_event}")
            return AlertDto(
                id=webhook_event.get("delivery_id", "unknown_webhook_event"),
                name="Malformed Webhook Event",
                source=["github_code_scanning"],
                **webhook_event
            )

        severity_mapping = {
            "note": AlertSeverity.INFO,
            "warning": AlertSeverity.WARNING,
            "error": AlertSeverity.CRITICAL,
        }

        current_status = None
        webhook_action = webhook_event.get("action")
        if webhook_action in ["created", "reopened", "reopened_by_user"]:
            current_status = AlertStatus.FIRING
        elif webhook_action in ["dismissed"]:
            current_status = AlertStatus.SUPPRESSED
        elif webhook_action in ["closed_by_user", "fixed"]:
            current_status = AlertStatus.RESOLVED
        elif "state" in alert_data:
            alert_state = alert_data.get("state")
            current_status = {
                "open": AlertStatus.FIRING,
                "dismissed": AlertStatus.RESOLVED,
                "fixed": AlertStatus.RESOLVED,
            }.get(alert_state, None)

        repository_info = webhook_event.get("repository", {})
        owner = repository_info.get("owner", {}).get("login", default_repository_owner)
        name = repository_info.get("name", default_repository_name)
        
        alert_data.pop("url", None)
        # Get hash of html_url
        id = self._create_uuid(alert_data.get("html_url"))
        return AlertDto(
            id=str(id),
            name=alert_data.get("rule", {}).get("description", "Code Scanning Alert via Webhook"),
            status=current_status,
            lastReceived=alert_data.get("updated_at") or alert_data.get("created_at"),
            severity=severity_mapping.get(alert_data.get("rule", {}).get("severity"), AlertSeverity.INFO),
            source=["github_code_scanning"],
            url=alert_data.get("html_url"),
            description=alert_data.get("most_recent_instance", {}).get("message", {}).get("text"),
            tool_name=alert_data.get("tool", {}).get("name"),
            repository_owner=owner,
            repository_name=name,
            **webhook_event,
        )

    def _format_alert(self, event: Dict[str, Any]) -> AlertDto:
        """Formats a GitHub Code Scanning alert (from API or Webhook) into a Keep AlertDto."""
        
        # Determine if it's a webhook payload
        if "action" in event and "alert" in event and "repository" in event:
            self.logger.debug("Detected webhook payload, delegating to _format_webhook_alert.")
            return self._format_webhook_alert(event, self.repository_owner, self.repository_name)
        
        # If not a webhook, assume it's a direct API alert object
        alert_data = event

        severity_mapping = {
            "note": AlertSeverity.INFO,
            "warning": AlertSeverity.WARNING,
            "error": AlertSeverity.CRITICAL,
        }
        status_mapping = {
            "open": AlertStatus.FIRING,
            "dismissed": AlertStatus.RESOLVED,
            "fixed": AlertStatus.RESOLVED,
        }
        alert_data.pop("url", None)
        id=self._create_uuid(alert_data.get("html_url"))

        return AlertDto(
            id=str(id),
            name=alert_data.get("rule", {}).get("description", "Code Scanning Alert"),
            status=status_mapping.get(alert_data.get("state"), None),
            lastReceived=alert_data.get("updated_at") or alert_data.get("created_at"),
            severity=severity_mapping.get(alert_data.get("rule", {}).get("severity"), AlertSeverity.INFO),
            source=["github_code_scanning"],
            url=alert_data.get("html_url"),
            description=alert_data.get("most_recent_instance", {}).get("message", {}).get("text"),
            tool_name=alert_data.get("tool", {}).get("name"),
            repository_owner=self.repository_owner,
            repository_name=self.repository_name,
            **alert_data,
        )

    def _get_alerts(self) -> List[AlertDto]:
        """Fetches all Code Scanning alerts for the configured repository."""
        self.logger.info(f"Fetching all Code Scanning alerts for {self.repository_owner}/{self.repository_name}")
        alerts_data = []
        page = 1
        while True:
            response = self._make_request(
                method="GET",
                url_path=f"/repos/{self.repository_owner}/{self.repository_name}/code-scanning/alerts",
                params={"per_page": 100, "page": page, "sort": "created", "direction": "desc"}
            )
            current_page_alerts = response.json()
            if not current_page_alerts:
                break
            alerts_data.extend(current_page_alerts)
            page += 1
        
        return [self._format_alert(alert) for alert in alerts_data]

    def _query(
        self,
        tool_name: Optional[str] = None,
        tool_guid: Optional[str] = None,
        ref: Optional[str] = None,
        state: Optional[str] = None,
        severity: Optional[str] = None, # Corresponds to alert.rule.severity
        # For pagination and sorting, these can be passed via kwargs
        # page: Optional[int] = None, per_page: Optional[int] = None,
        # direction: Optional[str] = None, sort: Optional[str] = None,
        # before: Optional[str] = None, after: Optional[str] = None,
        **kwargs: Any
    ) -> List[AlertDto]:
        """Queries Code Scanning alerts based on provided filters."""
        self.logger.info(f"Querying Code Scanning alerts for {self.repository_owner}/{self.repository_name}")
        
        api_params = {}
        if tool_name:
            api_params["tool_name"] = tool_name
        if tool_guid:
            api_params["tool_guid"] = tool_guid
        if ref:
            api_params["ref"] = ref
        if state:
            api_params["state"] = state
        if severity: # This filters by rule severity
            api_params["severity"] = severity
        
        
        api_params.update(kwargs)
        if "page" not in api_params:
            api_params["page"] = 1
        if "per_page" not in api_params:
            api_params["per_page"] = 100 # Max per_page
        if "sort" not in api_params:
            api_params["sort"] = "created"
        if "direction" not in api_params:
            api_params["direction"] = "desc"

        self.logger.debug(f"Querying with API parameters: {api_params}")

        alerts_data = []
        current_page = api_params.pop("page")
        
        while True:
            paginated_params = api_params.copy()
            paginated_params["page"] = current_page
            response = self._make_request(
                method="GET",
                url_path=f"/repos/{self.repository_owner}/{self.repository_name}/code-scanning/alerts",
                params=paginated_params
            )
            current_page_alerts = response.json()
            if not current_page_alerts:
                break
            alerts_data.extend(current_page_alerts)
            if len(current_page_alerts) < paginated_params.get("per_page", 100):
                break
            current_page += 1

        return [self._format_alert(alert) for alert in alerts_data]

    def setup_webhook(
        self, webhook_url: str, description: str = "KeepHQ Code Scanning Webhook", events: List[str] = None, **kwargs
    ) -> Dict[str, Any]:
        """Sets up a webhook in the GitHub repository for Code Scanning alerts."""
        self.logger.info(f"Setting up webhook for {self.repository_owner}/{self.repository_name}")
        if events is None:
            events = ["code_scanning_alert"]
        
        payload = {
            "name": "web",
            "active": True,
            "events": events,
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "insecure_ssl": "0"
            }
        }
        response = self._make_request(
            method="POST",
            url_path=f"/repos/{self.repository_owner}/{self.repository_name}/hooks",
            json_data=payload
        )
        webhook_data = response.json()
        self.logger.info(f"Webhook created successfully with ID: {webhook_data.get('id')}")
        return webhook_data

    def update_code_scanning_alert(
        self,
        alert_number: int,
        state: str,
        dismissed_reason: Optional[str] = None,
        dismissed_comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates a GitHub Code Scanning alert (e.g., dismisses or reopens it)."""
        self.logger.info(f"Updating Code Scanning alert #{alert_number} for {self.repository_owner}/{self.repository_name} to state '{state}'")
        
        if state not in ["open", "dismissed"]:
            raise ValueError("State must be either 'open' or 'dismissed'.")

        payload = {"state": state}
        if state == "dismissed":
            valid_dismissed_reasons = ["false positive", "won't fix", "used in tests"]
            if dismissed_reason not in valid_dismissed_reasons:
                raise ValueError(f"dismissed_reason must be one of {valid_dismissed_reasons}")
            payload["dismissed_reason"] = dismissed_reason
            if dismissed_comment:
                payload["dismissed_comment"] = dismissed_comment
        
        response = self._make_request(
            method="PATCH",
            url_path=f"/repos/{self.repository_owner}/{self.repository_name}/code-scanning/alerts/{alert_number}",
            json_data=payload
        )
        updated_alert_data = response.json()
        self.logger.info(f"Code Scanning alert #{alert_number} updated successfully.")
        return updated_alert_data

    @staticmethod
    def _create_uuid(html_url: str) -> str:
        """Create a UUID from the alert data."""
        md5 = hashlib.md5()
        md5.update(html_url.encode("utf-8"))
        return uuid.UUID(md5.hexdigest())

if __name__ == "__main__":
    import logging
    import os

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    # Load environment variables
    token = os.environ.get("GITHUB_PAT")
    owner = os.environ.get("GITHUB_OWNER")
    repo = os.environ.get("GITHUB_REPO")
    config = ProviderConfig(
        description="GitHub Code Scanning Provider",
        authentication={
            "github_token": token,
            "repository_owner": owner,
            "repository_name": repo,
        }
    )

    github_code_scanning_provider = GithubCodeScanningProvider(context_manager, "github_code_scanning", config)
    result = github_code_scanning_provider._query()
    print(result)
    pass
