"""Tests for FastAPI API endpoints."""

import sys
import os
from unittest.mock import patch, AsyncMock

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ===================================================================
# Health & Root Endpoints
# ===================================================================

class TestHealthAndRoot:
    """Tests for the health check and root endpoints."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_root_returns_app_info(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert data["status"] == "healthy"
        assert "version" in data


# ===================================================================
# Dashboard Stats
# ===================================================================

class TestDashboardStats:
    """Tests for GET /api/dashboard/stats."""

    @pytest.mark.asyncio
    async def test_dashboard_stats_structure(self, client):
        response = await client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        # Verify expected top-level keys
        assert "total_submissions" in data
        assert "total_complete" in data
        assert "total_failed" in data
        assert "total_analyzing" in data
        assert "submissions_by_type" in data
        assert "submissions_by_severity" in data
        assert "total_iocs" in data
        assert "total_unique_iocs" in data
        assert "avg_iocs_per_submission" in data
        assert "submissions_last_7_days" in data
        assert "top_iocs" in data
        assert "mitre_heatmap" in data
        assert "recent_findings" in data

    @pytest.mark.asyncio
    async def test_dashboard_stats_empty_db(self, client):
        """On an empty database, counts should be zero."""
        response = await client.get("/api/dashboard/stats")
        data = response.json()
        assert data["total_submissions"] == 0
        assert data["total_iocs"] == 0
        assert data["total_unique_iocs"] == 0
        assert data["avg_iocs_per_submission"] == 0.0

    @pytest.mark.asyncio
    async def test_dashboard_stats_submissions_by_type(self, client):
        """submissions_by_type should have file, url, sandbox_report keys."""
        response = await client.get("/api/dashboard/stats")
        data = response.json()
        by_type = data["submissions_by_type"]
        assert "file" in by_type
        assert "url" in by_type
        assert "sandbox_report" in by_type

    @pytest.mark.asyncio
    async def test_dashboard_stats_last_7_days(self, client):
        """submissions_last_7_days should have exactly 7 entries."""
        response = await client.get("/api/dashboard/stats")
        data = response.json()
        assert len(data["submissions_last_7_days"]) == 7
        for entry in data["submissions_last_7_days"]:
            assert "date" in entry
            assert "count" in entry


# ===================================================================
# Search IOCs
# ===================================================================

class TestSearchIOCs:
    """Tests for GET /api/search/iocs."""

    @pytest.mark.asyncio
    async def test_search_iocs_empty_results(self, client):
        response = await client.get("/api/search/iocs", params={"q": "test"})
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_search_iocs_requires_query(self, client):
        """Missing the required 'q' parameter should return 422."""
        response = await client.get("/api/search/iocs")
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_search_iocs_invalid_type(self, client):
        """An invalid IOC type filter should return 400."""
        response = await client.get(
            "/api/search/iocs",
            params={"q": "test", "type": "invalid_type"}
        )
        assert response.status_code == 400


# ===================================================================
# URL Submissions
# ===================================================================

class TestURLSubmission:
    """Tests for POST /api/submissions/url."""

    @pytest.mark.asyncio
    async def test_submit_url_creates_submission(self, client):
        """A valid URL submission should create a record and return 200."""
        # Patch trigger_analysis_workflow so it doesn't actually call n8n
        with patch("api.submissions.trigger_analysis_workflow", new_callable=AsyncMock):
            response = await client.post(
                "/api/submissions/url",
                json={"url": "https://example.com/malware.js"}
            )
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "url"
        assert data["original_url"] == "https://example.com/malware.js"
        assert data["status"] == "pending"
        assert "id" in data
        assert data["id"] > 0

    @pytest.mark.asyncio
    async def test_submit_url_invalid_url(self, client):
        """A malformed URL should be rejected."""
        response = await client.post(
            "/api/submissions/url",
            json={"url": "not-a-valid-url"}
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_submit_url_missing_body(self, client):
        """Missing request body should return 422."""
        response = await client.post("/api/submissions/url")
        assert response.status_code == 422


# ===================================================================
# Management  --  Detailed Health
# ===================================================================

class TestManagementHealth:
    """Tests for GET /api/management/health/detailed."""

    @pytest.mark.asyncio
    async def test_detailed_health_returns_structure(self, client):
        response = await client.get("/api/management/health/detailed")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "checks" in data
        checks = data["checks"]
        assert "database" in checks
        assert "total_submissions" in checks
        assert "uptime" in checks

    @pytest.mark.asyncio
    async def test_detailed_health_db_connected(self, client):
        """The database check should report connected when using the test DB."""
        response = await client.get("/api/management/health/detailed")
        data = response.json()
        assert data["checks"]["database"]["status"] == "connected"


# ===================================================================
# Management  --  Delete Submission
# ===================================================================

class TestDeleteSubmission:
    """Tests for DELETE /api/management/submissions/{id}."""

    @pytest.mark.asyncio
    async def test_delete_nonexistent_returns_404(self, client):
        response = await client.delete("/api/management/submissions/99999")
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_delete_existing_submission(self, client):
        """Create a submission then delete it."""
        with patch("api.submissions.trigger_analysis_workflow", new_callable=AsyncMock):
            create_resp = await client.post(
                "/api/submissions/url",
                json={"url": "https://to-be-deleted.com/script.ps1"}
            )
        assert create_resp.status_code == 200
        sub_id = create_resp.json()["id"]

        delete_resp = await client.delete(f"/api/management/submissions/{sub_id}")
        assert delete_resp.status_code == 200
        data = delete_resp.json()
        assert "deleted" in data["message"].lower()
        assert data["deleted_counts"]["submission"] == 1


# ===================================================================
# YARA Rules
# ===================================================================

class TestYaraRules:
    """Tests for YARA rules CRUD at /api/yara-rules/."""

    @pytest.mark.asyncio
    async def test_list_rules_empty(self, client):
        response = await client.get("/api/yara-rules/")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert data["rules"] == []

    @pytest.mark.asyncio
    async def test_create_rule(self, client):
        payload = {
            "name": "test_rule_emotet",
            "description": "Detects Emotet variant",
            "category": "malware",
            "rule_content": 'rule test_rule_emotet { strings: $a = "emotet" condition: $a }',
            "author": "test",
            "source": "unit-test",
            "tags": ["emotet", "trojan"],
            "enabled": True,
        }
        response = await client.post("/api/yara-rules/", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test_rule_emotet"
        assert data["category"] == "malware"
        assert data["enabled"] is True
        assert "id" in data
        assert data["id"] > 0

    @pytest.mark.asyncio
    async def test_create_rule_missing_rule_keyword(self, client):
        """rule_content that does not contain 'rule' should be rejected."""
        payload = {
            "name": "bad_rule",
            "rule_content": "strings: $a = 'test' condition: $a",
        }
        response = await client.post("/api/yara-rules/", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_rule_empty_name(self, client):
        """An empty name should be rejected."""
        payload = {
            "name": "   ",
            "rule_content": 'rule empty { condition: true }',
        }
        response = await client.post("/api/yara-rules/", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_duplicate_rule_name(self, client):
        """Duplicate rule names should return 409."""
        payload = {
            "name": "unique_dup_test",
            "rule_content": 'rule unique_dup_test { condition: true }',
        }
        resp1 = await client.post("/api/yara-rules/", json=payload)
        assert resp1.status_code == 201

        resp2 = await client.post("/api/yara-rules/", json=payload)
        assert resp2.status_code == 409

    @pytest.mark.asyncio
    async def test_get_rule_by_id(self, client):
        """Create then fetch a rule by ID."""
        payload = {
            "name": "fetch_test_rule",
            "rule_content": 'rule fetch_test_rule { condition: true }',
        }
        create_resp = await client.post("/api/yara-rules/", json=payload)
        rule_id = create_resp.json()["id"]

        get_resp = await client.get(f"/api/yara-rules/{rule_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["name"] == "fetch_test_rule"

    @pytest.mark.asyncio
    async def test_get_nonexistent_rule(self, client):
        response = await client.get("/api/yara-rules/99999")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rule(self, client):
        """Create then delete a rule."""
        payload = {
            "name": "delete_me_rule",
            "rule_content": 'rule delete_me_rule { condition: true }',
        }
        create_resp = await client.post("/api/yara-rules/", json=payload)
        rule_id = create_resp.json()["id"]

        delete_resp = await client.delete(f"/api/yara-rules/{rule_id}")
        assert delete_resp.status_code == 204

        # Verify it is gone
        get_resp = await client.get(f"/api/yara-rules/{rule_id}")
        assert get_resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_rules_after_creation(self, client):
        """After creating a rule, the list should include it."""
        payload = {
            "name": "list_check_rule",
            "rule_content": 'rule list_check_rule { condition: true }',
            "category": "test",
        }
        await client.post("/api/yara-rules/", json=payload)

        list_resp = await client.get("/api/yara-rules/")
        data = list_resp.json()
        assert data["total_count"] >= 1
        names = [r["name"] for r in data["rules"]]
        assert "list_check_rule" in names


# ===================================================================
# Submission List & Get
# ===================================================================

class TestSubmissionListAndGet:
    """Tests for listing and fetching submissions."""

    @pytest.mark.asyncio
    async def test_list_submissions_empty(self, client):
        response = await client.get("/api/submissions/")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_get_nonexistent_submission(self, client):
        response = await client.get("/api/submissions/99999")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_list_after_url_submit(self, client):
        """After submitting a URL, the list should contain it."""
        with patch("api.submissions.trigger_analysis_workflow", new_callable=AsyncMock):
            await client.post(
                "/api/submissions/url",
                json={"url": "https://list-test.com/payload.exe"}
            )

        list_resp = await client.get("/api/submissions/")
        assert list_resp.status_code == 200
        items = list_resp.json()
        assert len(items) >= 1
        assert any(s["original_url"] == "https://list-test.com/payload.exe" for s in items)
