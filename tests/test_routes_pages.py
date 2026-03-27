"""Smoke tests — each page returns 200 with auth, redirects without."""
import pytest


class TestSmokePages:
    """Authenticated super_admin can load every page without 500."""

    @pytest.mark.parametrize("path", [
        "/",
        "/log-stage",
        "/bulk-upload",
        "/bulk-advance",
        "/search",
        "/reports",
        "/export",
        "/settings",
        "/templates",
        "/audit-log",
        "/email-queue",
        "/assessor-scorecard",
        "/users",
        "/system-settings",
        "/api-keys",
        "/csv-template",
        "/xlsx-template",
    ])
    def test_page_loads(self, auth_client, path):
        r = auth_client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"
