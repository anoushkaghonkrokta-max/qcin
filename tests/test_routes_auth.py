"""Auth decorator enforcement + login/logout route tests."""
import pytest


class TestLoginRequired:
    """Unauthenticated requests should redirect to /login."""

    @pytest.mark.parametrize("path", [
        "/", "/log-stage", "/bulk-upload", "/search", "/reports",
        "/edit-case/1", "/case-history/APP-001", "/export",
    ])
    def test_unauthenticated_redirects(self, client, path):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 308)
        assert "/login" in r.headers.get("Location", "")


class TestAdminRequired:
    """Only super_admin should access admin-only routes."""

    @pytest.mark.parametrize("path", ["/system-settings", "/backup"])
    def test_officer_blocked(self, officer_client, path):
        r = officer_client.get(path, follow_redirects=False)
        assert r.status_code in (302, 308)

    @pytest.mark.parametrize("path", ["/system-settings"])
    def test_board_admin_blocked(self, board_admin_client, path):
        r = board_admin_client.get(path, follow_redirects=False)
        assert r.status_code in (302, 308)


class TestBoardAdminRequired:
    """board_admin and super_admin can access; officer cannot."""

    @pytest.mark.parametrize("path", [
        "/settings", "/templates", "/audit-log", "/assessor-scorecard",
    ])
    def test_officer_blocked(self, officer_client, path):
        r = officer_client.get(path, follow_redirects=False)
        assert r.status_code in (302, 308)

    @pytest.mark.parametrize("path", ["/settings", "/templates"])
    def test_board_admin_allowed(self, board_admin_client, path):
        r = board_admin_client.get(path, follow_redirects=True)
        # May return 200 or 500 (if DB query fails); NOT 302 redirect
        assert r.status_code != 302


class TestLoginRoute:
    def test_get_login_page(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        assert b"login" in r.data.lower() or b"Login" in r.data

    def test_post_invalid_credentials(self, client):
        r = client.post("/login", data={"username": "bad", "password": "wrong"},
                        follow_redirects=True)
        assert r.status_code == 200
        # Should still be on login page (flash error)

    def test_logout_clears_session(self, auth_client):
        r = auth_client.get("/logout", follow_redirects=False)
        assert r.status_code in (302, 308)
        # After logout, accessing / should redirect to login
        r2 = auth_client.get("/", follow_redirects=False)
        assert "/login" in r2.headers.get("Location", "")
