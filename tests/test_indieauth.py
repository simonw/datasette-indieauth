from datasette.app import Datasette
import pytest
import httpx


@pytest.fixture
def non_mocked_hosts():
    return ["localhost"]


@pytest.mark.asyncio
async def test_plugin_is_installed():
    app = Datasette([], memory=True).app()
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get("http://localhost/-/plugins.json")
        assert 200 == response.status_code
        installed_plugins = {p["name"] for p in response.json()}
        assert "datasette-indieauth" in installed_plugins


@pytest.mark.asyncio
async def test_auth_succeeds(httpx_mock):
    httpx_mock.add_response(url="https://indieauth.com/auth", data=b"me=example.com")
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get(
            "http://localhost/-/indieauth?code=code&me=example.com",
            allow_redirects=False,
        )
        # Should set a cookie
        assert response.status_code == 302
        assert datasette.unsign(response.cookies["ds_actor"], "actor") == {
            "a": {"me": "example.com", "display": "example.com"}
        }


@pytest.mark.asyncio
async def test_auth_fails(httpx_mock):
    httpx_mock.add_response(url="https://indieauth.com/auth", status_code=404)
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get(
            "http://localhost/-/indieauth?code=code&me=example.com",
            allow_redirects=False,
        )
        # Should return error
        assert response.status_code == 403
