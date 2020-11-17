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
async def test_indieauth_com_succeeds(httpx_mock):
    httpx_mock.add_response(
        url="https://indieauth.com/auth", data=b"me=https://simonwillison.net/"
    )
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get(
            "http://localhost/-/indieauth/indieauth-com-done?code=code&me=https://simonwillison.net/",
            allow_redirects=False,
        )
        # Should set a cookie
        assert response.status_code == 302
        assert datasette.unsign(response.cookies["ds_actor"], "actor") == {
            "a": {"me": "https://simonwillison.net/", "display": "simonwillison.net"}
        }


@pytest.mark.asyncio
async def test_indieauth_com_fails(httpx_mock):
    httpx_mock.add_response(
        url="https://indieauth.com/auth",
        status_code=404,
        data=b"error_description=An+error+of+some+sort",
    )
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get(
            "http://localhost/-/indieauth/indieauth-com-done?code=code&me=example.com",
            allow_redirects=False,
        )
        # Should return error
        assert response.status_code == 403
        assert "An error of some sort" in response.text


@pytest.mark.asyncio
async def test_restrict_access(httpx_mock):
    httpx_mock.add_response(
        url="https://indieauth.com/auth", data=b"me=https://simonwillison.net/"
    )
    datasette = Datasette(
        [],
        memory=True,
        metadata={
            "plugins": {
                "datasette-indieauth": {"restrict_access": "https://simonwillison.net/"}
            }
        },
    )
    app = datasette.app()
    paths = ("/", "/:memory:", "/-/metadata")
    async with httpx.AsyncClient(app=app) as client:
        # All pages should 403 and show login form
        for path in paths:
            response = await client.get("http://localhost{}".format(path))
            assert response.status_code == 403
            assert '<form action="/-/indieauth" method="post">' in response.text
            assert "simonwillison.net" not in response.text

        # Now do the login and try again
        response2 = await client.get(
            "http://localhost/-/indieauth/indieauth-com-done?code=code&me=example.com",
            allow_redirects=False,
        )
        assert response2.status_code == 302
        ds_actor = response2.cookies["ds_actor"]
        # Everything should 200 now
        for path in paths:
            response = await client.get(
                "http://localhost{}".format(path), cookies={"ds_actor": ds_actor}
            )
            assert response.status_code == 200
            assert "simonwillison.net" in response.text
