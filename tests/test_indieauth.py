from datasette.app import Datasette
import json
import pytest
import httpx
import mf2py
import urllib


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


@pytest.mark.asyncio
@pytest.mark.parametrize("title", [None, "This is the title"])
async def test_h_app(title):
    metadata = {}
    if title:
        metadata["title"] = title
    datasette = Datasette(
        [],
        memory=True,
        metadata=metadata,
    )
    response = await datasette.client.get("/-/indieauth")
    html = response.text
    items = mf2py.parse(doc=html)["items"]
    expected_title = title or "Datasette"
    assert items[0] == {
        "type": ["h-app"],
        "properties": {"name": [expected_title], "url": ["http://localhost/"]},
    }


@pytest.mark.asyncio
async def test_indieauth_succeeds(httpx_mock):
    httpx_mock.add_response(
        url="https://indieauth.simonwillison.net",
        data=b'<link rel="authorization_endpoint" href="https://indieauth.simonwillison.net/auth">',
    )
    httpx_mock.add_response(
        url="https://indieauth.simonwillison.net/auth",
        method="POST",
        data=json.dumps(
            {
                "me": "https://indieauth.simonwillison.net/index.php/author/simonw/",
                "profile": {"email": "simon@example.net"},
            }
        ).encode("utf-8"),
    )
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        # Get CSRF token
        csrftoken = (
            await client.get(
                "http://localhost/-/indieauth",
            )
        ).cookies["ds_csrftoken"]
        # Submit the form
        post_response = await client.post(
            "http://localhost/-/indieauth",
            data={"csrftoken": csrftoken, "me": "https://indieauth.simonwillison.net/"},
            cookies={"ds_csrftoken": csrftoken},
            allow_redirects=False,
        )
        # Should set a cookie and redirect
        assert post_response.status_code == 302
        assert "ds_indieauth" in post_response.cookies
        ds_indieauth = post_response.cookies["ds_indieauth"]
        verifier = datasette.unsign(ds_indieauth, "datasette-indieauth-cookie")["v"]
        # Verify the location is in the right shape
        location = post_response.headers["location"]
        assert location.startswith("https://indieauth.simonwillison.net/auth?")
        querystring = location.split("?", 1)[1]
        bits = dict(urllib.parse.parse_qsl(querystring))
        assert bits["redirect_uri"] == "http://localhost/-/indieauth/done"
        assert bits["client_id"] == "http://localhost/-/indieauth"
        assert bits["me"] == "https://indieauth.simonwillison.net/"
        # Next step for user is to redirect to that page, login and redirect back
        # Simulate the redirect-back part
        response = await client.get(
            "http://localhost/-/indieauth/done",
            params={
                "state": bits["state"],
                "code": "123",
            },
            cookies={"ds_indieauth": ds_indieauth},
            allow_redirects=False,
        )
        # This should have made a POST to https://indieauth.simonwillison.net/auth
        last_request = httpx_mock.get_requests()[-1]
        post_bits = dict(urllib.parse.parse_qsl(last_request.read().decode("utf-8")))
        assert post_bits == {
            "grant_type": "authorization_code",
            "code": "123",
            "client_id": "http://localhost/-/indieauth",
            "redirect_uri": "http://localhost/-/indieauth/done",
            "code_verifier": verifier,
        }
        # Should set cookie for "https://indieauth.simonwillison.net/index.php/author/simonw/"
        assert response.status_code == 302
        assert response.headers["location"]
        assert "ds_actor" in response.cookies
        assert datasette.unsign(response.cookies["ds_actor"], "actor") == {
            "a": {
                "me": "https://indieauth.simonwillison.net/index.php/author/simonw/",
                "display": "indieauth.simonwillison.net/index.php/author/simonw/",
                "email": "simon@example.net",
            }
        }
