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
async def test_restrict_access():
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
    paths = ("/-/actor.json", "/", "/:memory:", "/-/metadata")
    async with httpx.AsyncClient(app=app) as client:
        # All pages should 403 and show login form
        for path in paths:
            response = await client.get("http://localhost{}".format(path))
            assert response.status_code == 403
            assert '<form action="/-/indieauth" method="post">' in response.text
            assert "simonwillison.net" not in response.text

        # Now try with a signed ds_actor cookie - everything should 200
        cookies = {
            "ds_actor": datasette.sign(
                {
                    "a": {
                        "me": "https://simonwillison.net/",
                        "display": "simonwillison.net",
                    }
                },
                "actor",
            )
        }
        for path in paths:
            response2 = await client.get(
                "http://localhost{}".format(path),
                cookies=cookies,
            )
            assert response2.status_code == 200
            assert "simonwillison.net" in response2.text


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
@pytest.mark.parametrize(
    "auth_response_status,auth_response_body,expected_profile,expected_error",
    (
        # It can return JSON:
        (
            200,
            json.dumps(
                {
                    "me": "https://indieauth.simonwillison.net/index.php/author/simonw/",
                    "profile": {"email": "simon@example.net"},
                    "scope": "email",
                }
            ),
            {"email": "simon@example.net"},
            None,
        ),
        # Or it can return form-encoded data:
        (
            200,
            "me=https%3A%2F%2Findieauth.simonwillison.net%2Findex.php%2Fauthor%2Fsimonw%2F&scope=email",
            {},
            None,
        ),
        # These are errors
        (
            500,
            "error",
            None,
            "Invalid response from authorization server",
        ),
        (
            200,
            "me2=no%20me%20here",
            None,
            "Invalid authorization_code response from authorization server",
        ),
    ),
)
async def test_indieauth_flow(
    httpx_mock,
    auth_response_status,
    auth_response_body,
    expected_profile,
    expected_error,
):
    httpx_mock.add_response(
        url="https://indieauth.simonwillison.net",
        data=b'<link rel="authorization_endpoint" href="https://indieauth.simonwillison.net/auth">',
    )
    httpx_mock.add_response(
        url="https://indieauth.simonwillison.net/auth",
        method="POST",
        data=auth_response_body.encode("utf-8"),
        status_code=auth_response_status,
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
        if expected_error:
            assert response.status_code == 200
            assert expected_error in response.text
        else:
            assert response.status_code == 302
            assert response.headers["location"]
            assert "ds_actor" in response.cookies
            expected_actor = {
                "me": "https://indieauth.simonwillison.net/index.php/author/simonw/",
                "display": "indieauth.simonwillison.net/index.php/author/simonw/",
                "indieauth_scope": "email",
            }
            expected_actor.update(expected_profile)
            assert datasette.unsign(response.cookies["ds_actor"], "actor") == {
                "a": expected_actor
            }


@pytest.mark.asyncio
async def test_indieauth_done_no_params_error():
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get("http://localhost/-/indieauth/done")
        assert response.status_code == 400
        assert "Invalid state" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "me,bodies,expected_error",
    (
        (
            "https://simonwillison.net/",
            {
                "https://simonwillison.net": "No link here",
                # "https://indieauth.simonwillison.net/auth": "me=https%3A%2F%2Findieauth.simonwillison.net%2Findex.php%2Fauthor%2Fsimonw%2F&scope",
            },
            "Invalid IndieAuth identifier - no authorization_endpoint found",
        ),
        (
            "",
            {},
            "Invalid IndieAuth identifier",
        ),
    ),
)
async def test_indieauth_errors(httpx_mock, me, bodies, expected_error):
    for url, body in bodies.items():
        httpx_mock.add_response(
            url=url,
            data=body.encode("utf-8"),
        )
    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        csrftoken = (
            await client.get(
                "http://localhost/-/indieauth",
            )
        ).cookies["ds_csrftoken"]
        # Submit the form
        post_response = await client.post(
            "http://localhost/-/indieauth",
            data={"csrftoken": csrftoken, "me": me},
            cookies={"ds_csrftoken": csrftoken},
            allow_redirects=False,
        )
        assert (
            '<p class="message-error">{}'.format(expected_error) in post_response.text
        )


@pytest.mark.asyncio
async def test_invalid_ds_indieauth_cookie():
    datasette = Datasette([], memory=True)
    app = datasette.app()
    state = datasette.sign({"a": "auth-url"}, "datasette-indieauth-state")
    async with httpx.AsyncClient(app=app) as client:
        response = await client.get(
            "http://localhost/-/indieauth/done",
            params={
                "state": state,
                "code": "123",
            },
            cookies={"ds_indieauth": "this-is-bad"},
            allow_redirects=False,
        )
    assert '<p class="message-error">Invalid ds_indieauth cookie' in response.text


@pytest.mark.asyncio
async def test_invalid_url(httpx_mock):
    def raise_timeout(request, ext):
        raise httpx.ReadTimeout(f"HTTP error occurred", request=request)

    httpx_mock.add_callback(raise_timeout, url="http://invalid")

    datasette = Datasette([], memory=True)
    app = datasette.app()
    async with httpx.AsyncClient(app=app) as client:
        csrftoken = (
            await client.get(
                "http://localhost/-/indieauth",
            )
        ).cookies["ds_csrftoken"]
        # Submit the form
        post_response = await client.post(
            "http://localhost/-/indieauth",
            data={"csrftoken": csrftoken, "me": "invalid"},
            cookies={"ds_csrftoken": csrftoken},
            allow_redirects=False,
        )
    assert "Invalid IndieAuth identifier: HTTP error occurred" in post_response.text
