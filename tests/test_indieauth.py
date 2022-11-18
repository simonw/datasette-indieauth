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
    ds = Datasette([], memory=True)
    response = await ds.client.get("/-/plugins.json")
    assert response.status_code == 200
    installed_plugins = {p["name"] for p in response.json()}
    assert "datasette-indieauth" in installed_plugins


@pytest.mark.asyncio
async def test_restrict_access():
    ds = Datasette(
        [],
        memory=True,
        metadata={
            "plugins": {
                "datasette-indieauth": {"restrict_access": "https://simonwillison.net/"}
            }
        },
    )
    paths = ("/-/actor.json", "/", "/_memory", "/-/metadata")
    # All pages should 403 and show login form
    for path in paths:
        response = await ds.client.get(path)
        assert response.status_code == 403
        assert '<form action="/-/indieauth" method="post">' in response.text
        assert "simonwillison.net" not in response.text

    # Now try with a signed ds_actor cookie - everything should 200
    cookies = {
        "ds_actor": ds.sign(
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
        response2 = await ds.client.get(path, cookies=cookies)
        assert response2.status_code == 200
        assert "simonwillison.net" in response2.text


@pytest.mark.asyncio
@pytest.mark.parametrize("title", [None, "This is the title"])
async def test_h_app(title):
    metadata = {}
    if title:
        metadata["title"] = title
    ds = Datasette(
        [],
        memory=True,
        metadata=metadata,
    )
    response = await ds.client.get("/-/indieauth")
    html = response.text
    items = mf2py.parse(doc=html)["items"]
    expected_title = title or "Datasette"
    assert items[0] == {
        "type": ["h-app"],
        "properties": {"name": [expected_title], "url": ["http://localhost/"]},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "me,auth_response_status,auth_response_body,expected_profile,expected_error",
    (
        # It can return JSON:
        (
            "https://indieauth.simonwillison.net/",
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
            "https://indieauth.simonwillison.net/",
            200,
            "me=https%3A%2F%2Findieauth.simonwillison.net%2Findex.php%2Fauthor%2Fsimonw%2F&scope=email",
            {},
            None,
        ),
        # These are errors
        (
            "https://indieauth.simonwillison.net/",
            500,
            "error",
            None,
            "Invalid response from authorization server",
        ),
        (
            "https://indieauth.simonwillison.net/",
            200,
            "me2=no%20me%20here",
            None,
            "Invalid authorization_code response from authorization server",
        ),
        # Security issue: returned me value must wrap original domain
        (
            "https://indieauth.simonwillison.net/",
            200,
            "me=https%3A%2F%2Findieauth.simonwillison.com%2F&scope=email",
            None,
            "&#34;me&#34; value returned by authorization server had a domain that did not match the initial URL",
        ),
    ),
)
async def test_indieauth_flow(
    httpx_mock,
    me,
    auth_response_status,
    auth_response_body,
    expected_profile,
    expected_error,
):
    httpx_mock.add_response(
        url=me,
        text='<link rel="authorization_endpoint" href="https://indieauth.simonwillison.net/auth">',
    )
    httpx_mock.add_response(
        url="https://indieauth.simonwillison.net/auth",
        method="POST",
        text=auth_response_body,
        status_code=auth_response_status,
    )
    if not expected_error:
        httpx_mock.add_response(
            url="https://indieauth.simonwillison.net/index.php/author/simonw/",
            method="GET",
            text='<link rel="authorization_endpoint" href="https://indieauth.simonwillison.net/auth">',
        )
    if "indieauth.simonwillison.com" in auth_response_body:
        httpx_mock.add_response(
            url="https://indieauth.simonwillison.com/",
            method="GET",
            text='<link rel="authorization_endpoint" href="https://indieauth.simonwillison.net/auth">',
        )
    ds = Datasette([], memory=True)
    # Get CSRF token
    csrftoken = await _get_csrftoken(ds)
    # Submit the form
    post_response = await ds.client.post(
        "/-/indieauth",
        data={"csrftoken": csrftoken, "me": me},
        cookies={"ds_csrftoken": csrftoken},
    )
    # Should set a cookie and redirect
    assert post_response.status_code == 302
    assert "ds_indieauth" in post_response.cookies
    ds_indieauth = post_response.cookies["ds_indieauth"]
    ds_indieauth_bits = ds.unsign(ds_indieauth, "datasette-indieauth-cookie")
    verifier = ds_indieauth_bits["v"]
    assert ds_indieauth_bits["m"] == me
    # Verify the location is in the right shape
    location = post_response.headers["location"]
    assert location.startswith("https://indieauth.simonwillison.net/auth?")
    querystring = location.split("?", 1)[1]
    bits = dict(urllib.parse.parse_qsl(querystring))
    assert bits["redirect_uri"] == "http://localhost/-/indieauth/done"
    assert bits["client_id"] == "http://localhost/-/indieauth"
    assert bits["me"] == me
    # Next step for user is to redirect to that page, login and redirect back
    # Simulate the redirect-back part
    response = await ds.client.get(
        "/-/indieauth/done",
        params={
            "state": bits["state"],
            "code": "123",
        },
        cookies={"ds_indieauth": ds_indieauth},
    )
    # This should have made a POST to https://indieauth.simonwillison.net/auth
    last_post_request = [r for r in httpx_mock.get_requests() if r.method == "POST"][-1]
    post_bits = dict(urllib.parse.parse_qsl(last_post_request.read().decode("utf-8")))
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
        assert ds.unsign(response.cookies["ds_actor"], "actor") == {"a": expected_actor}


@pytest.mark.asyncio
async def test_indieauth_done_no_params_error():
    ds = Datasette([], memory=True)
    response = await ds.client.get("/-/indieauth/done")
    assert response.status_code == 400
    assert "Invalid state" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "me,bodies,expected_error",
    (
        (
            "https://simonwillison.net/",
            {
                "https://simonwillison.net/": "No link here",
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
            text=body,
        )
    ds = Datasette([], memory=True)
    csrftoken = await _get_csrftoken(ds)
    # Submit the form
    post_response = await ds.client.post(
        "/-/indieauth",
        data={"csrftoken": csrftoken, "me": me},
        cookies={"ds_csrftoken": csrftoken},
    )
    assert '<p class="message-error">{}'.format(expected_error) in post_response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_cookie", ["this-is-bad", {"v": "blah"}, {"m": "blah"}, {"s": "blah"}]
)
async def test_invalid_ds_indieauth_cookie(bad_cookie):
    ds = Datasette([], memory=True)
    state = ds.sign({"a": "auth-url"}, "datasette-indieauth-state")
    if isinstance(bad_cookie, dict):
        ds_indieauth = ds.sign(bad_cookie, "datasette-indieauth-cookie")
    else:
        ds_indieauth = bad_cookie
    response = await ds.client.get(
        "/-/indieauth/done",
        params={
            "state": state,
            "code": "123",
        },
        cookies={"ds_indieauth": ds_indieauth},
    )
    assert '<p class="message-error">Invalid ds_indieauth cookie' in response.text


@pytest.mark.asyncio
async def test_invalid_url(httpx_mock):
    def raise_timeout(request):
        raise httpx.ReadTimeout(f"HTTP error occurred", request=request)

    httpx_mock.add_callback(raise_timeout, url="http://invalid/")

    ds = Datasette([], memory=True)
    csrftoken = await _get_csrftoken(ds)
    # Submit the form
    post_response = await ds.client.post(
        "/-/indieauth",
        data={"csrftoken": csrftoken, "me": "invalid"},
        cookies={"ds_csrftoken": csrftoken},
    )
    assert "Invalid IndieAuth identifier: HTTP error occurred" in post_response.text


@pytest.mark.asyncio
async def test_non_matching_authorization_endpoint(httpx_mock):
    # See https://github.com/simonw/datasette-indieauth/issues/22
    httpx_mock.add_response(
        url="https://simonwillison.net/",
        text='<link rel="authorization_endpoint" href="https://indieauth.simonwillison.net/auth">',
    )
    httpx_mock.add_response(
        url="https://indieauth.simonwillison.net/auth",
        method="POST",
        text="me=https%3A%2F%2Fsimonwillison.net%2Fme",
    )
    httpx_mock.add_response(
        url="https://simonwillison.net/me",
        text='<link rel="authorization_endpoint" href="https://example.com">',
    )
    ds = Datasette([], memory=True)
    csrftoken = await _get_csrftoken(ds)
    # Submit the form
    post_response = await ds.client.post(
        "/-/indieauth",
        data={"csrftoken": csrftoken, "me": "https://simonwillison.net/"},
        cookies={"ds_csrftoken": csrftoken},
    )
    ds_indieauth = post_response.cookies["ds_indieauth"]
    state = dict(
        urllib.parse.parse_qsl(post_response.headers["location"].split("?", 1)[1])
    )["state"]
    # ... after redirecting back again
    response = await ds.client.get(
        "/-/indieauth/done",
        params={
            "state": state,
            "code": "123",
        },
        cookies={"ds_indieauth": ds_indieauth},
    )
    # This should be an error because the authorization_endpoint did not match
    assert (
        "&#34;me&#34; value resolves to a different authorization_endpoint"
        in response.text
    )


async def _get_csrftoken(ds):
    return (await ds.client.get("/-/indieauth")).cookies["ds_csrftoken"]


@pytest.mark.asyncio
async def test_menu():
    ds = Datasette()
    index = await ds.client.get("/")
    assert '<li><a href="/-/indieauth">Sign in IndieAuth</a></li>' in index.text
