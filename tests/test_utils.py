import base64
import hashlib
import pytest
from urllib.parse import parse_qsl
from datasette_indieauth import utils
from datasette.app import Datasette


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "https://example.com/username",
        "https://example.com/users?id=100",
    ],
)
def test_verify_profile_url_valid(url):
    assert utils.verify_profile_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "example.com",
        "http://example.com",
        "mailto:user@example.com",
        "https://example.com/foo/../bar",
        "https://example.com/#me",
        "https://user:pass@example.com/",
        "https://example.com:8443/",
        "https://172.28.92.51/",
    ],
)
def test_verify_profile_url_invalid(url):
    assert not utils.verify_profile_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "https://example.com/username",
        "https://example.com/users?id=100",
        "https://example.com:8443/",
        "http://127.0.0.1/",
        "http://localhost/",
    ],
)
def test_verify_client_identifier_valid(url):
    assert utils.verify_client_identifier(url)


@pytest.mark.parametrize(
    "url",
    [
        "example.com",
        "http://example.com",
        "mailto:user@example.com",
        "https://example.com/foo/../bar",
        "https://example.com/#me",
        "https://user:pass@example.com/",
        "https://172.28.92.51/",
    ],
)
def test_verify_client_identifier_invalid(url):
    assert not utils.verify_client_identifier(url)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("example.com", "http://example.com/"),
        ("http://Example.com", "http://example.com/"),
        ("https://simonwillison.net/", "https://simonwillison.net/"),
    ],
)
def test_canonicalize_url(url, expected):
    assert utils.canonicalize_url(url) == expected


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            """
    <!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Aaron Parecki</title>
      <link rel="authorization_endpoint" href="https://aaronparecki.com/auth">
  <link rel="token_endpoint" href="https://aaronparecki.com/auth/token">
  <link rel="micropub" href="https://aaronparecki.com/micropub">
    """,
            [
                {
                    "rel": "authorization_endpoint",
                    "href": "https://aaronparecki.com/auth",
                },
                {
                    "rel": "token_endpoint",
                    "href": "https://aaronparecki.com/auth/token",
                },
                {"rel": "micropub", "href": "https://aaronparecki.com/micropub"},
            ],
        ),
        (
            # Incomplete elements should not be returned
            """
    <title>Aaron Parecki</title>
      <link rel="authorization_endpoint" href="https://aaronparecki.com/auth">
  <link rel="token_endpoint" href="https://aaronparecki.""",
            [
                {
                    "rel": "authorization_endpoint",
                    "href": "https://aaronparecki.com/auth",
                }
            ],
        ),
    ],
)
def test_parse_link_rels(html, expected):
    assert utils.parse_link_rels(html) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body,headers,expected",
    [
        # Link: rel=authorization_endpoint
        (
            "",
            [("link", '<https://aaronparecki.com/auth>; rel="authorization_endpoint"')],
            ("https://aaronparecki.com/auth", None),
        ),
        # Link: rel=authorization_endpoint and rel=token_endpoint
        (
            "",
            [
                (
                    "link",
                    '<https://aaronparecki.com/auth>; rel="authorization_endpoint"',
                ),
                ("link", '<https://aaronparecki.com/token>; rel="token_endpoint"'),
            ],
            ("https://aaronparecki.com/auth", "https://aaronparecki.com/token"),
        ),
        # HTML with those things in it
        (
            """
            <link rel="authorization_endpoint" href="https://aaronparecki.com/auth">
            <link rel="token_endpoint" href="https://aaronparecki.com/token">
            """,
            [],
            ("https://aaronparecki.com/auth", "https://aaronparecki.com/token"),
        ),
        # If headers has it, HTML is ignored
        (
            '<link rel="authorization_endpoint" href="https://aaronparecki.com/auth2">',
            [
                (
                    "link",
                    '<https://aaronparecki.com/auth>; rel="authorization_endpoint"',
                )
            ],
            ("https://aaronparecki.com/auth", None),
        ),
    ],
)
async def test_discover_endpoints(httpx_mock, body, headers, expected):
    httpx_mock.add_response(
        url="https://example.com", data=body.encode("utf-8"), headers=headers
    )
    actual = await utils.discover_endpoints("https://example.com/")
    assert actual == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("example.com", "example.com"),
        ("http://SimonWillison.net/", "simonwillison.net"),
        ("https://simonwillison.net/id", "simonwillison.net/id"),
    ],
)
def test_display_url(url, expected):
    assert utils.display_url(url) == expected


def test_challenge_verifier_pair():
    challenge, verifier = utils.challenge_verifier_pair()
    hash = utils.decode_challenge(challenge)
    assert hashlib.sha256(verifier.encode("utf-8")).digest() == hash


def test_build_authorization_url():
    datasette = Datasette([], memory=True)
    url, state, verifier = utils.build_authorization_url(
        authorization_endpoint="https://example.com/auth",
        client_id="https://simonwillison.net/login",
        redirect_uri="https://simonwillison.net/login/auth",
        me="https://simonwillison.net/",
        scope="blah",
        signing_function=datasette.sign,
    )
    assert url.split("?")[0] == "https://example.com/auth"
    bits = dict(parse_qsl(url.split("?")[1]))
    assert bits["response_type"] == "code"
    assert bits["client_id"] == "https://simonwillison.net/login"
    assert bits["redirect_uri"] == "https://simonwillison.net/login/auth"
    assert bits["me"] == "https://simonwillison.net/"
    assert bits["state"] == state
    assert bits["scope"] == "blah"
    assert bits["code_challenge_method"] == "S256"
    assert hashlib.sha256(verifier.encode("utf-8")).digest() == utils.decode_challenge(
        bits["code_challenge"]
    )


@pytest.mark.parametrize(
    "url,other_url,expected",
    [
        ("https://www.example.com/", "https://www.example.com/", True),
        ("https://www.example.com/foo", "https://www.example.com/bar", True),
        ("https://www.example.com/", "https://www.example.org/", False),
        ("https://foo.example.com/", "https://www.example.com/", False),
    ],
)
def test_verify_same_domain(url, other_url, expected):
    assert utils.verify_same_domain(url, other_url) is expected
