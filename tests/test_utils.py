import pytest
from datasette_indieauth import utils


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
            # Incomplete elements should not be returend
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
