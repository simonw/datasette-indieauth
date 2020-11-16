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
