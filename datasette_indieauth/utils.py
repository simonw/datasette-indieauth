from html.parser import HTMLParser
import httpx
import ipaddress
from urllib.parse import urlparse, urlsplit, urlunsplit


def verify_profile_url(url):
    bits = urlparse(url)
    # Profile URLs MUST have either an https or http scheme
    if bits.scheme not in ("http", "https"):
        return False
    # MUST contain a path component (/ is a valid path)
    if not bits.path:
        return False
    # MUST NOT contain single-dot or double-dot path segments
    if "/./" in bits.path or "/../" in bits.path:
        return False
    # MUST NOT contain a fragment component
    if bits.fragment:
        return False
    # MUST NOT contain a username or password component
    if "@" in bits.netloc:
        return False
    # and MUST NOT contain a port
    if ":" in bits.netloc:
        return False
    # Additionally, hostnames MUST be domain names and
    # MUST NOT be ipv4 or ipv6 addresses.
    try:
        ipaddress.ip_address(bits.netloc)
        return False
    except ValueError:
        pass
    return True


def verify_client_identifier(url):
    bits = urlparse(url)
    # Client identifier URLs MUST have either an https or http scheme
    if bits.scheme not in ("http", "https"):
        return False
    # MUST contain a path component (/ is a valid path)
    if not bits.path:
        return False
    # MUST NOT contain single-dot or double-dot path segments
    if "/./" in bits.path or "/../" in bits.path:
        return False
    # MAY contain a query string component
    # MUST NOT contain a fragment component
    if bits.fragment:
        return False
    # MUST NOT contain a username or password component
    if "@" in bits.netloc:
        return False
    # MAY contain a port
    # Additionally, hostnames MUST be domain names or a loopback interface
    # and MUST NOT be IPv4 or IPv6 addresses except for
    # IPv4 127.0.0.1 or IPv6 [::1].
    if bits.netloc == "127.0.0.1":
        return True
    # TODO: Allow IPv6 [::1]
    try:
        ipaddress.ip_address(bits.netloc)
        return False
    except ValueError:
        pass
    return True


def canonicalize_url(url):
    # For ease of use, clients MAY allow users to enter just a hostname
    # part of the URL, in which case the client MUST turn that into a
    # valid URL before beginning the IndieAuth flow, by prepending either
    # an http or https scheme and appending the path /
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    scheme, netloc, path, query, fragment = urlsplit(url)
    # Since domain names are case insensitive, the hostname component of the URL
    # MUST be compared case insensitively. Implementations SHOULD convert the
    # hostname to lowercase when storing and using URLs.
    netloc = netloc.lower()
    # If a URL with no path component is ever encountered, it MUST be
    # treated as if it had the path /.
    if not path:
        path = "/"
    return urlunsplit((scheme, netloc, path, query, fragment))


class LinkRelParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.link_rels = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "link" and "rel" in attrs:
            self.link_rels.append(attrs)


def parse_link_rels(html):
    parser = LinkRelParser()
    parser.feed(html)
    return parser.link_rels


async def discover_endpoints(url):
    authorization_endpoint = None
    token_endpoint = None
    async with httpx.AsyncClient() as client:
        async with client.stream("GET", url) as response:
            # Check response.links first
            if "authorization_endpoint" in response.links and response.links[
                "authorization_endpoint"
            ].get("url"):
                authorization_endpoint = response.links["authorization_endpoint"]["url"]
            if "token_endpoint" in response.links and response.links[
                "token_endpoint"
            ].get("url"):
                token_endpoint = response.links["token_endpoint"]["url"]
            if authorization_endpoint and token_endpoint:
                # No need to consume any HTML at all
                return authorization_endpoint, token_endpoint
            # Just pull the first chunk - chunks are 64KB
            chunk = next(response.iter_text())
    rels = parse_link_rels(chunk)
    if authorization_endpoint is None:
        matches = [r["href"] for r in rels if r["rel"] == "authorization_endpoint"]
        if matches:
            authorization_endpoint = matches[0]
    if token_endpoint is None:
        matches = [r["href"] for r in rels if r["rel"] == "token_endpoint"]
        if matches:
            token_endpoint = matches[0]
    return authorization_endpoint, token_endpoint


def display_url(url):
    # Strips http:// or https:// and path if path == "/"
    url = canonicalize_url(url)
    scheme, netloc, path, query, fragment = urlsplit(url)
    if path == "/":
        path = ""
    url = urlunsplit((scheme, netloc, path, query, fragment))
    return url.split("://")[1]
