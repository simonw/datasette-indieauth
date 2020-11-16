from urllib.parse import urlparse
import ipaddress


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
