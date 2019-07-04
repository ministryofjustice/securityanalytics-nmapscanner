from netaddr import IPNetwork
from netaddr.core import AddrFormatError
import re

# <name> from https://tools.ietf.org/html/rfc952#page-5
ALLOWED_NAME = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

# <name> from https://tools.ietf.org/html/rfc952#page-5
UNDERSCORE_ALLOWED_NAME = re.compile(r"[_]?(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

# from https://tools.ietf.org/html/rfc3696#section-2
ALL_NUMERIC = re.compile(r"[0-9]+$")


# TODO move this to somewhere it can be used by other bits of code too later
# Lifted from https://stackoverflow.com/a/33214423
# Modified to extract compilation of regexes
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if ALL_NUMERIC.match(labels[-1]):
        return False

    # hostname should consist of at least two parts:
    if len(labels) < 2:
        return False

    # RFC2782 allows for an underscore as the first character for each part of the domain name
    host_check = all(UNDERSCORE_ALLOWED_NAME.match(label) for label in labels[:-2])
    domain_check = all(ALLOWED_NAME.match(label) for label in labels[-2:])
    return (host_check & domain_check)


# Since we pass the target string directly into the script that is run inside the ecs instance
# anyone with access to the task queue could cause our instance to execute arbitrary code.
# TODO support nmap ranges e.g. 2-6.13-55.33.2-99
def sanitise_nmap_target(target_str):
    targets = target_str.split(" ")
    sanitised = []
    # Try to parse as network descriptions (includes individual hosts)
    for target in targets:
        try:
            # not used but will throw if it is an invalid input
            IPNetwork(target)
            sanitised.append(target)
        except AddrFormatError:
            # prefix to make into a url and parse then extract only the netloc,
            #  will prevent e.g. use of semicolon in query params getting through
            if is_valid_hostname(target):
                sanitised.append(target)
            else:
                raise ValueError(
                    f"Target {target} was an invalid specification.")

    return " ".join(sanitised)
