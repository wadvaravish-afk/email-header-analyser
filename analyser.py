from email.header import decode_header, make_header
import re
import sys
import ipaddress
from email.parser import HeaderParser
from email.utils import parseaddr

# Matches IPv4 addresses like 203.0.113.45
IPV4_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Internal network ranges (RFC 1918 + loopback)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Free email providers often used in phishing Reply-To addresses
FREE_MAIL_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "icloud.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
}

# How much each severity counts towards the verdict
SEVERITY_SCORES = {"high": 3, "medium": 1, "info": 0}


def parse_headers(raw_text):
    parser = HeaderParser()
    return parser.parsestr(raw_text)


def is_private_ip(ip):
    addr = ipaddress.ip_address(ip)
    return any(addr in network for network in PRIVATE_NETWORKS)


def parse_received(header):
    # Headers span multiple lines, so squash all whitespace into single spaces
    text = " ".join(header.split())

    hop = {"from": None, "by": None, "ips": [], "date": None, "raw": text}

    from_match = re.search(r'\bfrom\s+(\S+)', text)
    if from_match:
        hop["from"] = from_match.group(1)

    by_match = re.search(r'\bby\s+(\S+)', text)
    if by_match:
        hop["by"] = by_match.group(1)

    # The timestamp is everything after the last semicolon
    if ";" in text:
        hop["date"] = text.rsplit(";", 1)[1].strip()

    # Only look for IPs in the "from" part (before " by ")
    from_section = text.split(" by ")[0] if from_match else ""
    for ip in re.findall(IPV4_PATTERN, from_section):
        try:
            ipaddress.ip_address(ip)  # skip invalid ones like 999.1.1.1
        except ValueError:
            continue
        hop["ips"].append({"ip": ip, "private": is_private_ip(ip)})

    return hop


def get_hops(msg):
    received = msg.get_all("Received") or []
    hops = [parse_received(h) for h in received]
    hops.reverse()  # oldest (origin) first
    return hops


def get_auth_results(msg):
    results = {"spf": None, "dkim": None, "dmarc": None}

    headers = msg.get_all("Authentication-Results") or []
    if not headers:
        return results

    # Only trust the top header, added by the receiving server
    text = " ".join(headers[0].split())

    for check in results:
        match = re.search(rf'\b{check}=(\w+)', text, re.IGNORECASE)
        if match:
            results[check] = match.group(1).lower()

    return results


def get_domain(header_value):
    """Pull the domain out of an address header like 'Name <user@domain.com>'."""
    if not header_value:
        return None
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()


def get_message_id_domain(message_id):
    """Pull the domain out of a Message-ID like <123.abc@domain.com>."""
    if not message_id:
        return None
    match = re.search(r'@([^>\s]+)', message_id)
    return match.group(1).lower() if match else None


def domains_match(a, b):
    """Treat subdomains as matching, e.g. mail.example.com and example.com."""
    if not a or not b:
        return True  # nothing to compare, so don't raise a flag
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def find_red_flags(msg, auth):
    flags = []

    def add(severity, title, detail):
        flags.append({"severity": severity, "title": title, "detail": detail})

    from_domain = get_domain(msg["From"])
    return_domain = get_domain(msg["Return-Path"])
    reply_domain = get_domain(msg["Reply-To"])
    msgid_domain = get_message_id_domain(msg["Message-ID"])

    # If DMARC passes, the domain owner has approved this sender,
    # so mismatches caused by mailing services are expected.
    dmarc_passed = auth["dmarc"] == "pass"
    mismatch_severity = "info" if dmarc_passed else "medium"
    service_note = (" This is normal when a mailing service sends on the "
                    "domain's behalf, and DMARC passed.") if dmarc_passed else ""

    # 1. From vs Return-Path
    if not domains_match(from_domain, return_domain):
        add(mismatch_severity, "From / Return-Path mismatch",
            f"From uses {from_domain}, but bounces go to {return_domain}." + service_note)

    # 2. Reply-To (still risky even if DMARC passes)
    if reply_domain and not domains_match(from_domain, reply_domain):
        if reply_domain in FREE_MAIL_DOMAINS:
            add("high", "Reply-To uses free webmail",
                f"Replies go to a {reply_domain} address instead of {from_domain}.")
        else:
            add("high", "Reply-To mismatch",
                f"Replies go to {reply_domain} instead of {from_domain}.")

    # 3. SPF
    if auth["spf"] == "fail":
        add("high", "SPF failed",
            "The sending server is not authorised to send for this domain.")
    elif auth["spf"] == "softfail":
        add("medium", "SPF softfail",
            "The sending server is probably not authorised for this domain.")

    # 4. DKIM
    if auth["dkim"] == "fail":
        add("high", "DKIM failed",
            "The signature is invalid, so the email may have been altered.")
    elif auth["dkim"] == "none":
        add("medium", "No DKIM signature",
            "The email was not signed by the sending domain.")

    # 5. DMARC
    if auth["dmarc"] == "fail":
        add("high", "DMARC failed",
            "The From domain does not align with SPF or DKIM results.")

    # 6. Message-ID
    if not domains_match(from_domain, msgid_domain):
        add(mismatch_severity, "Message-ID domain mismatch",
            f"Message-ID was created by {msgid_domain}, not {from_domain}." + service_note)

    return flags


def get_verdict(flags):
    score = sum(SEVERITY_SCORES[flag["severity"]] for flag in flags)

    if score >= 6:
        label = "Likely phishing"
    elif score >= 3:
        label = "Suspicious"
    else:
        label = "No major red flags"

    return {"score": score, "label": label}


def get_summary(msg):
    fields = ["From", "To", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID"]
    summary = {}
    for field in fields:
        value = msg[field]
        if value:
            # Decode encoded text like =?UTF-8?B?...?= into readable characters
            try:
                value = str(make_header(decode_header(value)))
            except Exception:
                pass
            value = " ".join(value.split())
        summary[field] = value
    return summary


def analyse(raw_text):
    """Run every check and return all results in one dictionary."""
    msg = parse_headers(raw_text)
    auth = get_auth_results(msg)
    flags = find_red_flags(msg, auth)
    return {
        "summary": get_summary(msg),
        "hops": get_hops(msg),
        "auth": auth,
        "flags": flags,
        "verdict": get_verdict(flags),
    }
if __name__ == "__main__":
    # Use the file given on the command line, or sample1 by default
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/sample1.txt"

    with open(path) as f:
        msg = parse_headers(f.read())

    print(f"Analysing {path}\n")

    hops = get_hops(msg)
    for i, hop in enumerate(hops, start=1):
        print(f"Hop {i}")
        print("  From:", hop["from"])
        print("  By:  ", hop["by"])
        for ip in hop["ips"]:
            label = "private" if ip["private"] else "public"
            print(f"  IP:   {ip['ip']} ({label})")
        print("  Date:", hop["date"])
        print()

    auth = get_auth_results(msg)
    print("Authentication")
    for check, result in auth.items():
        print(f"  {check.upper()}: {result or 'not found'}")

    flags = find_red_flags(msg, auth)
    print(f"\nFindings ({len(flags)})")
    for flag in flags:
        print(f"  [{flag['severity'].upper()}] {flag['title']}")
        print(f"      {flag['detail']}")

    verdict = get_verdict(flags)
    print(f"\nVerdict: {verdict['label']} (score {verdict['score']})")
