"""
blockpages.py - Vendor-neutral block-page detection shared by all phases.

STRONG phrases only appear on security-device block/response pages (Palo Alto,
FortiGate, and generic SWG wording), so one match is enough. Weaker per-phase
markers ("blocked", "intrusion", ...) also appear on ordinary pages, so they only
count when the page also names a security vendor.
"""

STRONG_PHRASES = (
    # Palo Alto response pages
    "web page blocked",
    "access to the web page you were trying to visit has been blocked",
    "has been blocked in accordance with company policy",
    "application blocked",
    "file download blocked",
    "virus download blocked",
    # FortiGate replacement messages
    "the page you have requested has been blocked",
    "high security alert",
    "virus/malware detected",
    "fortiguard",
    # Generic SWG wording
    "blocked by your organization",
    "blocked by your administrator",
)

VENDOR_HINTS = ("forti", "palo alto", "paloalto", "pan-os", "prisma access", "zscaler",
                "netskope", "umbrella", "sophos", "check point", "checkpoint", "cloudflare gateway")


def looks_blocked(low_text, weak_markers=()):
    """True if lower-cased page text is a security-device block page."""
    if any(p in low_text for p in STRONG_PHRASES):
        return True
    return (any(m in low_text for m in weak_markers)
            and any(v in low_text for v in VENDOR_HINTS))


def names_vendor(low_text):
    return any(v in low_text for v in VENDOR_HINTS)
