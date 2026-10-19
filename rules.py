
"""Security rules for the Web Security Scanner."""

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Helps enforce HTTPS connections in supported browsers.",
        "recommendation": (
            "Configure HSTS on HTTPS responses after verifying "
            "that HTTPS works correctly across the site."
        ),
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Helps restrict the sources from which a page can load content.",
        "recommendation": (
            "Define a Content Security Policy appropriate for the application."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Helps prevent browsers from MIME-sniffing response content.",
        "recommendation": "Set the header to: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information browsers send.",
        "recommendation": (
            "Set a suitable policy, such as strict-origin-when-cross-origin."
        ),
    },
    "Permissions-Policy": {
        "severity": "Informational",
        "description": "Controls access to supported browser features.",
        "recommendation": (
            "Restrict browser features that the application does not need."
        ),
    },
}
