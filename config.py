# Configuration file for XSS Hunter Pro

# Default scanning settings
DEFAULT_CONFIG = {
    "max_threads": 10,
    "request_delay": 100,  # milliseconds
    "timeout": 30,  # seconds
    "follow_redirects": True,
    "max_payloads_per_param": 50,
    "deep_scan": False,
    # Proxy settings
    "use_proxy": False,
    "proxy_host": "127.0.0.1",
    "proxy_port": 8080,
    # Detection settings
    "test_reflected_xss": True,
    "test_stored_xss": False,
    "test_dom_xss": True,
    "bypass_csp": True,
    "bypass_waf": True,
    # Payload settings
    "use_basic_payloads": True,
    "use_csp_bypass_payloads": True,
    "use_waf_bypass_payloads": True,
    "use_custom_payloads": False,
    # Output settings
    "log_all_requests": False,
    "save_results": True,
    "export_format": "csv",
}

# XSS severity levels
SEVERITY_LEVELS = {
    "High": "Immediate security risk - XSS can be executed",
    "Medium": "Potential security risk - Some filtering present",
    "Low": "Limited security risk - Heavy filtering but bypass possible",
    "Info": "Information disclosure - Parameter reflection detected",
}

# Common XSS injection contexts
INJECTION_CONTEXTS = {
    "html": "Plain HTML content",
    "attribute": "HTML attribute value",
    "script": "Inside JavaScript code",
    "style": "Inside CSS styles",
    "url": "URL parameter or href attribute",
    "comment": "HTML comment",
}

# File paths
PAYLOAD_FILES = {
    "basic": "payloads/xss_payloads.txt",
    "csp_bypass": "csp/payload.txt",
    "waf_bypass": "payloads/waf_bypass.txt",
}

# User agent strings for testing
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]

# Common WAF signatures
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "akamai": ["akamai", "ak-bmsc"],
    "aws_waf": ["awselb", "awsalb"],
    "imperva": ["imperva", "incap_ses"],
    "f5_bigip": ["bigip", "f5-big-ip"],
}

# CSP directive keywords
CSP_DIRECTIVES = [
    "default-src",
    "script-src",
    "object-src",
    "style-src",
    "img-src",
    "media-src",
    "frame-src",
    "font-src",
    "connect-src",
    "form-action",
    "frame-ancestors",
]
