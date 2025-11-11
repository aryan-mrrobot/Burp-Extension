# -*- coding: utf-8 -*-
import re
import time
import threading

# Try to import Java classes, but handle gracefully if not in Jython
try:
    from java.net import URL
    from burp import IHttpRequestResponse

    JAVA_AVAILABLE = True
except ImportError:
    JAVA_AVAILABLE = False

    # Define dummy classes for testing outside Burp
    class URL:
        def __init__(self, url_string):
            self.url_string = url_string

    class IHttpRequestResponse:
        pass


class XSSScanner:
    def __init__(self, callbacks, payload_manager):
        self._callbacks = callbacks
        # Handle None callbacks gracefully for testing
        if callbacks:
            self._helpers = callbacks.getHelpers()
        else:
            self._helpers = None
        self.payload_manager = payload_manager
        self.is_scanning = False
        self.scan_thread = None

        # XSS detection patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r'javascript:.*?["\']',
            r'on\w+\s*=\s*["\'][^"\']*["\']',
            r'<iframe[^>]*src\s*=\s*["\']javascript:',
            r"<img[^>]*onerror\s*=",
            r"<svg[^>]*onload\s*=",
            r"eval\s*\(",
            r"alert\s*\(",
            r"prompt\s*\(",
            r"confirm\s*\(",
        ]

        # Reflection patterns
        self.reflection_patterns = [
            r"<[^>]*{payload}[^>]*>",
            r"{payload}",
            r'["\'][^"\']*{payload}[^"\']*["\']',
            r'javascript:[^"\']*{payload}',
        ]

    def scan_url(self, url, ui_tab=None):
        """Main scanning function"""
        self.is_scanning = True

        try:
            print("=== XSS SCANNER DEBUG: Starting scan_url() ===")
            if ui_tab:
                ui_tab.updateStatus("Starting scan for: " + url)
                ui_tab.setProgress(0, "Initializing...")
                ui_tab.addBackendLog("Scanner initialization started", "INFO")
                ui_tab.addBackendLog("DEBUG: scan_url() method called", "DEBUG")

            print("DEBUG: URL received: " + str(url))

            # Parse URL and extract parameters
            if not url.startswith("http"):
                url = "http://" + url
                print("DEBUG: Added http:// protocol")
                if ui_tab:
                    ui_tab.addBackendLog(
                        "Added http:// protocol to URL: " + url, "INFO"
                    )

            if ui_tab:
                ui_tab.addDiscoveredUrl(url, info="Starting scan")
                ui_tab.addBackendLog("URL parsing: " + url, "INFO")
            print("Scanning URL: " + url)
            print("DEBUG: Creating URL object...")

            try:
                parsed_url = URL(url)
                print(
                    "DEBUG: URL parsed successfully - Host: "
                    + str(parsed_url.getHost())
                )
                if ui_tab:
                    ui_tab.addBackendLog(
                        "DEBUG: URL parsed - Host: " + str(parsed_url.getHost()),
                        "DEBUG",
                    )
            except Exception as e:
                print("ERROR: Failed to parse URL: " + str(e))
                if ui_tab:
                    ui_tab.addBackendLog(
                        "ERROR: Failed to parse URL: " + str(e), "ERROR"
                    )
                return

            print("DEBUG: Checking Burp helpers...")
            # Build initial request
            if self._helpers:
                print("DEBUG: Burp helpers available, building request...")
                if ui_tab:
                    ui_tab.addBackendLog(
                        "DEBUG: Building HTTP request for baseline scan", "DEBUG"
                    )
                try:
                    request = self._helpers.buildHttpRequest(parsed_url)
                    print("DEBUG: HTTP request built successfully")
                    if ui_tab:
                        ui_tab.addBackendLog(
                            "Built HTTP request for baseline scan", "INFO"
                        )
                except Exception as e:
                    print("ERROR: Failed to build HTTP request: " + str(e))
                    if ui_tab:
                        ui_tab.addBackendLog(
                            "ERROR: Failed to build HTTP request: " + str(e), "ERROR"
                        )
                    return
            else:
                error_msg = "Warning: Burp helpers not available, scanner will not work properly"
                print(error_msg)
                if ui_tab:
                    ui_tab.addBackendLog(error_msg, "ERROR")
                return

            print("DEBUG: About to send baseline request...")
            # Send initial request to get baseline response
            if ui_tab:
                ui_tab.addBackendLog(
                    "Sending baseline request to " + parsed_url.getHost(), "INFO"
                )
                ui_tab.addHttpTraffic("GET", url)
                ui_tab.addBackendLog("DEBUG: About to call makeHttpRequest()", "DEBUG")

            try:
                print("DEBUG: Creating HTTP service...")
                http_service = self._helpers.buildHttpService(
                    parsed_url.getHost(),
                    parsed_url.getPort(),
                    parsed_url.getProtocol() == "https",
                )
                print("DEBUG: HTTP service created, making request with timeout...")

                # Use timeout wrapper for baseline request too
                response = self._send_request_with_timeout(
                    request, http_service, ui_tab, "baseline"
                )

                if not response:
                    print("ERROR: Baseline request failed or timed out")
                    if ui_tab:
                        ui_tab.addBackendLog(
                            "ERROR: Baseline request failed or timed out", "ERROR"
                        )
                        ui_tab.updateStatus(
                            "Baseline request failed - cannot continue scan"
                        )
                    return

                print("DEBUG: Baseline HTTP request completed successfully!")

                if ui_tab:
                    ui_tab.addBackendLog("DEBUG: Baseline request successful", "DEBUG")
            except Exception as e:
                print("ERROR: HTTP request failed: " + str(e))
                if ui_tab:
                    ui_tab.addBackendLog(
                        "ERROR: HTTP request failed: " + str(e), "ERROR"
                    )
                return

            print("DEBUG: Starting response analysis...")
            if ui_tab:
                ui_tab.updateStatus("Baseline request completed")
                ui_tab.setProgress(10, "Analyzing response...")
                ui_tab.addBackendLog("Baseline request completed successfully", "INFO")

            # Analyze the response
            print("DEBUG: Analyzing response...")
            response_info = self._helpers.analyzeResponse(response.getResponse())
            print("DEBUG: Response analysis completed")

            if ui_tab:
                ui_tab.addHttpTraffic(
                    "GET", url, response_info.getStatusCode() if response else None
                )
            headers = response_info.getHeaders()
            body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response.getResponse())[
                body_offset:
            ]

            print("DEBUG: Response body extracted, length: " + str(len(response_body)))

            if ui_tab:
                ui_tab.addBackendLog(
                    "Response analysis: "
                    + str(len(headers))
                    + " headers, "
                    + str(len(response_body))
                    + " bytes body",
                    "INFO",
                )

            # Extract and analyze CSP
            csp_header = self._extract_csp_header(headers)
            csp_analysis = self._analyze_csp(csp_header)

            # Send CSP analysis to UI
            if ui_tab:
                csp_issues = []
                if not csp_header:
                    csp_issues.append("missing-csp: No Content Security Policy found")
                else:
                    # Detailed CSP analysis
                    if "'unsafe-inline'" in csp_header:
                        csp_issues.append(
                            "unsafe-inline: Allows inline scripts and styles"
                        )
                    if "'unsafe-eval'" in csp_header:
                        csp_issues.append(
                            "unsafe-eval: Allows eval() and similar functions"
                        )
                    if "data:" in csp_header:
                        csp_issues.append("data-uri: Allows data: URIs")
                    if "script-src" not in csp_header:
                        csp_issues.append(
                            "missing-script-src: script-src directive missing"
                        )
                    if "object-src" not in csp_header:
                        csp_issues.append(
                            "missing-object-src: object-src directive missing"
                        )
                    if "base-uri" not in csp_header:
                        csp_issues.append(
                            "missing-base-uri: base-uri directive missing"
                        )

                ui_tab.addCSPAnalysis(url, csp_header, csp_issues)
                ui_tab.updateStatus(
                    "CSP Analysis: "
                    + str(len(csp_analysis))
                    + " potential bypasses found"
                )

            # Detect WAF
            waf_info = self._detect_waf(headers, response_body)
            if waf_info:
                if ui_tab:
                    ui_tab.updateStatus("WAF Detected: " + ", ".join(waf_info))
                    ui_tab.addBackendLog(
                        "WAF Detection: " + ", ".join(waf_info), "WARN"
                    )
            else:
                if ui_tab:
                    ui_tab.addBackendLog("No WAF detected", "INFO")

            print("DEBUG: Starting parameter extraction...")
            # Extract parameters from URL and forms
            parameters = self._extract_parameters(request, response_body)
            print(
                "DEBUG: Parameter extraction completed. Found "
                + str(len(parameters))
                + " parameters"
            )

            # Send endpoint discovery info to UI
            if ui_tab and parameters:
                param_names = [p["name"] for p in parameters]
                forms_info = [p for p in parameters if p["type"] == "form"]
                ui_tab.addEndpointInfo(url, param_names, forms_info)

            if ui_tab:
                ui_tab.updateStatus(
                    "Found " + str(len(parameters)) + " parameters to test"
                )
                ui_tab.setProgress(20, "Testing parameters...")
                ui_tab.addBackendLog(
                    "Parameter extraction completed: "
                    + str(len(parameters))
                    + " parameters found",
                    "INFO",
                )
                for param in parameters:
                    ui_tab.addBackendLog(
                        "Parameter: "
                        + param["name"]
                        + " ("
                        + param["type"]
                        + ") = "
                        + param["value"],
                        "DEBUG",
                    )

            # Test each parameter
            total_params = len(parameters)
            if total_params == 0:
                if ui_tab:
                    ui_tab.updateStatus("No parameters found to test")
                    ui_tab.setProgress(100, "Scan completed - no parameters")
                return

            print(
                "Starting parameter testing loop for "
                + str(total_params)
                + " parameters"
            )
            for i, param in enumerate(parameters):
                if not self.is_scanning:
                    print("Scan stopped by user during parameter testing")
                    break

                progress = 20 + (i * 60 // total_params)
                if ui_tab:
                    ui_tab.setProgress(progress, "Testing parameter: " + param["name"])

                print(
                    "Testing parameter "
                    + str(i + 1)
                    + "/"
                    + str(total_params)
                    + ": "
                    + param["name"]
                )

                # Add timeout for individual parameter testing
                param_start_time = time.time()
                self._test_parameter(url, param, csp_analysis, waf_info, ui_tab)
                param_duration = time.time() - param_start_time

                print(
                    "Parameter '"
                    + param["name"]
                    + "' testing completed in "
                    + str(round(param_duration, 2))
                    + " seconds"
                )

                # Safety check - if a single parameter takes too long, skip remaining
                if param_duration > 300:  # 5 minutes per parameter max
                    if ui_tab:
                        ui_tab.updateStatus(
                            "Parameter testing timeout - skipping remaining parameters"
                        )
                    print("Parameter testing timeout - stopping scan")
                    break

                # Small delay between parameters
                time.sleep(0.1)

            print("Parameter testing loop completed")

            if ui_tab:
                ui_tab.setProgress(100, "Scan completed")
                ui_tab.updateStatus("Scan completed successfully")

        except Exception as e:
            if ui_tab:
                ui_tab.updateStatus("Scan error: " + str(e))
        finally:
            self.is_scanning = False

    def _extract_parameters(self, request, response_body):
        """Extract parameters from request and response"""
        print("DEBUG: _extract_parameters() called")
        parameters = []

        print("DEBUG: Analyzing request for URL parameters...")
        # Extract URL parameters
        request_info = self._helpers.analyzeRequest(request)
        url = request_info.getUrl()
        print("DEBUG: Request analysis completed, URL: " + str(url))

        if url.getQuery():
            print("DEBUG: Found query string: " + str(url.getQuery()))
            query_params = url.getQuery().split("&")
            print("DEBUG: Split into " + str(len(query_params)) + " query parameters")
            for param in query_params:
                if "=" in param:
                    name, value = param.split("=", 1)
                    print("DEBUG: Found URL parameter: " + name + " = " + value)
                    parameters.append(
                        {
                            "name": name,
                            "value": value,
                            "type": "url",
                            "location": "query",
                        }
                    )
        else:
            print("DEBUG: No query string found")

        print("DEBUG: Checking for POST parameters...")
        # Extract POST parameters
        if request_info.getMethod() == "POST":
            print("DEBUG: This is a POST request")
            body_offset = request_info.getBodyOffset()
            body = self._helpers.bytesToString(request)[body_offset:]

            # Parse form data
            if "application/x-www-form-urlencoded" in str(request_info.getHeaders()):
                print("DEBUG: Found form-encoded POST data")
                form_params = body.split("&")
                for param in form_params:
                    if "=" in param:
                        name, value = param.split("=", 1)
                        print("DEBUG: Found POST parameter: " + name + " = " + value)
                        parameters.append(
                            {
                                "name": name,
                                "value": value,
                                "type": "post",
                                "location": "body",
                            }
                        )
        else:
            print("DEBUG: Not a POST request, method: " + str(request_info.getMethod()))

        print("DEBUG: Extracting form inputs from response HTML...")
        # Extract form inputs from response
        form_inputs = self._extract_form_inputs(response_body)
        print("DEBUG: Found " + str(len(form_inputs)) + " form inputs")
        for input_param in form_inputs:
            if input_param not in [p["name"] for p in parameters]:
                print("DEBUG: Adding form input parameter: " + input_param)
                parameters.append(
                    {
                        "name": input_param,
                        "value": "",
                        "type": "form",
                        "location": "form",
                    }
                )

        print(
            "DEBUG: _extract_parameters() completed with "
            + str(len(parameters))
            + " total parameters"
        )
        return parameters

    def _extract_form_inputs(self, html):
        """Extract form input names from HTML"""
        inputs = []

        # Find all input tags
        input_pattern = r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']'
        matches = re.finditer(input_pattern, html, re.IGNORECASE)
        for match in matches:
            inputs.append(match.group(1))

        # Find textarea tags
        textarea_pattern = r'<textarea[^>]+name\s*=\s*["\']([^"\']+)["\']'
        matches = re.finditer(textarea_pattern, html, re.IGNORECASE)
        for match in matches:
            inputs.append(match.group(1))

        # Find select tags
        select_pattern = r'<select[^>]+name\s*=\s*["\']([^"\']+)["\']'
        matches = re.finditer(select_pattern, html, re.IGNORECASE)
        for match in matches:
            inputs.append(match.group(1))

        return inputs

    def _test_parameter(self, base_url, param, csp_analysis, waf_info, ui_tab=None):
        """Test a specific parameter for XSS"""
        param_name = param["name"]

        if ui_tab:
            ui_tab.updateStatus("Testing parameter: " + param_name)
            ui_tab.addBackendLog(
                "Starting parameter test: " + param_name + " (" + param["type"] + ")",
                "INFO",
            )

        # Get appropriate payloads based on context and WAF
        payloads = self._get_test_payloads(csp_analysis, waf_info)

        if ui_tab:
            ui_tab.addBackendLog(
                "Generated "
                + str(len(payloads))
                + " test payloads for parameter "
                + param_name,
                "INFO",
            )

        print(
            "Testing parameter '"
            + param_name
            + "' with "
            + str(len(payloads))
            + " payloads"
        )

        for i, payload in enumerate(payloads):
            if not self.is_scanning:
                print("Scan stopped by user")
                break

            try:
                print(
                    "Testing payload "
                    + str(i + 1)
                    + "/"
                    + str(len(payloads))
                    + ": "
                    + payload[:50]
                )

                if ui_tab:
                    ui_tab.addBackendLog(
                        "Testing payload "
                        + str(i + 1)
                        + "/"
                        + str(len(payloads))
                        + ": "
                        + payload[:30],
                        "DEBUG",
                    )

                # Create test request
                test_request = self._create_test_request(base_url, param, payload)

                if ui_tab:
                    ui_tab.addBackendLog(
                        "Created test request for parameter " + param_name, "DEBUG"
                    )

                # Send request with timeout
                response = self._send_request(test_request, ui_tab)

                if response:
                    print("Response received, analyzing...")
                    if ui_tab:
                        ui_tab.addBackendLog(
                            "Response received, analyzing for XSS", "DEBUG"
                        )

                    # Analyze response for XSS
                    result = self._analyze_xss_response(response, payload, param_name)

                    if result:
                        # XSS found!
                        print(
                            "XSS FOUND! Parameter: "
                            + param_name
                            + ", Payload: "
                            + payload
                        )
                        if ui_tab:
                            ui_tab.addBackendLog(
                                "XSS VULNERABILITY FOUND in "
                                + param_name
                                + " with payload: "
                                + payload[:30],
                                "WARN",
                            )
                            ui_tab.addResult(
                                base_url,
                                param_name,
                                payload,
                                result["type"],
                                result["severity"],
                                result["csp_info"],
                                "Vulnerable",
                            )
                            ui_tab.updateStatus("XSS found in parameter: " + param_name)

                        # Log to Burp
                        self._log_finding(base_url, param_name, payload, result)
                        break  # Found XSS, move to next parameter
                    else:
                        print("No XSS detected in response")
                        if ui_tab:
                            ui_tab.addBackendLog(
                                "No XSS detected in response for payload " + str(i + 1),
                                "DEBUG",
                            )
                else:
                    print("No response received (timeout or error)")
                    if ui_tab:
                        ui_tab.addBackendLog(
                            "No response received (timeout or error) for payload "
                            + str(i + 1),
                            "WARN",
                        )

            except Exception as e:
                print("Error testing payload: " + str(e))
                if ui_tab:
                    ui_tab.updateStatus("Error testing payload: " + str(e))

            # Small delay between requests to avoid overwhelming the server
            time.sleep(0.1)

        print("Completed testing parameter: " + param_name)

    def _get_test_payloads(self, csp_analysis, waf_info):
        """Get appropriate test payloads based on analysis"""
        payloads = []

        # Start with basic payloads
        payloads.extend(self.payload_manager.get_payloads("basic")[:10])

        # Add CSP bypass payloads if CSP is present
        if csp_analysis:
            payloads.extend(self.payload_manager.get_payloads("csp_bypass")[:10])

        # Add WAF bypass payloads if WAF is detected
        if waf_info:
            payloads.extend(self.payload_manager.get_payloads("waf_bypass")[:10])

        # Add context-specific payloads
        context_payloads = [
            # HTML context
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            # Attribute context
            '" onmouseover="alert(\'XSS\')" "',
            "' onfocus='alert(\"XSS\")' '",
            # Script context
            '</script><script>alert("XSS")</script>',
            '\';alert("XSS");//',
            # URL context
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
        ]
        payloads.extend(context_payloads)

        return payloads[:50]  # Limit to 50 payloads for performance

    def _create_test_request(self, base_url, param, payload):
        """Create HTTP request with XSS payload"""
        parsed_url = URL(base_url)

        if param["type"] == "url":
            # Modify URL parameter
            query = parsed_url.getQuery() if parsed_url.getQuery() else ""

            # Replace or add parameter
            if param["name"] + "=" in query:
                # Replace existing parameter
                pattern = param["name"] + r"=[^&]*"
                new_query = re.sub(pattern, param["name"] + "=" + payload, query)
            else:
                # Add new parameter
                new_query = (
                    query + ("&" if query else "") + param["name"] + "=" + payload
                )

            # Construct new URL
            new_url = parsed_url.getProtocol() + "://" + parsed_url.getHost()
            if (
                parsed_url.getPort() != -1
                and parsed_url.getPort() != 80
                and parsed_url.getPort() != 443
            ):
                new_url += ":" + str(parsed_url.getPort())
            new_url += parsed_url.getPath()
            if new_query:
                new_url += "?" + new_query

            return self._helpers.buildHttpRequest(URL(new_url))

        elif param["type"] == "post":
            # Create POST request with modified parameter
            request = self._helpers.buildHttpRequest(parsed_url)
            request_info = self._helpers.analyzeRequest(request)

            # Modify POST body
            body_offset = request_info.getBodyOffset()
            headers = request_info.getHeaders()

            # Create new body with payload
            post_data = param["name"] + "=" + payload

            # Update Content-Length header
            updated_headers = []
            for header in headers:
                if header.lower().startswith("content-length:"):
                    updated_headers.append("Content-Length: " + str(len(post_data)))
                else:
                    updated_headers.append(header)

            return self._helpers.buildHttpMessage(
                updated_headers, self._helpers.stringToBytes(post_data)
            )

        else:
            # Default to GET request modification
            return self._helpers.buildHttpRequest(parsed_url)

    def _send_request_with_timeout(
        self, request, http_service, ui_tab=None, request_type="test"
    ):
        """Send HTTP request with timeout handling"""
        import threading

        print("DEBUG: Starting " + request_type + " request with timeout...")

        result = [None]
        exception = [None]

        def make_request():
            try:
                print("DEBUG: Thread starting " + request_type + " request...")
                result[0] = self._callbacks.makeHttpRequest(http_service, request)
                print(
                    "DEBUG: Thread completed " + request_type + " request successfully"
                )
            except Exception as e:
                print(
                    "DEBUG: Thread exception in " + request_type + " request: " + str(e)
                )
                exception[0] = e

        # Run request in thread with timeout
        request_thread = threading.Thread(target=make_request)
        request_thread.daemon = True
        request_thread.start()

        print("DEBUG: Waiting for " + request_type + " request (10 second timeout)...")
        request_thread.join(10)  # 10 second timeout for baseline

        if request_thread.is_alive():
            print("ERROR: " + request_type + " request timed out after 10 seconds")
            if ui_tab:
                ui_tab.addBackendLog(
                    request_type + " request timed out after 10 seconds", "ERROR"
                )
            return None

        if exception[0]:
            print("ERROR: " + request_type + " request failed: " + str(exception[0]))
            if ui_tab:
                ui_tab.addBackendLog(
                    request_type + " request failed: " + str(exception[0]), "ERROR"
                )
            return None

        print("DEBUG: " + request_type + " request completed successfully")
        return result[0]

    def _send_request(self, request, ui_tab=None):
        """Send HTTP request and return response with timeout handling"""
        try:
            request_info = self._helpers.analyzeRequest(request)
            url = request_info.getUrl()

            http_service = self._helpers.buildHttpService(
                url.getHost(), url.getPort(), url.getProtocol() == "https"
            )

            # Add timeout handling
            print("Sending request to: " + url.toString())

            if ui_tab:
                ui_tab.addHttpTraffic(request_info.getMethod(), url.toString())
                ui_tab.addBackendLog(
                    "Sending "
                    + request_info.getMethod()
                    + " request to: "
                    + url.toString(),
                    "DEBUG",
                )

            # Create a timeout wrapper for the request
            import threading

            result = [None]
            exception = [None]

            def make_request():
                try:
                    result[0] = self._callbacks.makeHttpRequest(http_service, request)
                except Exception as e:
                    exception[0] = e

            # Run request in thread with timeout
            request_thread = threading.Thread(target=make_request)
            request_thread.daemon = True
            request_thread.start()
            request_thread.join(30)  # 30 second timeout

            if request_thread.is_alive():
                print("Request timed out after 30 seconds")
                if ui_tab:
                    ui_tab.addBackendLog("Request timed out after 30 seconds", "WARN")
                    ui_tab.addHttpTraffic(
                        request_info.getMethod(),
                        url.toString(),
                        error="Timeout after 30s",
                    )
                return None

            if exception[0]:
                print("Request failed: " + str(exception[0]))
                if ui_tab:
                    ui_tab.addBackendLog(
                        "Request failed: " + str(exception[0]), "ERROR"
                    )
                    ui_tab.addHttpTraffic(
                        request_info.getMethod(),
                        url.toString(),
                        error=str(exception[0]),
                    )
                return None

            print("Request completed successfully")
            if ui_tab:
                ui_tab.addBackendLog("Request completed successfully", "DEBUG")
                # Add successful HTTP traffic entry
                if result[0]:
                    response_info = self._helpers.analyzeResponse(
                        result[0].getResponse()
                    )
                    ui_tab.addHttpTraffic(
                        request_info.getMethod(),
                        url.toString(),
                        response_info.getStatusCode(),
                    )
            return result[0]

        except Exception as e:
            print("Error sending request: " + str(e))
            return None

    def _analyze_xss_response(self, response, payload, param_name):
        """Analyze response for XSS vulnerabilities"""
        if not response:
            return None

        response_info = self._helpers.analyzeResponse(response.getResponse())
        body_offset = response_info.getBodyOffset()
        response_body = self._helpers.bytesToString(response.getResponse())[
            body_offset:
        ]
        headers = response_info.getHeaders()

        # Check if payload is reflected
        if payload not in response_body:
            return None

        # Analyze injection context
        context = self._analyze_injection_context(response_body, payload)

        # Check for XSS execution indicators
        xss_indicators = self._check_xss_indicators(response_body, payload, context)

        if xss_indicators:
            # Determine severity
            severity = self._determine_severity(context, xss_indicators)

            # Get CSP info
            csp_info = self._extract_csp_header(headers)

            return {
                "type": "Reflected XSS",
                "severity": severity,
                "context": context,
                "indicators": xss_indicators,
                "csp_info": csp_info if csp_info else "None",
            }

        return None

    def _analyze_injection_context(self, response_body, payload):
        """Analyze where the payload was injected"""
        contexts = []

        # Find payload in response
        payload_index = response_body.find(payload)
        if payload_index == -1:
            return "unknown"

        # Get context around payload
        start = max(0, payload_index - 100)
        end = min(len(response_body), payload_index + len(payload) + 100)
        context_snippet = response_body[start:end]

        # Check different contexts
        if self._is_in_script_tag(context_snippet, payload):
            contexts.append("script")
        elif self._is_in_attribute(context_snippet, payload):
            contexts.append("attribute")
        elif self._is_in_html_tag(context_snippet, payload):
            contexts.append("tag")
        else:
            contexts.append("html")

        return contexts[0] if contexts else "html"

    def _is_in_script_tag(self, context, payload):
        """Check if payload is inside script tags"""
        payload_pos = context.find(payload)
        before = context[:payload_pos].lower()
        after = context[payload_pos:].lower()

        return "<script" in before and "</script>" in after

    def _is_in_attribute(self, context, payload):
        """Check if payload is inside an HTML attribute"""
        payload_pos = context.find(payload)
        before = context[:payload_pos]

        # Look for attribute patterns
        attr_pattern = r'(\w+)\s*=\s*["\'][^"\']*$'
        match = re.search(attr_pattern, before)
        return match is not None

    def _is_in_html_tag(self, context, payload):
        """Check if payload is inside HTML tag"""
        payload_pos = context.find(payload)
        before = context[:payload_pos]
        after = context[payload_pos:]

        last_open = before.rfind("<")
        last_close = before.rfind(">")

        return last_open > last_close and ">" in after

    def _check_xss_indicators(self, response_body, payload, context):
        """Check for XSS execution indicators"""
        indicators = []

        # Check for script execution patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                indicators.append("script_pattern")
                break

        # Check for event handlers
        event_handlers = ["onload", "onerror", "onclick", "onmouseover", "onfocus"]
        for handler in event_handlers:
            if handler in response_body.lower():
                indicators.append("event_handler")
                break

        # Check for JavaScript URLs
        if "javascript:" in response_body.lower():
            indicators.append("javascript_url")

        # Check for unescaped payload
        dangerous_chars = ["<", ">", '"', "'", "&"]
        unescaped = any(
            char in payload and char in response_body for char in dangerous_chars
        )
        if unescaped:
            indicators.append("unescaped_chars")

        # Context-specific checks
        if context == "script":
            indicators.append("script_context")
        elif context == "attribute":
            if '"' in payload or "'" in payload:
                indicators.append("attribute_escape")

        return indicators

    def _determine_severity(self, context, indicators):
        """Determine XSS severity based on context and indicators"""
        if "script_context" in indicators or "script_pattern" in indicators:
            return "High"
        elif "event_handler" in indicators or "javascript_url" in indicators:
            return "High"
        elif "attribute_escape" in indicators:
            return "Medium"
        elif "unescaped_chars" in indicators:
            return "Medium"
        else:
            return "Low"

    def _extract_csp_header(self, headers):
        """Extract CSP header from response headers"""
        for header in headers:
            if header.lower().startswith("content-security-policy:"):
                return header[len("content-security-policy:") :].strip()
        return None

    def _analyze_csp(self, csp_header):
        """Analyze CSP for bypass opportunities"""
        if not csp_header:
            return []

        # Simple CSP analysis - in real implementation, use CSPAnalyzer
        bypasses = []

        if "'unsafe-inline'" in csp_header:
            bypasses.append("unsafe-inline")
        if "'unsafe-eval'" in csp_header:
            bypasses.append("unsafe-eval")
        if "data:" in csp_header:
            bypasses.append("data-uri")

        return bypasses

    def _detect_waf(self, headers, response_body):
        """Simple WAF detection"""
        waf_indicators = []

        # Check headers for WAF signatures
        header_text = " ".join(headers).lower()

        if "cloudflare" in header_text or "cf-ray" in header_text:
            waf_indicators.append("cloudflare")
        if "akamai" in header_text:
            waf_indicators.append("akamai")
        if "imperva" in header_text or "incap" in header_text:
            waf_indicators.append("imperva")

        # Check response body
        body_lower = response_body.lower()
        if any(word in body_lower for word in ["blocked", "forbidden", "firewall"]):
            waf_indicators.append("generic")

        return waf_indicators

    def _log_finding(self, url, param_name, payload, result):
        """Log XSS finding to Burp (console logging kept for debug purposes)"""
        print("XSS Found!")
        print("URL: " + url)
        print("Parameter: " + param_name)
        print("Payload: " + payload)
        print("Type: " + result["type"])
        print("Severity: " + result["severity"])
        print("Context: " + result["context"])
        print("---")

    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
