# -*- coding: utf-8 -*-
from burp import (
    IBurpExtender,
    ITab,
    IHttpListener,
    IScannerCheck,
    IScanIssue,
    IExtensionStateListener,
)
from java.awt import BorderLayout
from javax.swing import JPanel, JLabel, SwingConstants
import sys
import os

# Add the project directory to Python path
# Use a more reliable method for Jython in Burp Suite
try:
    extension_path = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # __file__ not available in Jython, use alternative approach
    import java.lang.System

    extension_path = java.lang.System.getProperty("user.dir")
    # Try to find the actual extension directory
    if os.path.exists(os.path.join(extension_path, "main.py")):
        pass  # Current directory is correct
    elif os.path.exists("D:\\project\\main.py"):
        extension_path = "D:\\project"
    else:
        # Fallback to a common location
        extension_path = "."

if extension_path not in sys.path:
    sys.path.append(extension_path)

# Import our custom modules with error handling
try:
    from ui.xss_hunter_tab import XSSHunterTab
    from utils.payload_utils import (
        PayloadManager,
        ContextAnalyzer,
        CSPAnalyzer,
        WAFDetector,
    )
    from utils.xss_scanner import XSSScanner

    MODULES_LOADED = True
    print("All custom modules imported successfully")
except Exception as e:
    print("Error importing custom modules: " + str(e))
    import traceback

    traceback.print_exc()
    MODULES_LOADED = False


class BurpExtender(
    IBurpExtender, ITab, IHttpListener, IScannerCheck, IExtensionStateListener
):
    def registerExtenderCallbacks(self, callbacks):
        # Store callbacks and helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set extension name
        callbacks.setExtensionName("XSS Hunter Pro")

        # Initialize components
        self.initializeComponents()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerExtensionStateListener(self)

        # Add our tab to Burp UI
        callbacks.addSuiteTab(self)

        # Print startup message
        print("XSS Hunter Pro Extension Loaded Successfully!")
        print("Extension Path: " + extension_path)
        print("Python Path: " + str(sys.path))
        callbacks.issueAlert(
            "XSS Hunter Pro Extension loaded successfully. Check the 'XSS Hunter' tab for full functionality."
        )

        # Load payloads
        self.loadPayloads()

    def initializeComponents(self):
        """Initialize all extension components"""
        try:
            print("Starting component initialization...")

            if not MODULES_LOADED:
                print(
                    "Custom modules not loaded - extension will run with limited functionality"
                )
                return

            # Initialize payload manager
            print("Initializing PayloadManager...")
            self.payload_manager = PayloadManager(extension_path)

            # Initialize analyzers
            print("Initializing analyzers...")
            self.context_analyzer = ContextAnalyzer()
            self.csp_analyzer = CSPAnalyzer()
            self.waf_detector = WAFDetector()

            # Initialize scanner
            print("Initializing XSSScanner...")
            self.xss_scanner = XSSScanner(self._callbacks, self.payload_manager)

            # Initialize UI
            print("Initializing UI...")
            self.xss_hunter_tab = XSSHunterTab(self._callbacks, self.xss_scanner)

            print("All components initialized successfully")

        except Exception as e:
            print("Error initializing components: " + str(e))
            import traceback

            traceback.print_exc()

    def loadPayloads(self):
        """Load payloads into UI"""
        try:
            if (
                not MODULES_LOADED
                or not hasattr(self, "payload_manager")
                or not hasattr(self, "xss_hunter_tab")
            ):
                print("Components not loaded - skipping payload loading")
                return

            # Load basic XSS payloads
            basic_payloads = self.payload_manager.get_payloads("basic")
            self.xss_hunter_tab.basicPayloadsArea.setText("\n".join(basic_payloads))

            # Load CSP bypass payloads
            csp_payloads = self.payload_manager.get_payloads("csp_bypass")
            self.xss_hunter_tab.cspPayloadsArea.setText("\n".join(csp_payloads))

            # Load WAF bypass payloads
            waf_payloads = self.payload_manager.get_payloads("waf_bypass")
            self.xss_hunter_tab.wafPayloadsArea.setText("\n".join(waf_payloads))

            print("Payloads loaded into UI successfully")

        except Exception as e:
            print("Error loading payloads: " + str(e))

    # ITab implementation
    def getTabCaption(self):
        return "XSS Hunter"

    def getUiComponent(self):
        try:
            print("BurpExtender.getUiComponent() called")
            # Use the main XSS Hunter tab
            if hasattr(self, "xss_hunter_tab"):
                print("Using main XSS Hunter tab")
                return self.xss_hunter_tab.getUiComponent()
            else:
                # Fallback UI if main UI fails
                print("Creating fallback UI")
                panel = JPanel(BorderLayout())
                label = JLabel(
                    "XSS Hunter Pro - Error loading main UI", SwingConstants.CENTER
                )
                panel.add(label, BorderLayout.CENTER)
                return panel
        except Exception as e:
            print("Error in getUiComponent: " + str(e))
            import traceback

            traceback.print_exc()
            # Fallback UI if main UI fails
            panel = JPanel(BorderLayout())
            label = JLabel(
                "XSS Hunter Pro - Error loading main UI", SwingConstants.CENTER
            )
            panel.add(label, BorderLayout.CENTER)
            return panel

    # IHttpListener implementation
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages for passive analysis"""
        try:
            if not messageIsRequest:
                # Analyze response for potential XSS vulnerabilities
                self.passiveAnalysis(messageInfo)
        except Exception as e:
            print("Error in processHttpMessage: " + str(e))

    def passiveAnalysis(self, messageInfo):
        """Perform passive analysis on HTTP responses"""
        try:
            if not MODULES_LOADED:
                return

            response = messageInfo.getResponse()
            if not response:
                return

            response_info = self._helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response)[body_offset:]

            # Analyze CSP
            csp_header = None
            for header in headers:
                if header.lower().startswith("content-security-policy:"):
                    csp_header = header[len("content-security-policy:") :].strip()
                    break

            if csp_header and hasattr(self, "csp_analyzer"):
                csp_directives = self.csp_analyzer.parse_csp(csp_header)
                bypasses = self.csp_analyzer.analyze_csp_bypasses(csp_directives)

                if bypasses:
                    # Log CSP analysis results
                    url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                    print("CSP Analysis for: " + url)
                    for bypass in bypasses:
                        print("  - " + bypass["type"] + ": " + bypass["description"])

            # Detect WAF
            header_dict = {}
            for header in headers:
                if ":" in header:
                    name, value = header.split(":", 1)
                    header_dict[name.strip()] = value.strip()

            if hasattr(self, "waf_detector"):
                detected_wafs = self.waf_detector.detect_waf(header_dict, response_body)
                if detected_wafs:
                    url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                    print("WAF detected for " + url + ": " + ", ".join(detected_wafs))

        except Exception as e:
            print("Error in passive analysis: " + str(e))

    # IScannerCheck implementation
    def doPassiveScan(self, baseRequestResponse):
        """Perform passive scanning"""
        issues = []
        try:
            response = baseRequestResponse.getResponse()
            if not response:
                return issues

            request_info = self._helpers.analyzeRequest(baseRequestResponse)
            response_info = self._helpers.analyzeResponse(response)

            # Check for potential XSS sinks
            body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response)[body_offset:]

            # Look for reflection patterns
            url = request_info.getUrl()
            if url.getQuery():
                query_params = url.getQuery().split("&")
                for param in query_params:
                    if "=" in param:
                        name, value = param.split("=", 1)
                        if value in response_body and len(value) > 3:
                            # Potential reflection found
                            issue = self.createXSSIssue(
                                baseRequestResponse,
                                "Potential XSS - Parameter Reflection",
                                "Parameter '"
                                + name
                                + "' appears to be reflected in the response",
                                "Information",
                            )
                            issues.append(issue)

        except Exception as e:
            print("Error in doPassiveScan: " + str(e))

        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Perform active scanning"""
        issues = []
        try:
            if not MODULES_LOADED or not hasattr(self, "payload_manager"):
                return issues

            # Get basic payloads for active scanning
            payloads = self.payload_manager.get_payloads("basic")[
                :5
            ]  # Limit for performance

            for payload in payloads:
                # Insert payload
                checkRequest = insertionPoint.buildRequest(
                    self._helpers.stringToBytes(payload)
                )

                # Make request
                checkRequestResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest
                )

                # Analyze response
                if self.analyzeXSSResponse(checkRequestResponse, payload):
                    issue = self.createXSSIssue(
                        checkRequestResponse,
                        "Cross-Site Scripting (XSS)",
                        "XSS vulnerability found with payload: " + payload,
                        "High",
                    )
                    issues.append(issue)
                    break  # Found one, no need to test more

        except Exception as e:
            print("Error in doActiveScan: " + str(e))

        return issues

    def analyzeXSSResponse(self, requestResponse, payload):
        """Analyze response for XSS"""
        try:
            response = requestResponse.getResponse()
            if not response:
                return False

            response_info = self._helpers.analyzeResponse(response)
            body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response)[body_offset:]

            # Simple check - payload reflected and contains dangerous chars
            if payload in response_body:
                dangerous_chars = ["<", ">", '"', "'"]
                return any(char in payload for char in dangerous_chars)

            return False

        except Exception as e:
            print("Error analyzing XSS response: " + str(e))
            return False

    def createXSSIssue(self, requestResponse, issueName, issueDetail, severity):
        """Create XSS issue for Burp"""
        return XSSIssue(
            requestResponse.getHttpService(),
            self._helpers.analyzeRequest(requestResponse).getUrl(),
            [requestResponse],
            issueName,
            issueDetail,
            severity,
        )

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        # Simple consolidation - if same URL and issue type, it's a duplicate
        if (
            existingIssue.getUrl().toString() == newIssue.getUrl().toString()
            and existingIssue.getIssueName() == newIssue.getIssueName()
        ):
            return -1  # Existing issue is preferred
        return 0  # Issues are different

    # IExtensionStateListener implementation
    def extensionUnloaded(self):
        """Clean up when extension is unloaded"""
        try:
            if hasattr(self, "xss_scanner"):
                self.xss_scanner.stop_scan()
            print("XSS Hunter Pro Extension Unloaded")
        except Exception as e:
            print("Error during extension unload: " + str(e))


class XSSIssue(IScanIssue):
    """Custom XSS issue implementation"""

    def __init__(
        self, httpService, url, httpMessages, issueName, issueDetail, severity
    ):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._issueName = issueName
        self._issueDetail = issueDetail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return 0x00040000  # XSS issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Cross-site scripting (XSS) vulnerabilities allow an attacker to inject malicious scripts into web applications."

    def getRemediationBackground(self):
        return "Ensure all user input is properly validated and encoded before being included in HTML output."

    def getIssueDetail(self):
        return self._issueDetail

    def getRemediationDetail(self):
        return "Implement proper input validation and output encoding. Use CSP headers to mitigate XSS risks."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
