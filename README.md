# XSS Hunter Pro - Advanced Burp Suite Extension for XSS Detection

## Overview

XSS Hunter Pro is a comprehensive Burp Suite extension designed to detect reflected Cross-Site Scripting (XSS) vulnerabilities with advanced capabilities for bypassing Content Security Policy (CSP) and Web Application Firewalls (WAF).

## Features

### Core Functionality

- **Reflected XSS Detection**: Automated testing for reflected XSS vulnerabilities
- **CSP Bypass**: Advanced payloads and techniques to bypass Content Security Policy
- **WAF Evasion**: Specialized payloads to bypass various Web Application Firewalls
- **Context-Aware Testing**: Intelligent payload selection based on injection context
- **Passive Analysis**: Real-time analysis of HTTP traffic for potential vulnerabilities

### User Interface

- **Scanner Tab**: Configure and run XSS scans with various options
- **Results Tab**: View and manage scan results with severity indicators
- **Payloads Tab**: Manage and customize XSS payloads
- **Configuration Tab**: Configure extension settings and preferences

### Advanced Features

- **Multi-threaded Scanning**: Efficient scanning with configurable thread pools
- **WAF Detection**: Automatic detection of popular WAF solutions
- **CSP Analysis**: Detailed analysis of Content Security Policy headers
- **Context Analysis**: Determines injection context for targeted payloads
- **Custom Payloads**: Support for user-defined payload sets

## Installation

1. Download the extension files to a directory
2. Open Burp Suite Professional
3. Go to Extender > Extensions
4. Click "Add" and select "Python"
5. Browse to the main.py file
6. Click "Next" to load the extension

## Directory Structure

```
project/
├── main.py                    # Main extension file
├── config.py                  # Configuration settings
├── ui/
│   └── xss_hunter_tab.py     # User interface components
├── utils/
│   ├── payload_utils.py      # Payload management and analysis
│   └── xss_scanner.py        # Core scanning engine
├── payloads/
│   ├── xss_payloads.txt      # Basic XSS payloads
│   └── waf_bypass.txt        # WAF bypass payloads
└── csp/
    └── payload.txt           # CSP bypass payloads
```

## Usage

### Basic Scanning

1. Navigate to the "XSS Hunter" tab in Burp Suite
2. Enter the target URL in the Scanner tab
3. Configure scan options (Reflected XSS, CSP Bypass, WAF Bypass)
4. Click "Start Scan" to begin testing

### Payload Management

1. Go to the Payloads tab
2. View and edit different payload categories:
   - Basic XSS: Standard XSS payloads
   - CSP Bypass: Payloads designed to bypass CSP
   - WAF Bypass: Payloads for WAF evasion
   - Custom: User-defined payloads

### Results Analysis

1. Check the Results tab for discovered vulnerabilities
2. Results include:
   - Target URL and parameter
   - Successful payload
   - Vulnerability type and severity
   - CSP information
   - Current status

## Payload Categories

### Basic XSS Payloads

- Standard script injection payloads
- Event handler-based payloads
- HTML5 element payloads
- JavaScript execution methods

### CSP Bypass Payloads

- Data URI schemes
- JSONP callback exploitation
- Script gadget abuse
- Object and embed tag bypasses
- Base64 encoded payloads

### WAF Bypass Techniques

- Case variation and encoding
- Comment insertion
- Unicode and hex encoding
- Alternative event handlers
- Fragmentation techniques

## Configuration Options

### Threading Settings

- **Max Threads**: Number of concurrent scanning threads
- **Delay**: Delay between requests in milliseconds

### Detection Settings

- **Timeout**: Request timeout in seconds
- **Follow Redirects**: Whether to follow HTTP redirects

### Proxy Settings

- **Use Proxy**: Enable proxy for requests
- **Proxy Host/Port**: Proxy server configuration

## Advanced Features

### Context-Aware Payload Selection

The extension analyzes where user input is reflected and selects appropriate payloads:

- HTML context: Standard script tags and HTML injection
- Attribute context: Attribute breakout techniques
- Script context: JavaScript injection methods
- URL context: JavaScript URLs and data URIs

### CSP Analysis

Automatic analysis of Content Security Policy headers to identify:

- Missing or weak directives
- Unsafe-inline and unsafe-eval permissions
- Wildcard domains and JSONP endpoints
- Bypass opportunities

### WAF Detection

Identifies popular WAF solutions including:

- Cloudflare
- Akamai
- AWS WAF
- Imperva
- F5 BIG-IP
- ModSecurity

## Security Considerations

- Only use this extension on applications you own or have permission to test
- Be mindful of the payload intensity and server load
- Review and understand payloads before using in production environments
- Some payloads may trigger security alerts or logging systems

## Troubleshooting

### Common Issues

**Issue**: `TypeError: can't convert <ui.xss_hunter_tab.JPanel instance> to java.awt.Component`

**Solution**: This indicates a Java/Jython compatibility issue. Try the following:

1. **Check Jython Configuration**:

   - Go to Extender → Options
   - Ensure "Python Environment" is properly configured
   - Try changing the Jython standalone JAR if available

2. **Use Debug Mode**:

   - The extension includes multiple test tabs for debugging (MinimalTestTab, SimpleTestTab)
   - Check the Extender → Extensions → Output tab for detailed logs

3. **Verify File Paths**:
   - Ensure all project files are in the same directory as `main.py`
   - Check that the `ui/`, `utils/`, `csp/`, and `payloads/` directories exist

**Issue**: `ModuleNotFoundError` for custom modules

**Solution**:

1. Ensure the directory structure is intact with all `__init__.py` files
2. Verify Python path includes the extension directory
3. Check file permissions and accessibility

**Issue**: Extension loads but no "XSS Hunter" tab appears

**Solution**:

1. Check the Extender → Extensions → Errors tab for exceptions
2. Look for component initialization errors in the Output tab
3. Try reloading the extension

### Debug Information

- Check Burp Suite's Extensions > Errors tab for Python errors
- Monitor the extension output in the Scanner tab status area
- The extension includes debug versions (MinimalTestTab, SimpleTestTab) that are automatically tried if the main UI fails
- Enable verbose logging in configuration if needed

### Load Order Debugging

The extension tries multiple UI approaches in this order:

1. **MinimalTestTab**: Most basic Java Swing component
2. **SimpleTestTab**: Simple UI with minimal functionality
3. **XSSHunterTab**: Full featured interface

If any level fails, check the Burp Suite Extender output for specific error messages.

## Contributing

To extend the functionality:

1. Add new payloads to appropriate payload files
2. Modify detection logic in utils/xss_scanner.py
3. Enhance UI components in ui/xss_hunter_tab.py
4. Update configuration options in config.py

## Legal Notice

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any applications. The authors are not responsible for any misuse of this tool.

## Version History

- v1.0: Initial release with basic XSS detection
- v1.1: Added CSP bypass capabilities
- v1.2: Enhanced WAF detection and bypass techniques
- v1.3: Improved UI and context-aware scanning

## Support

For issues, questions, or contributions, please refer to the project documentation or contact the development team.
