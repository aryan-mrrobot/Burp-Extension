#!/usr/bin/env python
"""
XSS Hunter Pro Setup Script
This script helps set up the XSS Hunter Pro Burp Suite extension
"""

import os
import sys


def check_dependencies():
    """Check if all required files are present"""
    required_files = [
        "main.py",
        "config.py",
        "ui/xss_hunter_tab.py",
        "utils/payload_utils.py",
        "utils/xss_scanner.py",
        "payloads/xss_payloads.txt",
        "payloads/waf_bypass.txt",
        "csp/payload.txt",
    ]

    missing_files = []
    current_dir = os.path.dirname(os.path.abspath(__file__))

    for file_path in required_files:
        full_path = os.path.join(current_dir, file_path)
        if not os.path.exists(full_path):
            missing_files.append(file_path)

    if missing_files:
        print("ERROR: Missing required files:")
        for file_path in missing_files:
            print("  - " + file_path)
        return False

    print("✓ All required files found")
    return True


def validate_payload_files():
    """Validate that payload files contain data"""
    payload_files = {
        "payloads/xss_payloads.txt": "Basic XSS payloads",
        "payloads/waf_bypass.txt": "WAF bypass payloads",
        "csp/payload.txt": "CSP bypass payloads",
    }

    current_dir = os.path.dirname(os.path.abspath(__file__))

    for file_path, description in payload_files.items():
        full_path = os.path.join(current_dir, file_path)
        try:
            with open(full_path, "r") as f:
                lines = f.readlines()
                payload_count = len(
                    [
                        line
                        for line in lines
                        if line.strip() and not line.strip().startswith("#")
                    ]
                )
                print("✓ {}: {} payloads loaded".format(description, payload_count))
        except Exception as e:
            print("ERROR: Could not read {}: {}".format(file_path, str(e)))
            return False

    return True


def create_burp_config():
    """Create a sample Burp configuration note"""
    config_text = """
# Burp Suite Configuration for XSS Hunter Pro

To load the XSS Hunter Pro extension in Burp Suite:

1. Open Burp Suite Professional
2. Go to Extender > Extensions
3. Click "Add"
4. Select "Extension type: Python"
5. Browse to select the main.py file from this directory
6. Click "Next" to load the extension

The extension will appear as "XSS Hunter Pro" in the extensions list
and add a new "XSS Hunter" tab to the Burp Suite interface.

Extension Requirements:
- Burp Suite Professional (with Jython support)
- Python 2.7 (bundled with Burp Suite)

Directory: {}
Main file: main.py
""".format(
        os.path.dirname(os.path.abspath(__file__))
    )

    try:
        with open("BURP_SETUP.txt", "w") as f:
            f.write(config_text)
        print("✓ Created BURP_SETUP.txt with configuration instructions")
    except Exception as e:
        print("Warning: Could not create setup file: " + str(e))


def main():
    """Main setup function"""
    print("XSS Hunter Pro Setup")
    print("=" * 50)

    # Check Python version
    if sys.version_info[0] >= 3:
        print(
            "Warning: This extension is designed for Python 2.7 (Jython in Burp Suite)"
        )
        print(
            "Current Python version: {}.{}.{}".format(
                sys.version_info[0], sys.version_info[1], sys.version_info[2]
            )
        )

    # Check dependencies
    if not check_dependencies():
        print("\nSetup failed due to missing files.")
        return False

    # Validate payload files
    if not validate_payload_files():
        print("\nSetup failed due to payload file issues.")
        return False

    # Create Burp configuration
    create_burp_config()

    print("\n" + "=" * 50)
    print("Setup completed successfully!")
    print("\nNext steps:")
    print("1. Open Burp Suite Professional")
    print("2. Load the extension using main.py")
    print("3. Check the 'XSS Hunter' tab")
    print("\nSee BURP_SETUP.txt for detailed instructions.")

    return True


if __name__ == "__main__":
    main()
