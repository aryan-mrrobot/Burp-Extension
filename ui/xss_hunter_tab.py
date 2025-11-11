# -*- coding: utf-8 -*-
import threading

# Import core Java classes that are always available in burp
try:
    from burp import ITab
    from java.awt import (
        BorderLayout,
        FlowLayout,
        GridBagLayout,
        GridBagConstraints,
        Insets,
        Dimension,
    )
    from java.awt.event import ActionListener
    from javax.swing import JPanel, JLabel, JTextField, JButton, JScrollPane, JTextArea
    from javax.swing import (
        JCheckBox,
        JComboBox,
        JTabbedPane,
        SwingConstants,
        BorderFactory,
    )
    from javax.swing import JProgressBar
    import java.awt.Color

    CORE_JAVA_AVAILABLE = True
    print("Core Java/Swing classes imported successfully")
except ImportError as e:
    CORE_JAVA_AVAILABLE = False
    print("Core Java import failed: " + str(e))

# Try to import optional Java classes (like table components)
try:
    from javax.swing import JTable, DefaultTableModel
    from javax.swing.table import DefaultTableCellRenderer

    TABLE_COMPONENTS_AVAILABLE = True
except ImportError as e:
    TABLE_COMPONENTS_AVAILABLE = False
    print("Table components not available: " + str(e))

    # Create dummy table classes
    class JTable:
        def __init__(self, *args):
            pass

        def getColumnModel(self):
            return DummyColumnModel()

        def getColumn(self, name):
            return DummyColumn()

        def getBackground(self):
            return None

        def getForeground(self):
            return None

    class DefaultTableModel:
        def __init__(self, *args):
            pass

        def addRow(self, row):
            pass

        def setRowCount(self, count):
            pass

    class DefaultTableCellRenderer:
        def __init__(self, *args):
            pass


# Overall availability check
JAVA_AVAILABLE = CORE_JAVA_AVAILABLE

if not CORE_JAVA_AVAILABLE:
    print("Running outside Jython - using dummy classes for testing")

    # Define dummy classes for testing outside Burp
    class ITab:
        pass

    class ActionListener:
        pass

    class JPanel:
        def __init__(self, *args):
            pass

        def add(self, component, *args):
            pass

        def setBorder(self, border):
            pass

    class JLabel:
        def __init__(self, *args):
            pass

    class JTextField:
        def __init__(self, *args):
            pass

        def getText(self):
            return ""

        def setText(self, text):
            pass

        def setPreferredSize(self, size):
            pass

    class JButton:
        def __init__(self, *args):
            pass

        def addActionListener(self, listener):
            pass

        def setEnabled(self, enabled):
            pass

    class JScrollPane:
        def __init__(self, *args):
            pass

        def setBorder(self, border):
            pass

    class JTextArea:
        def __init__(self, *args):
            pass

        def setText(self, text):
            pass

        def getText(self):
            return ""

        def setEditable(self, editable):
            pass

        def setRows(self, rows):
            pass

        def append(self, text):
            pass

        def setCaretPosition(self, pos):
            pass

        def getDocument(self):
            return DummyDocument()

        def getCaretPosition(self):
            return 0

    class JCheckBox:
        def __init__(self, *args):
            pass

        def isSelected(self):
            return False

    class JComboBox:
        def __init__(self, *args):
            pass

        def getSelectedItem(self):
            return None

    class JTable:
        def __init__(self, *args):
            pass

        def getColumnModel(self):
            return DummyColumnModel()

        def getColumn(self, name):
            return DummyColumn()

        def getBackground(self):
            return None

        def getForeground(self):
            return None

    class JProgressBar:
        def __init__(self, *args):
            pass

        def setValue(self, value):
            pass

        def setString(self, text):
            pass

        def setStringPainted(self, painted):
            pass

    class JTabbedPane:
        def __init__(self, *args):
            pass

        def addTab(self, title, component):
            pass

    class GridBagLayout:
        pass

    class GridBagConstraints:
        # Add the missing constants
        WEST = 0
        EAST = 1
        NORTH = 2
        SOUTH = 3
        CENTER = 4
        HORIZONTAL = 5
        VERTICAL = 6
        BOTH = 7
        NONE = 8

        def __init__(self):
            self.gridx = 0
            self.gridy = 0
            self.anchor = 0
            self.fill = 0
            self.weightx = 0.0
            self.weighty = 0.0
            self.gridwidth = 1
            self.insets = None

    class BorderLayout:
        # Add the missing constants
        CENTER = "Center"
        NORTH = "North"
        SOUTH = "South"
        EAST = "East"
        WEST = "West"

    class FlowLayout:
        # Add the missing constants
        LEFT = 0
        CENTER = 1
        RIGHT = 2

        def __init__(self, *args):
            pass

    class SwingConstants:
        # Add the missing constants
        CENTER = 0
        LEFT = 1
        RIGHT = 2
        TOP = 3
        BOTTOM = 4

    class Insets:
        def __init__(self, top, left, bottom, right):
            self.top = top
            self.left = left
            self.bottom = bottom
            self.right = right

    class Dimension:
        def __init__(self, width, height):
            self.width = width
            self.height = height

    class BorderFactory:
        @staticmethod
        def createTitledBorder(title):
            return None


# Helper dummy classes
class DummyDocument:
    def getLength(self):
        return 0


class DummyColumnModel:
    def getColumn(self, index):
        return DummyColumn()


class DummyColumn:
    def setPreferredWidth(self, width):
        pass

    def setCellRenderer(self, renderer):
        pass


class XSSHunterTab(ITab):
    def __init__(self, callbacks, scanner):
        print("Initializing XSSHunterTab...")
        print("JAVA_AVAILABLE: " + str(JAVA_AVAILABLE))
        self._callbacks = callbacks
        self._scanner = scanner

        # Initialize payload areas first to prevent attribute errors
        self.initializePayloadAreas()

        print("Callbacks and scanner stored, calling initUI...")
        self.initUI()
        print("XSSHunterTab initialization completed")

    def getTabCaption(self):
        return "XSS Hunter"

    def getUiComponent(self):
        """Return the main UI component for Burp Suite"""
        print("XSSHunterTab.getUiComponent() called")
        print("Panel type: " + str(type(self._panel)))
        return self._panel

    def initUI(self):
        if not JAVA_AVAILABLE:
            print(
                "Java components are not available - check Jython configuration and classpath."
            )
            self._panel = self.createDummyPanel()
            return
        """Initialize the user interface"""
        print("Initializing UI components...")

        if JAVA_AVAILABLE:
            try:
                print("Creating Java components with proper error handling...")
                from javax.swing import JPanel as JavaJPanel
                from java.awt import BorderLayout as JavaBorderLayout
                from javax.swing import JTabbedPane as JavaJTabbedPane
                from javax.swing import JLabel as JavaJLabel

                print("Creating real Java JPanel with BorderLayout")
                self._panel = JavaJPanel(JavaBorderLayout())
                print("Main panel created: " + str(type(self._panel)))
                print("Main panel class: " + str(self._panel.__class__))

                # Create tabbed pane
                tabbedPane = JavaJTabbedPane()
                print("Created tabbed pane: " + str(type(tabbedPane)))

                # Create tabs with proper Java component checking
                try:
                    # Scanner tab
                    scannerTab = self.createScannerTab(use_java=True)
                    if scannerTab is not None:
                        print("Adding Scanner tab: " + str(type(scannerTab)))
                        tabbedPane.addTab("Scanner", scannerTab)
                    else:
                        print("Scanner tab creation failed, adding placeholder")
                        tabbedPane.addTab(
                            "Scanner", JavaJLabel("Scanner tab failed to load")
                        )

                    # Results tab
                    resultsTab = self.createResultsTab(use_java=True)
                    if resultsTab is not None:
                        print("Adding Results tab: " + str(type(resultsTab)))
                        tabbedPane.addTab("Results", resultsTab)
                    else:
                        print("Results tab creation failed, adding placeholder")
                        tabbedPane.addTab(
                            "Results", JavaJLabel("Results tab failed to load")
                        )

                    # Payloads tab
                    payloadsTab = self.createPayloadsTab(use_java=True)
                    if payloadsTab is not None:
                        print("Adding Payloads tab: " + str(type(payloadsTab)))
                        tabbedPane.addTab("Payloads", payloadsTab)
                    else:
                        print("Payloads tab creation failed, adding placeholder")
                        # Initialize the payload areas as placeholders so the attributes exist
                        self.initializePayloadAreas()
                        tabbedPane.addTab(
                            "Payloads", JavaJLabel("Payloads tab failed to load")
                        )

                    # Configuration tab
                    configTab = self.createConfigTab(use_java=True)
                    if configTab is not None:
                        print("Adding Configuration tab: " + str(type(configTab)))
                        tabbedPane.addTab("Configuration", configTab)
                    else:
                        print("Configuration tab creation failed, adding placeholder")
                        tabbedPane.addTab(
                            "Configuration",
                            JavaJLabel("Configuration tab failed to load"),
                        )

                except Exception as tab_error:
                    print("Error creating individual tabs: " + str(tab_error))
                    import traceback

                    traceback.print_exc()
                    # Add a simple error tab
                    tabbedPane.addTab(
                        "Error", JavaJLabel("Failed to create tabs: " + str(tab_error))
                    )

                self._panel.add(tabbedPane, JavaBorderLayout.CENTER)
                print("UI initialization completed successfully with Java components")
                return

            except Exception as e:
                print("Error creating Java components in XSSHunterTab: " + str(e))
                import traceback

                traceback.print_exc()
                print("Creating minimal fallback UI with real Java components...")

                # Create a minimal but functional UI with real Java components
                try:
                    from javax.swing import JPanel as JavaJPanel
                    from java.awt import BorderLayout as JavaBorderLayout
                    from javax.swing import JLabel as JavaJLabel

                    self._panel = JavaJPanel(JavaBorderLayout())
                    error_label = JavaJLabel(
                        "XSS Hunter - UI creation failed: " + str(e)
                    )
                    self._panel.add(error_label, JavaBorderLayout.CENTER)
                    print("Minimal fallback UI created successfully")
                    return
                except Exception as fallback_error:
                    print(
                        "Even fallback Java components failed: " + str(fallback_error)
                    )

        # Last resort - this should not happen in Burp, but just in case
        print("Creating absolute fallback UI (this should not happen in Burp)")
        self._panel = self.createDummyPanel()

    def initializePayloadAreas(self):
        """Initialize payload text areas as placeholders to prevent attribute errors"""
        print("Initializing payload areas as placeholders...")
        try:
            from javax.swing import JTextArea as JavaJTextArea

            self.basicPayloadsArea = JavaJTextArea("Basic payloads not loaded")
            self.cspPayloadsArea = JavaJTextArea("CSP payloads not loaded")
            self.wafPayloadsArea = JavaJTextArea("WAF payloads not loaded")
            self.customPayloadsArea = JavaJTextArea("Custom payloads not loaded")
            print("Payload areas initialized successfully with Java components")
        except Exception as e:
            print("Failed to create Java payload areas, using dummy: " + str(e))
            # Use dummy text areas
            self.basicPayloadsArea = JTextArea("Basic payloads not loaded")
            self.cspPayloadsArea = JTextArea("CSP payloads not loaded")
            self.wafPayloadsArea = JTextArea("WAF payloads not loaded")
            self.customPayloadsArea = JTextArea("Custom payloads not loaded")

    def createDummyPanel(self):
        """Create a simple dummy panel for fallback"""
        try:
            # Try to create real Java components even if main imports failed
            from javax.swing import JPanel as JavaJPanel
            from java.awt import BorderLayout as JavaBorderLayout
            from javax.swing import JLabel as JavaJLabel

            panel = JavaJPanel(JavaBorderLayout())
            label = JavaJLabel(
                "XSS Hunter - Limited functionality (Java imports partially failed)"
            )
            panel.add(label, JavaBorderLayout.CENTER)
            return panel
        except Exception as e:
            print("Failed to create even basic Java components: " + str(e))
            # This should never happen in Burp Suite, but return None to be safe
            return None

    def createScannerTab(self, use_java=False):
        if use_java and JAVA_AVAILABLE:
            try:
                # Import Java components directly for this tab
                from javax.swing import (
                    JPanel as JavaJPanel,
                    JLabel as JavaJLabel,
                    JTextField as JavaJTextField,
                )
                from javax.swing import (
                    JButton as JavaJButton,
                    JTextArea as JavaJTextArea,
                    JScrollPane as JavaJScrollPane,
                    JTabbedPane as JavaJTabbedPane,
                )
                from javax.swing import (
                    JCheckBox as JavaJCheckBox,
                    JComboBox as JavaJComboBox,
                    JSplitPane as JavaJSplitPane,
                )
                from javax.swing import (
                    JProgressBar as JavaJProgressBar,
                    BorderFactory as JavaBorderFactory,
                )
                from java.awt import (
                    BorderLayout as JavaBorderLayout,
                    FlowLayout as JavaFlowLayout,
                )
                from java.awt import (
                    GridBagLayout as JavaGridBagLayout,
                    GridBagConstraints as JavaGridBagConstraints,
                )
                from java.awt import Insets as JavaInsets, Dimension as JavaDimension

                print("Creating comprehensive Scanner tab with Java components")
                mainPanel = JavaJPanel(JavaBorderLayout())

                # Top control panel
                controlPanel = JavaJPanel(JavaGridBagLayout())
                controlPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("XSS Scanner Configuration")
                )
                gbc = JavaGridBagConstraints()

                # URL input section
                gbc.gridx = 0
                gbc.gridy = 0
                gbc.anchor = JavaGridBagConstraints.WEST
                gbc.insets = JavaInsets(5, 5, 5, 5)
                controlPanel.add(JavaJLabel("Target URL:"), gbc)

                gbc.gridx = 1
                gbc.fill = JavaGridBagConstraints.HORIZONTAL
                gbc.weightx = 1.0
                self.urlField = JavaJTextField("https://www.hackerone.com/", 40)
                controlPanel.add(self.urlField, gbc)

                # Scan options panel
                gbc.gridx = 0
                gbc.gridy = 1
                gbc.gridwidth = 2
                gbc.fill = JavaGridBagConstraints.HORIZONTAL
                gbc.insets = JavaInsets(10, 5, 5, 5)

                optionsPanel = JavaJPanel(JavaFlowLayout(JavaFlowLayout.LEFT))
                optionsPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("Scan Options")
                )

                self.enableCrawling = JavaJCheckBox("Enable Crawling", True)
                self.enableFuzzing = JavaJCheckBox("Enable Fuzzing", True)
                self.testReflected = JavaJCheckBox("Reflected XSS", True)
                self.testStored = JavaJCheckBox("Stored XSS", True)
                self.testDOM = JavaJCheckBox("DOM XSS", True)

                optionsPanel.add(self.enableCrawling)
                optionsPanel.add(self.enableFuzzing)
                optionsPanel.add(self.testReflected)
                optionsPanel.add(self.testStored)
                optionsPanel.add(self.testDOM)

                controlPanel.add(optionsPanel, gbc)

                # CSP and WAF bypass options
                gbc.gridy = 2
                bypassPanel = JavaJPanel(JavaFlowLayout(JavaFlowLayout.LEFT))
                bypassPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("Bypass Techniques")
                )

                self.bypassCSP = JavaJCheckBox("CSP Bypass", True)
                self.bypassWAF = JavaJCheckBox("WAF Bypass", True)
                self.useEncodedPayloads = JavaJCheckBox("Encoded Payloads", True)
                self.usePolyglotPayloads = JavaJCheckBox("Polyglot Payloads", True)

                bypassPanel.add(self.bypassCSP)
                bypassPanel.add(self.bypassWAF)
                bypassPanel.add(self.useEncodedPayloads)
                bypassPanel.add(self.usePolyglotPayloads)

                controlPanel.add(bypassPanel, gbc)

                # Scan depth and threading options
                gbc.gridy = 3
                advancedPanel = JavaJPanel(JavaFlowLayout(JavaFlowLayout.LEFT))
                advancedPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("Advanced Options")
                )

                advancedPanel.add(JavaJLabel("Crawl Depth:"))
                self.crawlDepthField = JavaJTextField("3", 3)
                advancedPanel.add(self.crawlDepthField)

                advancedPanel.add(JavaJLabel("Max URLs:"))
                self.maxUrlsField = JavaJTextField("50", 4)
                advancedPanel.add(self.maxUrlsField)

                advancedPanel.add(JavaJLabel("Threads:"))
                self.threadsField = JavaJTextField("5", 3)
                advancedPanel.add(self.threadsField)

                advancedPanel.add(JavaJLabel("Delay (ms):"))
                self.delayField = JavaJTextField("500", 4)
                advancedPanel.add(self.delayField)

                controlPanel.add(advancedPanel, gbc)

                # Control buttons
                gbc.gridy = 4
                gbc.fill = JavaGridBagConstraints.NONE
                gbc.anchor = JavaGridBagConstraints.CENTER

                buttonPanel = JavaJPanel(JavaFlowLayout())

                self.startScanButton = JavaJButton("Start Comprehensive Scan")
                self.startScanButton.addActionListener(StartScanAction(self))
                buttonPanel.add(self.startScanButton)

                self.stopScanButton = JavaJButton("Stop Scan")
                self.stopScanButton.setEnabled(False)
                self.stopScanButton.addActionListener(StopScanAction(self))
                buttonPanel.add(self.stopScanButton)

                self.clearResultsButton = JavaJButton("Clear Results")
                self.clearResultsButton.addActionListener(ClearResultsAction(self))
                buttonPanel.add(self.clearResultsButton)

                controlPanel.add(buttonPanel, gbc)

                # Progress bar
                gbc.gridy = 5
                gbc.fill = JavaGridBagConstraints.HORIZONTAL
                gbc.insets = JavaInsets(10, 5, 5, 5)

                self.progressBar = JavaJProgressBar()
                self.progressBar.setStringPainted(True)
                self.progressBar.setString("Ready to scan")
                controlPanel.add(self.progressBar, gbc)

                mainPanel.add(controlPanel, JavaBorderLayout.NORTH)

                # Create a tabbed pane for the bottom section
                bottomTabbedPane = JavaJTabbedPane()

                # Status area tab
                statusPanel = JavaJPanel(JavaBorderLayout())
                statusPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("Scan Status & Results")
                )

                self.statusArea = JavaJTextArea(
                    "XSS Hunter Pro Scanner Ready\n"
                    + "Features:\n"
                    + "✓ Comprehensive crawling with configurable depth\n"
                    + "✓ Advanced fuzzing with multiple payload types\n"
                    + "✓ CSP and WAF bypass techniques\n"
                    + "✓ Reflected, Stored, and DOM XSS detection\n"
                    + "✓ Encoded and polyglot payload testing\n"
                    + "✓ Multi-threaded scanning\n\n"
                    + "Enter a target URL and configure options above, then click 'Start Comprehensive Scan'\n"
                )
                self.statusArea.setEditable(False)
                self.statusArea.setRows(20)
                statusScroll = JavaJScrollPane(self.statusArea)
                statusPanel.add(statusScroll, JavaBorderLayout.CENTER)

                # Discovered URLs area tab
                import traceback

                urlsPanel = JavaJPanel(JavaBorderLayout())
                try:
                    urlsPanel.setBorder(
                        JavaBorderFactory.createTitledBorder(
                            "Discovered URLs & Endpoints"
                        )
                    )

                    self.discoveredUrlsArea = JavaJTextArea(
                        "No URLs discovered yet...\n"
                    )
                    self.discoveredUrlsArea.setEditable(False)
                    self.discoveredUrlsArea.setRows(20)

                    # Create JScrollPane with multiple fallback methods
                    print("Creating JScrollPane with JavaJTextArea component")
                    print("Component type: " + str(type(self.discoveredUrlsArea)))

                    # Method 1: Direct instantiation
                    try:
                        urlsScroll = JavaJScrollPane(self.discoveredUrlsArea)
                        print("✓ JScrollPane created with direct instantiation")
                        urlsPanel.add(urlsScroll, JavaBorderLayout.CENTER)
                        print("✓ JScrollPane added to panel")
                    except Exception as direct_error:
                        print(
                            "✗ Direct JScrollPane creation failed: " + str(direct_error)
                        )

                        # Method 2: Create empty ScrollPane and set viewport
                        try:
                            urlsScroll = JavaJScrollPane()
                            urlsScroll.setViewportView(self.discoveredUrlsArea)
                            print("✓ JScrollPane created with setViewportView")
                            urlsPanel.add(urlsScroll, JavaBorderLayout.CENTER)
                            print("✓ JScrollPane added to panel")
                        except Exception as viewport_error:
                            print(
                                "✗ Viewport JScrollPane creation failed: "
                                + str(viewport_error)
                            )

                            # Method 3: Add text area directly without scroll pane
                            print("⚠ Using fallback: adding JTextArea directly")
                            urlsPanel.add(
                                self.discoveredUrlsArea, JavaBorderLayout.CENTER
                            )
                except Exception as e:
                    print("Error setting up JScrollPane in URLs panel: " + str(e))
                    traceback.print_exc()
                    # Add the text area directly without scroll pane as fallback
                    urlsPanel.add(self.discoveredUrlsArea, JavaBorderLayout.CENTER)

                # Backend Logs area tab
                backendLogsPanel = JavaJPanel(JavaBorderLayout())
                backendLogsPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("Backend Debug Logs")
                )

                self.backendLogsArea = JavaJTextArea(
                    "Backend logs will appear here...\n"
                    + "This section shows real-time backend operations:\n"
                    + "• HTTP requests and responses\n"
                    + "• Parameter extraction and testing\n"
                    + "• Payload generation and selection\n"
                    + "• CSP analysis and WAF detection\n"
                    + "• Error handling and timeouts\n"
                    + "• Internal scanner state changes\n\n"
                    + "Start a scan to see backend activity...\n"
                )
                self.backendLogsArea.setEditable(False)
                self.backendLogsArea.setRows(20)

                try:
                    backendLogsScroll = JavaJScrollPane(self.backendLogsArea)
                    backendLogsPanel.add(backendLogsScroll, JavaBorderLayout.CENTER)
                except Exception as backend_error:
                    print(
                        "Error creating backend logs scroll pane: " + str(backend_error)
                    )
                    backendLogsPanel.add(self.backendLogsArea, JavaBorderLayout.CENTER)

                # HTTP Traffic area tab
                httpTrafficPanel = JavaJPanel(JavaBorderLayout())
                httpTrafficPanel.setBorder(
                    JavaBorderFactory.createTitledBorder("HTTP Traffic Monitor")
                )

                self.httpTrafficArea = JavaJTextArea(
                    "HTTP traffic will be logged here...\n"
                    + "This section shows:\n"
                    + "• Request URLs and methods\n"
                    + "• Response status codes and headers\n"
                    + "• Request/response timing\n"
                    + "• Network errors and timeouts\n"
                    + "• Payload injection details\n\n"
                    + "Start a scan to monitor HTTP traffic...\n"
                )
                self.httpTrafficArea.setEditable(False)
                self.httpTrafficArea.setRows(20)

                try:
                    httpTrafficScroll = JavaJScrollPane(self.httpTrafficArea)
                    httpTrafficPanel.add(httpTrafficScroll, JavaBorderLayout.CENTER)
                except Exception as traffic_error:
                    print(
                        "Error creating HTTP traffic scroll pane: " + str(traffic_error)
                    )
                    httpTrafficPanel.add(self.httpTrafficArea, JavaBorderLayout.CENTER)

                # Add all tabs to the bottom tabbed pane
                bottomTabbedPane.addTab("Status & Results", statusPanel)
                bottomTabbedPane.addTab("Discovered URLs", urlsPanel)
                bottomTabbedPane.addTab("Backend Logs", backendLogsPanel)
                bottomTabbedPane.addTab("HTTP Traffic", httpTrafficPanel)

                mainPanel.add(bottomTabbedPane, JavaBorderLayout.CENTER)

                print("Comprehensive Scanner tab created successfully")
                return mainPanel

            except Exception as e:
                print("Error creating Scanner tab with Java components: " + str(e))
                import traceback

                traceback.print_exc()
                return None

        # Fallback to dummy components
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()

        # Target URL
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        gbc.insets = Insets(10, 10, 5, 5)
        panel.add(JLabel("Target URL:"), gbc)

        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        gbc.insets = Insets(10, 5, 5, 10)
        self.urlField = JTextField()
        self.urlField.setPreferredSize(Dimension(400, 25))
        panel.add(self.urlField, gbc)

        # Scan options
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(10, 10, 5, 10)

        optionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        optionsPanel.setBorder(BorderFactory.createTitledBorder("Scan Options"))

        self.testReflected = JCheckBox("Test Reflected XSS", True)
        self.testStored = JCheckBox("Test Stored XSS", False)
        self.testDOM = JCheckBox("Test DOM XSS", True)
        self.bypassCSP = JCheckBox("CSP Bypass", True)
        self.bypassWAF = JCheckBox("WAF Bypass", True)
        self.deepScan = JCheckBox("Deep Scan", False)

        optionsPanel.add(self.testReflected)
        optionsPanel.add(self.testStored)
        optionsPanel.add(self.testDOM)
        optionsPanel.add(self.bypassCSP)
        optionsPanel.add(self.bypassWAF)
        optionsPanel.add(self.deepScan)

        panel.add(optionsPanel, gbc)

        # Payload selection
        gbc.gridy = 2
        gbc.insets = Insets(5, 10, 5, 10)

        payloadPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload Type"))

        payloadTypes = ["Basic XSS", "CSP Bypass", "WAF Bypass", "Custom"]
        self.payloadCombo = JComboBox(payloadTypes)
        payloadPanel.add(JLabel("Payload Type:"))
        payloadPanel.add(self.payloadCombo)

        panel.add(payloadPanel, gbc)

        # Control buttons
        gbc.gridy = 3
        gbc.insets = Insets(10, 10, 5, 10)

        buttonPanel = JPanel(FlowLayout())

        self.startScanButton = JButton("Start Scan")
        self.startScanButton.addActionListener(StartScanAction(self))

        self.stopScanButton = JButton("Stop Scan")
        self.stopScanButton.setEnabled(False)
        self.stopScanButton.addActionListener(StopScanAction(self))

        self.clearResultsButton = JButton("Clear Results")
        self.clearResultsButton.addActionListener(ClearResultsAction(self))

        buttonPanel.add(self.startScanButton)
        buttonPanel.add(self.stopScanButton)
        buttonPanel.add(self.clearResultsButton)

        panel.add(buttonPanel, gbc)

        # Progress bar
        gbc.gridy = 4
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 10, 5, 10)

        self.progressBar = JProgressBar()
        self.progressBar.setStringPainted(True)
        self.progressBar.setString("Ready")
        panel.add(self.progressBar, gbc)

        # Status area
        gbc.gridy = 5
        gbc.fill = GridBagConstraints.BOTH
        gbc.weighty = 1.0
        gbc.insets = Insets(5, 10, 10, 10)

        self.statusArea = JTextArea()
        self.statusArea.setEditable(False)
        self.statusArea.setRows(10)
        scrollPane = JScrollPane(self.statusArea)
        scrollPane.setBorder(BorderFactory.createTitledBorder("Status"))
        panel.add(scrollPane, gbc)

        return panel

    def createResultsTab(self, use_java=False):
        panel = JPanel(BorderLayout())

        # Results table
        columns = ["URL", "Parameter", "Payload", "Type", "Severity", "CSP", "Status"]
        self.resultsTableModel = DefaultTableModel(columns, 0)
        self.resultsTable = JTable(self.resultsTableModel)

        # Set column widths
        columnModel = self.resultsTable.getColumnModel()
        columnModel.getColumn(0).setPreferredWidth(200)  # URL
        columnModel.getColumn(1).setPreferredWidth(100)  # Parameter
        columnModel.getColumn(2).setPreferredWidth(150)  # Payload
        columnModel.getColumn(3).setPreferredWidth(80)  # Type
        columnModel.getColumn(4).setPreferredWidth(80)  # Severity
        columnModel.getColumn(5).setPreferredWidth(100)  # CSP
        columnModel.getColumn(6).setPreferredWidth(80)  # Status

        # Custom cell renderer for severity
        severityRenderer = SeverityRenderer()
        self.resultsTable.getColumn("Severity").setCellRenderer(severityRenderer)

        scrollPane = JScrollPane(self.resultsTable)
        panel.add(scrollPane, BorderLayout.CENTER)

        # Results control panel
        controlPanel = JPanel(FlowLayout())

        exportButton = JButton("Export Results")
        exportButton.addActionListener(ExportResultsAction(self))

        filterButton = JButton("Filter Results")
        filterButton.addActionListener(FilterResultsAction(self))

        controlPanel.add(exportButton)
        controlPanel.add(filterButton)

        panel.add(controlPanel, BorderLayout.SOUTH)

        return panel

    def createPayloadsTab(self, use_java=False):
        panel = JPanel(BorderLayout())

        # Payload categories
        tabbedPane = JTabbedPane()

        # Basic XSS payloads
        basicPanel = JPanel(BorderLayout())
        self.basicPayloadsArea = JTextArea()
        self.basicPayloadsArea.setRows(20)
        basicScrollPane = JScrollPane(self.basicPayloadsArea)
        basicPanel.add(basicScrollPane, BorderLayout.CENTER)
        tabbedPane.addTab("Basic XSS", basicPanel)

        # CSP bypass payloads
        cspPanel = JPanel(BorderLayout())
        self.cspPayloadsArea = JTextArea()
        self.cspPayloadsArea.setRows(20)
        cspScrollPane = JScrollPane(self.cspPayloadsArea)
        cspPanel.add(cspScrollPane, BorderLayout.CENTER)
        tabbedPane.addTab("CSP Bypass", cspPanel)

        # WAF bypass payloads
        wafPanel = JPanel(BorderLayout())
        self.wafPayloadsArea = JTextArea()
        self.wafPayloadsArea.setRows(20)
        wafScrollPane = JScrollPane(self.wafPayloadsArea)
        wafPanel.add(wafScrollPane, BorderLayout.CENTER)
        tabbedPane.addTab("WAF Bypass", wafPanel)

        # Custom payloads
        customPanel = JPanel(BorderLayout())
        self.customPayloadsArea = JTextArea()
        self.customPayloadsArea.setRows(20)
        customScrollPane = JScrollPane(self.customPayloadsArea)
        customPanel.add(customScrollPane, BorderLayout.CENTER)

        # Custom payload controls
        customControlPanel = JPanel(FlowLayout())
        addPayloadButton = JButton("Add Payload")
        addPayloadButton.addActionListener(AddPayloadAction(self))

        removePayloadButton = JButton("Remove Selected")
        removePayloadButton.addActionListener(RemovePayloadAction(self))

        loadPayloadsButton = JButton("Load from File")
        loadPayloadsButton.addActionListener(LoadPayloadsAction(self))

        savePayloadsButton = JButton("Save to File")
        savePayloadsButton.addActionListener(SavePayloadsAction(self))

        customControlPanel.add(addPayloadButton)
        customControlPanel.add(removePayloadButton)
        customControlPanel.add(loadPayloadsButton)
        customControlPanel.add(savePayloadsButton)

        customPanel.add(customControlPanel, BorderLayout.SOUTH)
        tabbedPane.addTab("Custom", customPanel)

        panel.add(tabbedPane, BorderLayout.CENTER)

        return panel

    def createConfigTab(self, use_java=False):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()

        # Threading settings
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(10, 10, 5, 10)

        threadingPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        threadingPanel.setBorder(BorderFactory.createTitledBorder("Threading"))

        threadingPanel.add(JLabel("Max Threads:"))
        self.maxThreadsField = JTextField("10", 5)
        threadingPanel.add(self.maxThreadsField)

        threadingPanel.add(JLabel("Delay (ms):"))
        self.delayField = JTextField("100", 5)
        threadingPanel.add(self.delayField)

        panel.add(threadingPanel, gbc)

        # Detection settings
        gbc.gridy = 1

        detectionPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        detectionPanel.setBorder(BorderFactory.createTitledBorder("Detection"))

        detectionPanel.add(JLabel("Timeout (seconds):"))
        self.timeoutField = JTextField("30", 5)
        detectionPanel.add(self.timeoutField)

        self.followRedirects = JCheckBox("Follow Redirects", True)
        detectionPanel.add(self.followRedirects)

        panel.add(detectionPanel, gbc)

        # Proxy settings
        gbc.gridy = 2

        proxyPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        proxyPanel.setBorder(BorderFactory.createTitledBorder("Proxy"))

        self.useProxy = JCheckBox("Use Proxy", False)
        proxyPanel.add(self.useProxy)

        proxyPanel.add(JLabel("Host:"))
        self.proxyHostField = JTextField("127.0.0.1", 10)
        proxyPanel.add(self.proxyHostField)

        proxyPanel.add(JLabel("Port:"))
        self.proxyPortField = JTextField("8080", 5)
        proxyPanel.add(self.proxyPortField)

        panel.add(proxyPanel, gbc)

        # Save/Load config
        gbc.gridy = 3
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER

        configButtonPanel = JPanel(FlowLayout())

        saveConfigButton = JButton("Save Configuration")
        saveConfigButton.addActionListener(SaveConfigAction(self))

        loadConfigButton = JButton("Load Configuration")
        loadConfigButton.addActionListener(LoadConfigAction(self))

        resetConfigButton = JButton("Reset to Defaults")
        resetConfigButton.addActionListener(ResetConfigAction(self))

        configButtonPanel.add(saveConfigButton)
        configButtonPanel.add(loadConfigButton)
        configButtonPanel.add(resetConfigButton)

        panel.add(configButtonPanel, gbc)

        # Fill remaining space
        gbc.gridy = 4
        gbc.fill = GridBagConstraints.BOTH
        gbc.weighty = 1.0
        panel.add(JPanel(), gbc)

        return panel

    def updateStatus(self, message):
        from javax.swing import SwingUtilities
        from java.lang import Runnable

        class UpdateStatusRunnable(Runnable):
            def __init__(self, status_area, msg):
                self.status_area = status_area
                self.msg = msg

            def run(self):
                self.status_area.append(self.msg + "\n")
                self.status_area.setCaretPosition(
                    self.status_area.getDocument().getLength()
                )

        SwingUtilities.invokeLater(UpdateStatusRunnable(self.statusArea, message))

    def addResult(self, url, parameter, payload, xss_type, severity, csp_info, status):
        row = [url, parameter, payload, xss_type, severity, csp_info, status]
        self.resultsTableModel.addRow(row)

    def clearResults(self):
        self.resultsTableModel.setRowCount(0)

    def setProgress(self, value, text=""):
        from javax.swing import SwingUtilities
        from java.lang import Runnable

        class SetProgressRunnable(Runnable):
            def __init__(self, progress_bar, val, txt):
                self.progress_bar = progress_bar
                self.val = val
                self.txt = txt

            def run(self):
                self.progress_bar.setValue(self.val)
                if self.txt:
                    self.progress_bar.setString(self.txt)

        SwingUtilities.invokeLater(SetProgressRunnable(self.progressBar, value, text))

    def addDiscoveredUrl(self, url, status_code=None, method="GET", info=""):
        """Add a discovered URL to the discovered URLs area"""
        from javax.swing import SwingUtilities
        from java.lang import Runnable

        class AddDiscoveredUrlRunnable(Runnable):
            def __init__(
                self, discovered_area, url_val, status, meth, info_val, timestamp
            ):
                self.discovered_area = discovered_area
                self.url_val = url_val
                self.status = status
                self.meth = meth
                self.info_val = info_val
                self.timestamp = timestamp

            def run(self):
                if hasattr(self, "discovered_area") and self.discovered_area:
                    status_text = " (" + str(self.status) + ")" if self.status else ""
                    method_text = "[" + self.meth + "] " if self.meth != "GET" else ""
                    info_text = " - " + self.info_val if self.info_val else ""

                    entry = (
                        self.timestamp
                        + " "
                        + method_text
                        + self.url_val
                        + status_text
                        + info_text
                        + "\n"
                    )
                    self.discovered_area.append(entry)
                    self.discovered_area.setCaretPosition(
                        self.discovered_area.getDocument().getLength()
                    )

        if hasattr(self, "discoveredUrlsArea") and self.discoveredUrlsArea:
            timestamp = self._get_timestamp()
            SwingUtilities.invokeLater(
                AddDiscoveredUrlRunnable(
                    self.discoveredUrlsArea, url, status_code, method, info, timestamp
                )
            )

    def addCSPAnalysis(self, url, csp_header, analysis):
        """Add CSP analysis to the discovered URLs area"""
        if hasattr(self, "discoveredUrlsArea"):
            timestamp = self._get_timestamp()
            self.discoveredUrlsArea.append(
                timestamp + " CSP Analysis for: " + url + "\n"
            )
            if csp_header:
                self.discoveredUrlsArea.append("  CSP Header: " + csp_header + "\n")
            else:
                self.discoveredUrlsArea.append("  No CSP header found\n")

            if analysis:
                for issue in analysis:
                    self.discoveredUrlsArea.append("  - " + issue + "\n")
            else:
                self.discoveredUrlsArea.append("  No CSP issues detected\n")

            self.discoveredUrlsArea.append("\n")
            self.discoveredUrlsArea.setCaretPosition(
                self.discoveredUrlsArea.getDocument().getLength()
            )

    def addEndpointInfo(self, endpoint, parameters=None, forms=None):
        """Add endpoint discovery information"""
        if hasattr(self, "discoveredUrlsArea"):
            timestamp = self._get_timestamp()
            self.discoveredUrlsArea.append(timestamp + " [ENDPOINT] " + endpoint + "\n")

            if parameters:
                self.discoveredUrlsArea.append(
                    "  Parameters: " + ", ".join(parameters) + "\n"
                )

            if forms:
                self.discoveredUrlsArea.append(
                    "  Forms: " + str(len(forms)) + " found\n"
                )
                for form in forms[:3]:  # Show first 3 forms
                    self.discoveredUrlsArea.append("    - " + str(form) + "\n")
                if len(forms) > 3:
                    self.discoveredUrlsArea.append(
                        "    ... and " + str(len(forms) - 3) + " more\n"
                    )

            self.discoveredUrlsArea.append("\n")
            self.discoveredUrlsArea.setCaretPosition(
                self.discoveredUrlsArea.getDocument().getLength()
            )

    def clearDiscoveredUrls(self):
        """Clear the discovered URLs area"""
        if hasattr(self, "discoveredUrlsArea"):
            self.discoveredUrlsArea.setText(
                "Discovered URLs & Endpoints will appear here...\n"
            )

    def addBackendLog(self, message, log_type="INFO"):
        """Add message to backend logs area"""
        from javax.swing import SwingUtilities
        from java.lang import Runnable

        class AddBackendLogRunnable(Runnable):
            def __init__(self, backend_area, msg, log_t, timestamp):
                self.backend_area = backend_area
                self.msg = msg
                self.log_t = log_t
                self.timestamp = timestamp

            def run(self):
                if hasattr(self, "backend_area") and self.backend_area:
                    log_entry = (
                        self.timestamp + " [" + self.log_t + "] " + self.msg + "\n"
                    )
                    self.backend_area.append(log_entry)
                    self.backend_area.setCaretPosition(
                        self.backend_area.getDocument().getLength()
                    )

        if hasattr(self, "backendLogsArea") and self.backendLogsArea:
            timestamp = self._get_timestamp()
            SwingUtilities.invokeLater(
                AddBackendLogRunnable(
                    self.backendLogsArea, message, log_type, timestamp
                )
            )

    def addHttpTraffic(self, method, url, status_code=None, timing=None, error=None):
        """Add HTTP traffic information"""
        from javax.swing import SwingUtilities
        from java.lang import Runnable

        class AddHttpTrafficRunnable(Runnable):
            def __init__(
                self, traffic_area, meth, url_val, status, timing_val, err, timestamp
            ):
                self.traffic_area = traffic_area
                self.meth = meth
                self.url_val = url_val
                self.status = status
                self.timing_val = timing_val
                self.err = err
                self.timestamp = timestamp

            def run(self):
                if hasattr(self, "traffic_area") and self.traffic_area:
                    if self.err:
                        traffic_entry = (
                            self.timestamp
                            + " [ERROR] "
                            + self.meth
                            + " "
                            + self.url_val
                            + " - "
                            + str(self.err)
                            + "\n"
                        )
                    else:
                        status_text = " -> " + str(self.status) if self.status else ""
                        timing_text = (
                            " (" + str(self.timing_val) + "ms)"
                            if self.timing_val
                            else ""
                        )
                        traffic_entry = (
                            self.timestamp
                            + " ["
                            + self.meth
                            + "] "
                            + self.url_val
                            + status_text
                            + timing_text
                            + "\n"
                        )

                    self.traffic_area.append(traffic_entry)
                    self.traffic_area.setCaretPosition(
                        self.traffic_area.getDocument().getLength()
                    )

        if hasattr(self, "httpTrafficArea") and self.httpTrafficArea:
            timestamp = self._get_timestamp()
            SwingUtilities.invokeLater(
                AddHttpTrafficRunnable(
                    self.httpTrafficArea,
                    method,
                    url,
                    status_code,
                    timing,
                    error,
                    timestamp,
                )
            )

    def clearBackendLogs(self):
        """Clear the backend logs area"""
        if hasattr(self, "backendLogsArea"):
            self.backendLogsArea.setText("Backend logs cleared...\n")

    def clearHttpTraffic(self):
        """Clear the HTTP traffic area"""
        if hasattr(self, "httpTrafficArea"):
            self.httpTrafficArea.setText("HTTP traffic logs cleared...\n")

    def _get_timestamp(self):
        """Get current timestamp for logging"""
        import time

        return time.strftime("[%H:%M:%S]")


# Action listeners
class StartScanAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        url = self.tab.urlField.getText()
        if not url:
            self.tab.updateStatus("Error: Please enter a target URL")
            return

        # Start scan in background thread
        scan_thread = threading.Thread(target=self.runScan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()

        self.tab.startScanButton.setEnabled(False)
        self.tab.stopScanButton.setEnabled(True)
        self.tab.updateStatus("Starting scan for: " + url)

    def runScan(self, url):
        try:
            self.tab._scanner.scan_url(url, self.tab)
        except Exception as e:
            self.tab.updateStatus("Scan error: " + str(e))
        finally:
            self.tab.startScanButton.setEnabled(True)
            self.tab.stopScanButton.setEnabled(False)


class StopScanAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        self.tab._scanner.stop_scan()
        self.tab.updateStatus("Scan stopped by user")
        self.tab.startScanButton.setEnabled(True)
        self.tab.stopScanButton.setEnabled(False)


class ClearResultsAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        self.tab.clearResults()
        self.tab.clearDiscoveredUrls()
        self.tab.clearBackendLogs()
        self.tab.clearHttpTraffic()
        self.tab.updateStatus("All results and logs cleared")


class ExportResultsAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for exporting results
        self.tab.updateStatus("Export functionality not yet implemented")


class FilterResultsAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for filtering results
        self.tab.updateStatus("Filter functionality not yet implemented")


class AddPayloadAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for adding custom payload
        self.tab.updateStatus("Add payload functionality not yet implemented")


class RemovePayloadAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for removing custom payload
        self.tab.updateStatus("Remove payload functionality not yet implemented")


class LoadPayloadsAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for loading payloads from file
        self.tab.updateStatus("Load payloads functionality not yet implemented")


class SavePayloadsAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for saving payloads to file
        self.tab.updateStatus("Save payloads functionality not yet implemented")


class SaveConfigAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for saving configuration
        self.tab.updateStatus("Save configuration functionality not yet implemented")


class LoadConfigAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for loading configuration
        self.tab.updateStatus("Load configuration functionality not yet implemented")


class ResetConfigAction(ActionListener):
    def __init__(self, tab):
        self.tab = tab

    def actionPerformed(self, event):
        # Implementation for resetting configuration
        self.tab.updateStatus("Reset configuration functionality not yet implemented")


# Custom cell renderer for severity column
if JAVA_AVAILABLE:

    class SeverityRenderer(DefaultTableCellRenderer):
        def getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        ):
            c = super(SeverityRenderer, self).getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column
            )

            if value == "High":
                c.setBackground(java.awt.Color.RED)
                c.setForeground(java.awt.Color.WHITE)
            elif value == "Medium":
                c.setBackground(java.awt.Color.ORANGE)
                c.setForeground(java.awt.Color.BLACK)
            elif value == "Low":
                c.setBackground(java.awt.Color.YELLOW)
                c.setForeground(java.awt.Color.BLACK)
            elif value == "Info":
                c.setBackground(java.awt.Color.BLUE)
                c.setForeground(java.awt.Color.WHITE)
            else:
                c.setBackground(table.getBackground())
                c.setForeground(table.getForeground())

            return c

else:

    class SeverityRenderer:
        def getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        ):
            return None
