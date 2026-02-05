package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.vista.security.core.*;
import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * TrafficMonitorPanel displays intelligent findings from automatic HTTP traffic analysis.
 * 
 * Features:
 * - Real-time findings display
 * - Smart filtering (URL, severity, type)
 * - Detail view for findings
 * - Statistics dashboard
 * - Integration with VISTA features
 */
public class TrafficMonitorPanel extends JPanel implements TrafficBufferListener {
    
    private final IBurpExtenderCallbacks callbacks;
    private final TrafficBufferManager bufferManager;
    private final TrafficFilterEngine filterEngine;
    private final TrafficMonitorService monitorService;
    private final IntelligentTrafficAnalyzer analyzer;
    private final ScopeManager scopeManager; // NEW: Scope management
    
    // UI Components - Findings View
    private JTable findingsTable;
    private DefaultTableModel findingsTableModel;
    private JTextArea findingDetailsArea;
    private JLabel statsLabel;
    
    // UI Components - Traffic View
    private JTable trafficTable;
    private DefaultTableModel trafficTableModel;
    private JTextArea requestResponseArea;
    
    // UI Components - Controls
    private JTextField urlFilterField;
    private JComboBox<String> severityFilterCombo;
    private JComboBox<String> typeFilterCombo;
    private JComboBox<String> methodFilterCombo;
    private JComboBox<String> detectionEngineFilterCombo; // NEW: Detection engine filter
    private JCheckBox autoAnalyzeCheckbox;
    private JCheckBox scopeEnabledCheckbox; // NEW: Enable scope filtering
    private JButton startStopButton;
    private JButton clearButton;
    private JButton exportButton;
    private JButton manageScopeButton; // NEW: Manage scope button
    
    // Data
    private final List<TrafficFinding> allFindings;
    private final Timer updateTimer;
    private int requestCounter = 0; // NEW: Request numbering
    private boolean firstStart = true; // Track first monitoring start
    private com.vista.security.service.AIService cachedAIService; // Cache AI service to avoid recreating
    
    public TrafficMonitorPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.allFindings = new ArrayList<>();
        
        // Initialize core components
        this.bufferManager = new TrafficBufferManager(1000);
        this.filterEngine = new TrafficFilterEngine();
        this.scopeManager = new ScopeManager(); // NEW: Initialize scope manager
        
        TrafficCaptureListener captureListener = new TrafficCaptureListener(callbacks, bufferManager);
        this.monitorService = new TrafficMonitorService(callbacks, bufferManager, captureListener, 5);
        
        FindingsManager findingsManager = FindingsManager.getInstance();
        // Create real AI service from configuration
        this.cachedAIService = createAIService();
        this.analyzer = new IntelligentTrafficAnalyzer(cachedAIService, findingsManager);
        
        // Set scope manager on analyzer for AI cost control
        this.analyzer.setScopeManager(this.scopeManager);
        
        // Add listener
        bufferManager.addListener(this);
        
        // Initialize UI
        setLayout(new BorderLayout());
        initializeUI();
        
        // Start update timer for batch UI updates
        this.updateTimer = new Timer(1000, e -> refreshUI());
        updateTimer.start();
        
        callbacks.printOutput("[Traffic Monitor] Panel initialized with AI integration and scope management");
    }
    
    private void initializeUI() {
        // Create tabbed pane for Findings and Traffic views
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        
        // Findings tab (primary view)
        JPanel findingsPanel = createFindingsPanel();
        tabbedPane.addTab("  🔍 Findings  ", findingsPanel);
        
        // Traffic tab (secondary view)
        JPanel trafficPanel = createTrafficPanel();
        tabbedPane.addTab("  📊 Traffic  ", trafficPanel);
        
        // Add to main panel
        add(tabbedPane, BorderLayout.CENTER);
        
        // Add controls at top
        add(createControlsPanel(), BorderLayout.NORTH);
        
        // Add statistics at bottom
        add(createStatsPanel(), BorderLayout.SOUTH);
    }
    
    private JPanel createControlsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Start/Stop button
        startStopButton = new JButton("▶ Start Monitoring");
        startStopButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        startStopButton.addActionListener(e -> toggleMonitoring());
        panel.add(startStopButton);
        
        // Auto-analyze checkbox
        autoAnalyzeCheckbox = new JCheckBox("Auto-Analyze", true);
        autoAnalyzeCheckbox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        panel.add(autoAnalyzeCheckbox);
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // HTTP Method filter
        panel.add(new JLabel("Method:"));
        methodFilterCombo = new JComboBox<>(new String[]{"All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"});
        methodFilterCombo.setToolTipText("Filter by HTTP method");
        methodFilterCombo.addActionListener(e -> applyFilters());
        panel.add(methodFilterCombo);
        
        // URL filter
        panel.add(new JLabel("URL:"));
        urlFilterField = new JTextField(15);
        urlFilterField.setToolTipText("Filter by URL pattern (e.g., example.com/api)");
        urlFilterField.addActionListener(e -> applyFilters());
        panel.add(urlFilterField);
        
        // Severity filter
        panel.add(new JLabel("Severity:"));
        severityFilterCombo = new JComboBox<>(new String[]{"All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"});
        severityFilterCombo.addActionListener(e -> applyFilters());
        panel.add(severityFilterCombo);
        
        // Type filter
        panel.add(new JLabel("Type:"));
        typeFilterCombo = new JComboBox<>(new String[]{"All", "SECRET", "HIDDEN_URL", "PARAMETER", "TOKEN", "DEBUG_CODE"});
        typeFilterCombo.addActionListener(e -> applyFilters());
        panel.add(typeFilterCombo);
        
        // Detection Engine filter
        panel.add(new JLabel("Engine:"));
        detectionEngineFilterCombo = new JComboBox<>(new String[]{"All", "🔍 Pattern", "🤖 AI"});
        detectionEngineFilterCombo.setToolTipText("Filter by detection engine");
        detectionEngineFilterCombo.addActionListener(e -> applyFilters());
        panel.add(detectionEngineFilterCombo);
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // Scope controls
        scopeEnabledCheckbox = new JCheckBox("Enable Scope", false);
        scopeEnabledCheckbox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        scopeEnabledCheckbox.setToolTipText("Enable to analyze ONLY in-scope domains (REQUIRED for Traffic Monitor)");
        scopeEnabledCheckbox.addActionListener(e -> {
            boolean enabled = scopeEnabledCheckbox.isSelected();
            scopeManager.setScopeEnabled(enabled);
            
            // Show helpful message when enabling scope
            if (enabled && scopeManager.size() == 0) {
                SwingUtilities.invokeLater(() -> {
                    int result = JOptionPane.showConfirmDialog(
                        this,
                        "Scope is now enabled, but no domains are defined yet.\n\n" +
                        "Would you like to add domains now?\n\n" +
                        "Note: Traffic Monitor will NOT analyze any traffic until\n" +
                        "you add at least one domain to scope.",
                        "Add Domains to Scope?",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.INFORMATION_MESSAGE
                    );
                    
                    if (result == JOptionPane.YES_OPTION) {
                        showScopeManager();
                    }
                });
            }
            
            applyFilters();
        });
        panel.add(scopeEnabledCheckbox);
        
        manageScopeButton = new JButton("⚙️ Manage Scope");
        manageScopeButton.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        manageScopeButton.setToolTipText("Add/remove in-scope domains");
        manageScopeButton.addActionListener(e -> showScopeManager());
        panel.add(manageScopeButton);
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // Clear button
        clearButton = new JButton("🗑 Clear");
        clearButton.addActionListener(e -> clearAll());
        panel.add(clearButton);
        
        // Export button
        exportButton = new JButton("📤 Export");
        exportButton.addActionListener(e -> exportFindings());
        panel.add(exportButton);
        
        return panel;
    }
    
    private JPanel createFindingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Findings table with Detection Engine column
        String[] columnNames = {"Time", "Severity", "Type", "Title", "Category", "Engine", "URL"};
        findingsTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        findingsTable = new JTable(findingsTableModel);
        findingsTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        findingsTable.setRowHeight(25);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.setAutoCreateRowSorter(true); // Enable sorting
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                displayFindingDetails();
            }
        });
        
        // Add keyboard navigation (up/down arrow keys)
        findingsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyPressed(java.awt.event.KeyEvent e) {
                int selectedRow = findingsTable.getSelectedRow();
                int rowCount = findingsTable.getRowCount();
                
                if (e.getKeyCode() == java.awt.event.KeyEvent.VK_UP) {
                    if (selectedRow > 0) {
                        findingsTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
                        findingsTable.scrollRectToVisible(findingsTable.getCellRect(selectedRow - 1, 0, true));
                    }
                    e.consume();
                } else if (e.getKeyCode() == java.awt.event.KeyEvent.VK_DOWN) {
                    if (selectedRow < rowCount - 1) {
                        findingsTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
                        findingsTable.scrollRectToVisible(findingsTable.getCellRect(selectedRow + 1, 0, true));
                    }
                    e.consume();
                }
            }
        });
        
        // Set column widths
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(150); // Time
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(80);  // Severity
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(100); // Type
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(250); // Title
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(120); // Category
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(80);  // Engine
        findingsTable.getColumnModel().getColumn(6).setPreferredWidth(400); // URL
        
        JScrollPane tableScrollPane = new JScrollPane(findingsTable);
        
        // Details area
        findingDetailsArea = new JTextArea();
        findingDetailsArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        findingDetailsArea.setEditable(false);
        findingDetailsArea.setLineWrap(true);
        findingDetailsArea.setWrapStyleWord(true);
        JScrollPane detailsScrollPane = new JScrollPane(findingDetailsArea);
        
        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, detailsScrollPane);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.6);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Enhanced traffic table with all Burp HTTP History columns
        String[] columnNames = {
            "#",           // Request number
            "Host",        // Domain
            "Method",      // HTTP method
            "URL",         // Path
            "Params",      // Has parameters?
            "Status",      // Status code
            "Length",      // Response size
            "MIME",        // Content type
            "Extension",   // File extension
            "Title",       // Page title
            "Time"         // Timestamp
        };
        trafficTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        trafficTable = new JTable(trafficTableModel);
        trafficTable.setFont(new Font("Consolas", Font.PLAIN, 11));
        trafficTable.setRowHeight(22);
        trafficTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        trafficTable.setAutoCreateRowSorter(true); // Enable sorting
        trafficTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                displayTrafficDetails();
            }
        });
        
        // Add keyboard navigation (up/down arrow keys)
        trafficTable.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyPressed(java.awt.event.KeyEvent e) {
                int selectedRow = trafficTable.getSelectedRow();
                int rowCount = trafficTable.getRowCount();
                
                if (e.getKeyCode() == java.awt.event.KeyEvent.VK_UP) {
                    if (selectedRow > 0) {
                        trafficTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
                        trafficTable.scrollRectToVisible(trafficTable.getCellRect(selectedRow - 1, 0, true));
                    }
                    e.consume();
                } else if (e.getKeyCode() == java.awt.event.KeyEvent.VK_DOWN) {
                    if (selectedRow < rowCount - 1) {
                        trafficTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
                        trafficTable.scrollRectToVisible(trafficTable.getCellRect(selectedRow + 1, 0, true));
                    }
                    e.consume();
                }
            }
        });
        
        // Set column widths for better display
        trafficTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        trafficTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Host
        trafficTable.getColumnModel().getColumn(2).setPreferredWidth(60);   // Method
        trafficTable.getColumnModel().getColumn(3).setPreferredWidth(300);  // URL
        trafficTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // Params
        trafficTable.getColumnModel().getColumn(5).setPreferredWidth(60);   // Status
        trafficTable.getColumnModel().getColumn(6).setPreferredWidth(80);   // Length
        trafficTable.getColumnModel().getColumn(7).setPreferredWidth(60);   // MIME
        trafficTable.getColumnModel().getColumn(8).setPreferredWidth(60);   // Extension
        trafficTable.getColumnModel().getColumn(9).setPreferredWidth(200);  // Title
        trafficTable.getColumnModel().getColumn(10).setPreferredWidth(100); // Time
        
        // Add right-click context menu for scope management
        JPopupMenu contextMenu = createTrafficContextMenu();
        trafficTable.setComponentPopupMenu(contextMenu);
        
        // Also add mouse listener to ensure selection before popup
        trafficTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    handlePopup(e);
                }
            }
            
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    handlePopup(e);
                }
            }
            
            private void handlePopup(java.awt.event.MouseEvent e) {
                int row = trafficTable.rowAtPoint(e.getPoint());
                if (row >= 0 && row < trafficTable.getRowCount()) {
                    trafficTable.setRowSelectionInterval(row, row);
                    contextMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        
        JScrollPane tableScrollPane = new JScrollPane(trafficTable);
        
        // Request/Response area
        requestResponseArea = new JTextArea();
        requestResponseArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        requestResponseArea.setEditable(false);
        JScrollPane detailsScrollPane = new JScrollPane(requestResponseArea);
        
        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, detailsScrollPane);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.6);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        // Stats label on the left
        statsLabel = new JLabel("Ready");
        statsLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        panel.add(statsLabel, BorderLayout.WEST);
        
        // Warning panel on the right (initially hidden)
        JPanel warningPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        
        // Clickable warning label
        JLabel warningLabel = new JLabel();
        warningLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        warningLabel.setForeground(new Color(200, 100, 0));
        warningLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        warningLabel.setToolTipText("Click to configure");
        
        // Add click listener to navigate to appropriate tab
        warningLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                String text = warningLabel.getText();
                if (text.contains("AI NOT CONFIGURED")) {
                    // Navigate to Settings tab
                    navigateToSettingsTab();
                } else if (text.contains("SCOPE NOT ENABLED") || text.contains("NO DOMAINS")) {
                    // Show scope manager
                    showScopeManager();
                }
            }
        });
        
        warningPanel.add(warningLabel);
        panel.add(warningPanel, BorderLayout.EAST);
        
        // Update warning based on scope and AI status
        Timer warningTimer = new Timer(1000, e -> {
            boolean aiConfigured = isAIConfigured();
            boolean scopeEnabled = scopeManager.isScopeEnabled();
            int domainsCount = scopeManager.size();
            
            StringBuilder warning = new StringBuilder();
            boolean showWarning = false;
            
            // Check AI configuration first
            if (!aiConfigured) {
                warning.append("⚠️ AI NOT CONFIGURED - Go to Settings to configure AI | ");
                showWarning = true;
            }
            
            // Check scope configuration
            if (!scopeEnabled) {
                warning.append("⚠️ SCOPE NOT ENABLED - Click here to enable scope");
                showWarning = true;
            } else if (domainsCount == 0) {
                warning.append("⚠️ NO DOMAINS IN SCOPE - Click here to add domains");
                showWarning = true;
            }
            
            if (showWarning) {
                warningLabel.setText(warning.toString());
                warningLabel.setVisible(true);
            } else {
                warningLabel.setVisible(false);
            }
        });
        warningTimer.start();
        
        return panel;
    }
    
    /**
     * Navigates to the Settings tab.
     */
    private void navigateToSettingsTab() {
        SwingUtilities.invokeLater(() -> {
            // Get the parent tabbed pane
            Container parent = this.getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) {
                parent = parent.getParent();
            }
            
            if (parent instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) parent;
                // Find Settings tab
                for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                    String title = tabbedPane.getTitleAt(i);
                    if (title != null && title.contains("Settings")) {
                        tabbedPane.setSelectedIndex(i);
                        callbacks.printOutput("[Traffic Monitor] Navigated to Settings tab");
                        
                        // Show helpful message
                        JOptionPane.showMessageDialog(
                            this,
                            "Please configure AI in the Settings tab:\n\n" +
                            "1. Choose your AI provider (OpenAI, Azure AI, or OpenRouter)\n" +
                            "2. Enter your API key\n" +
                            "3. Click 'Test Connection' to verify\n" +
                            "4. Click 'Save Configuration'\n\n" +
                            "After configuration, return to Traffic Monitor and enable scope.",
                            "Configure AI",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                        return;
                    }
                }
                
                // If Settings tab not found
                JOptionPane.showMessageDialog(
                    this,
                    "Please go to the Settings tab (⚙️) to configure AI.",
                    "Configure AI",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        });
    }
    
    private void toggleMonitoring() {
        if (monitorService.isRunning()) {
            monitorService.stop();
            startStopButton.setText("▶ Start Monitoring");
            callbacks.printOutput("[Traffic Monitor] Monitoring stopped");
        } else {
            // Show informational dialog on first start (not blocking)
            if (firstStart) {
                firstStart = false;
                showScopeInformationDialog();
            }
            
            // Always allow monitoring to start
            monitorService.start();
            startStopButton.setText("⏸ Stop Monitoring");
            callbacks.printOutput("[Traffic Monitor] Monitoring started");
            
            // Log current scope status
            if (!scopeManager.isScopeEnabled() || scopeManager.size() == 0) {
                callbacks.printOutput("[Traffic Monitor] ⚠️ Scope not configured - NO traffic will be analyzed");
                callbacks.printOutput("[Traffic Monitor] 💡 Enable scope and add domains to start analyzing traffic");
            } else {
                callbacks.printOutput("[Traffic Monitor] ✅ Scope configured - analyzing in-scope traffic only");
                callbacks.printOutput("[Traffic Monitor] 📋 Domains in scope: " + scopeManager.size());
            }
        }
    }
    
    private void applyFilters() {
        // Apply filters to findings table
        updateFindingsTable();
    }
    
    private void clearAll() {
        int result = JOptionPane.showConfirmDialog(
            this,
            "Clear all findings and traffic data?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        );
        
        if (result == JOptionPane.YES_OPTION) {
            allFindings.clear();
            bufferManager.clear();
            updateFindingsTable();
            updateTrafficTable();
            callbacks.printOutput("[Traffic Monitor] All data cleared");
        }
    }
    
    private void exportFindings() {
        // TODO: Implement export functionality
        JOptionPane.showMessageDialog(this, "Export functionality coming soon!");
    }
    
    private void displayFindingDetails() {
        int selectedRow = findingsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        // Get the finding from the DISPLAYED table, not from allFindings directly
        // because the table may be filtered
        String selectedTime = (String) findingsTableModel.getValueAt(selectedRow, 0);
        String selectedTitle = (String) findingsTableModel.getValueAt(selectedRow, 3);
        
        TrafficFinding finding = null;
        synchronized (allFindings) {
            for (TrafficFinding f : allFindings) {
                if (f.getFormattedTimestamp().equals(selectedTime) && 
                    f.getTitle().equals(selectedTitle)) {
                    finding = f;
                    break;
                }
            }
        }
        
        if (finding == null) {
            findingDetailsArea.setText("Finding not found");
            return;
        }
        
        StringBuilder details = new StringBuilder();
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append("FINDING DETAILS\n");
        details.append("═══════════════════════════════════════════════════════════\n\n");
        
        details.append("Title: ").append(finding.getTitle()).append("\n");
        details.append("Severity: ").append(finding.getSeverity()).append("\n");
        details.append("Type: ").append(finding.getType()).append("\n");
        details.append("Category: ").append(finding.getCategory()).append("\n");
        details.append("Time: ").append(finding.getFormattedTimestamp()).append("\n\n");
        
        details.append("Description:\n");
        details.append(finding.getDescription()).append("\n\n");
        
        details.append("Evidence:\n");
        details.append(finding.getEvidence()).append("\n\n");
        
        details.append("Source URL:\n");
        details.append(finding.getSourceTransaction().getUrl()).append("\n\n");
        
        details.append("═══════════════════════════════════════════════════════════\n");
        
        findingDetailsArea.setText(details.toString());
        findingDetailsArea.setCaretPosition(0);
    }
    
    private void displayTrafficDetails() {
        int selectedRow = trafficTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        // Get the URL from the DISPLAYED table, not from transactions directly
        // because the table may be filtered
        if (selectedRow >= trafficTableModel.getRowCount()) {
            return;
        }
        
        String selectedUrl = (String) trafficTableModel.getValueAt(selectedRow, 3); // URL column
        
        // Find the transaction with this URL
        List<HttpTransaction> transactions = bufferManager.getAllTransactions();
        HttpTransaction transaction = null;
        for (HttpTransaction tx : transactions) {
            if (tx.getUrl().equals(selectedUrl)) {
                transaction = tx;
                break;
            }
        }
        
        if (transaction == null) {
            requestResponseArea.setText("Transaction not found");
            return;
        }
        
        StringBuilder details = new StringBuilder();
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append("REQUEST\n");
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append(new String(transaction.getRequest()));
        details.append("\n\n");
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append("RESPONSE\n");
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append(new String(transaction.getResponse()));
        
        requestResponseArea.setText(details.toString());
        requestResponseArea.setCaretPosition(0);
    }
    
    @Override
    public void onTransactionAdded(HttpTransaction transaction) {
        // Analyze new transaction if auto-analyze is enabled
        if (autoAnalyzeCheckbox.isSelected()) {
            // Determine detection engines
            boolean aiConfigured = isAIConfigured();
            boolean scopeEnabled = scopeManager.isScopeEnabled();
            boolean hasScopeDomains = scopeManager.size() > 0;
            boolean inScope = scopeManager.isInScope(transaction.getUrl());
            
            // Determine detection mode based on scope and AI config
            String detectionMode;
            if (!aiConfigured) {
                detectionMode = "🔍 Pattern Only (AI not configured)";
            } else if (!scopeEnabled) {
                detectionMode = "🔍 Pattern Only (Scope not enabled)";
            } else if (!hasScopeDomains) {
                detectionMode = "🔍 Pattern Only (No domains in scope)";
            } else if (!inScope) {
                detectionMode = "🔍 Pattern Only (Out of Scope)";
            } else {
                detectionMode = "🤖 AI + 🔍 Pattern";
            }
            
            // Show analyzing indicator
            SwingUtilities.invokeLater(() -> {
                statsLabel.setText("🔄 Analyzing [" + detectionMode + "] " + transaction.getUrl() + "...");
            });
            
            // Analyze in background thread to avoid blocking UI
            new Thread(() -> {
                try {
                    callbacks.printOutput("[Traffic Monitor] ═══════════════════════════════════════");
                    callbacks.printOutput("[Traffic Monitor] 🔍 Starting Analysis");
                    callbacks.printOutput("[Traffic Monitor] URL: " + transaction.getUrl());
                    callbacks.printOutput("[Traffic Monitor] Detection Mode: " + detectionMode);
                    callbacks.printOutput("[Traffic Monitor] AI Configured: " + (aiConfigured ? "✅ YES" : "❌ NO"));
                    callbacks.printOutput("[Traffic Monitor] Scope Enabled: " + (scopeEnabled ? "✅ YES" : "❌ NO"));
                    callbacks.printOutput("[Traffic Monitor] Domains in Scope: " + scopeManager.size());
                    if (scopeEnabled && hasScopeDomains) {
                        callbacks.printOutput("[Traffic Monitor] URL In Scope: " + (inScope ? "✅ YES" : "❌ NO"));
                        if (!inScope) {
                            callbacks.printOutput("[Traffic Monitor] 💰 AI analysis will be SKIPPED (cost savings)");
                        }
                    }
                    if (!scopeEnabled || !hasScopeDomains) {
                        callbacks.printOutput("[Traffic Monitor] 💰 AI analysis DISABLED - Enable scope and add domains to use AI");
                    }
                    callbacks.printOutput("[Traffic Monitor] ═══════════════════════════════════════");
                    
                    List<HttpTransaction> batch = new ArrayList<>();
                    batch.add(transaction);
                    List<TrafficFinding> findings = analyzer.analyzeBatch(batch);
                    
                    synchronized (allFindings) {
                        allFindings.addAll(findings);
                    }
                    
                    if (!findings.isEmpty()) {
                        callbacks.printOutput("[Traffic Monitor] ✅ Found " + findings.size() + " issues in " + transaction.getUrl());
                        
                        // Show notification for critical/high findings
                        for (TrafficFinding finding : findings) {
                            if ("CRITICAL".equals(finding.getSeverity()) || "HIGH".equals(finding.getSeverity())) {
                                SwingUtilities.invokeLater(() -> {
                                    JOptionPane.showMessageDialog(
                                        TrafficMonitorPanel.this,
                                        finding.getSeverity() + " finding: " + finding.getTitle() + "\n\n" +
                                        "URL: " + transaction.getUrl(),
                                        "Security Finding Detected",
                                        JOptionPane.WARNING_MESSAGE
                                    );
                                });
                                break; // Only show one notification per transaction
                            }
                        }
                    } else {
                        callbacks.printOutput("[Traffic Monitor] ℹ️ No issues found in " + transaction.getUrl());
                    }
                } catch (Exception e) {
                    callbacks.printError("[Traffic Monitor] Error analyzing transaction: " + e.getMessage());
                } finally {
                    // Update stats to clear analyzing message
                    SwingUtilities.invokeLater(this::updateStats);
                }
            }).start();
        }
    }
    
    @Override
    public void onBufferCleared() {
        SwingUtilities.invokeLater(() -> {
            updateTrafficTable();
        });
    }
    
    private void refreshUI() {
        updateFindingsTable();
        updateTrafficTable();
        updateStats();
    }
    
    private void updateFindingsTable() {
        SwingUtilities.invokeLater(() -> {
            // Save current selection
            int selectedRow = findingsTable.getSelectedRow();
            TrafficFinding selectedFinding = null;
            if (selectedRow >= 0 && selectedRow < findingsTableModel.getRowCount()) {
                // Get the finding ID from the currently displayed table
                String selectedTime = (String) findingsTableModel.getValueAt(selectedRow, 0);
                String selectedTitle = (String) findingsTableModel.getValueAt(selectedRow, 3);
                
                // Find the actual finding object
                synchronized (allFindings) {
                    for (TrafficFinding f : allFindings) {
                        if (f.getFormattedTimestamp().equals(selectedTime) && 
                            f.getTitle().equals(selectedTitle)) {
                            selectedFinding = f;
                            break;
                        }
                    }
                }
            }
            
            findingsTableModel.setRowCount(0);
            
            int rowToSelect = -1;
            int currentRow = 0;
            
            synchronized (allFindings) {
                for (TrafficFinding finding : allFindings) {
                    // Apply scope filter to findings
                    if (scopeManager.isScopeEnabled() && 
                        !scopeManager.isInScope(finding.getSourceTransaction().getUrl())) {
                        continue;
                    }
                    
                    // Apply other filters
                    if (!matchesFilters(finding)) {
                        continue;
                    }
                    
                    findingsTableModel.addRow(new Object[]{
                        finding.getFormattedTimestamp(),
                        finding.getSeverity(),
                        finding.getType(),
                        finding.getTitle(),
                        finding.getCategory(),
                        "AI".equals(finding.getDetectionEngine()) ? "🤖 AI" : "🔍 Pattern",
                        finding.getSourceTransaction().getUrl()
                    });
                    
                    // Check if this was the selected finding
                    if (selectedFinding != null && finding == selectedFinding) {
                        rowToSelect = currentRow;
                    }
                    currentRow++;
                }
            }
            
            // Restore selection
            if (rowToSelect >= 0 && rowToSelect < findingsTableModel.getRowCount()) {
                findingsTable.setRowSelectionInterval(rowToSelect, rowToSelect);
            }
        });
    }
    
    private void updateTrafficTable() {
        SwingUtilities.invokeLater(() -> {
            // Save current selection
            int selectedRow = trafficTable.getSelectedRow();
            String selectedUrl = null;
            if (selectedRow >= 0 && selectedRow < trafficTableModel.getRowCount()) {
                selectedUrl = (String) trafficTableModel.getValueAt(selectedRow, 3); // URL column
            }
            
            trafficTableModel.setRowCount(0);
            
            List<HttpTransaction> transactions = bufferManager.getAllTransactions();
            String methodFilter = (String) methodFilterCombo.getSelectedItem();
            String urlFilter = urlFilterField.getText().trim();
            
            int requestNumber = 1;
            int rowToSelect = -1;
            int currentRow = 0;
            
            for (HttpTransaction tx : transactions) {
                // Apply scope filter
                if (scopeManager.isScopeEnabled() && !scopeManager.isInScope(tx.getUrl())) {
                    continue;
                }
                
                // Apply method filter
                if (!"All".equals(methodFilter)) {
                    if (!methodFilter.equalsIgnoreCase(tx.getMethod())) {
                        continue;
                    }
                }
                
                // Apply URL filter
                if (!urlFilter.isEmpty()) {
                    if (!tx.getUrl().toLowerCase().contains(urlFilter.toLowerCase())) {
                        continue;
                    }
                }
                
                trafficTableModel.addRow(new Object[]{
                    requestNumber++,
                    tx.getHost(),
                    tx.getMethod(),
                    tx.getUrl(),
                    tx.hasParams() ? "✓" : "",
                    tx.getStatusCode(),
                    tx.getFormattedSize(),
                    tx.getShortMimeType(),
                    tx.getExtension(),
                    tx.getTitle(),
                    tx.getFormattedTimestamp()
                });
                
                // Check if this was the selected row
                if (selectedUrl != null && tx.getUrl().equals(selectedUrl)) {
                    rowToSelect = currentRow;
                }
                currentRow++;
            }
            
            // Restore selection
            if (rowToSelect >= 0 && rowToSelect < trafficTableModel.getRowCount()) {
                trafficTable.setRowSelectionInterval(rowToSelect, rowToSelect);
            }
        });
    }
    
    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            int findingsCount = allFindings.size();
            int trafficCount = bufferManager.size();
            long dataVolume = bufferManager.getTotalDataVolume();
            
            int criticalCount = 0;
            int highCount = 0;
            
            synchronized (allFindings) {
                for (TrafficFinding finding : allFindings) {
                    if ("CRITICAL".equals(finding.getSeverity())) {
                        criticalCount++;
                    } else if ("HIGH".equals(finding.getSeverity())) {
                        highCount++;
                    }
                }
            }
            
            // Determine detection mode
            boolean aiConfigured = isAIConfigured();
            String detectionMode = aiConfigured ? "🤖 AI + 🔍 Pattern" : "🔍 Pattern Only";
            
            String status = monitorService.isRunning() ? "🟢 Monitoring" : "🔴 Stopped";
            String stats = String.format(
                "%s [%s] | Findings: %d (Critical: %d, High: %d) | Traffic: %d | Data: %.2f MB",
                status, detectionMode, findingsCount, criticalCount, highCount, trafficCount, dataVolume / 1024.0 / 1024.0
            );
            
            statsLabel.setText(stats);
        });
    }
    
    private boolean matchesFilters(TrafficFinding finding) {
        // URL filter
        String urlFilter = urlFilterField.getText().trim();
        if (!urlFilter.isEmpty()) {
            String url = finding.getSourceTransaction().getUrl();
            if (!url.contains(urlFilter)) {
                return false;
            }
        }
        
        // Severity filter
        String severityFilter = (String) severityFilterCombo.getSelectedItem();
        if (!"All".equals(severityFilter)) {
            if (!severityFilter.equals(finding.getSeverity())) {
                return false;
            }
        }
        
        // Type filter
        String typeFilter = (String) typeFilterCombo.getSelectedItem();
        if (!"All".equals(typeFilter)) {
            if (!typeFilter.equals(finding.getType())) {
                return false;
            }
        }
        
        // Detection Engine filter
        String engineFilter = (String) detectionEngineFilterCombo.getSelectedItem();
        if (!"All".equals(engineFilter)) {
            String findingEngine = "AI".equals(finding.getDetectionEngine()) ? "🤖 AI" : "🔍 Pattern";
            if (!engineFilter.equals(findingEngine)) {
                return false;
            }
        }
        
        return true;
    }
    
    public void cleanup() {
        if (updateTimer != null) {
            updateTimer.stop();
        }
        if (monitorService != null) {
            monitorService.stop();
        }
    }
    
    /**
     * Manually capture a message (called from context menu).
     * 
     * @param message The HTTP message to capture
     */
    public void captureMessage(IHttpRequestResponse message) {
        if (message == null) {
            return;
        }
        
        // Use the capture listener to process the message
        SwingUtilities.invokeLater(() -> {
            try {
                // Create transaction directly
                String id = java.util.UUID.randomUUID().toString();
                long timestamp = System.currentTimeMillis();
                
                byte[] request = message.getRequest();
                byte[] response = message.getResponse();
                
                if (request == null || response == null) {
                    callbacks.printError("[Traffic Monitor] Incomplete message - missing request or response");
                    return;
                }
                
                // Parse request
                burp.IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(request);
                String method = extractMethod(requestInfo);
                String path = extractUrl(request);
                
                // Build full URL with host information
                String fullUrl = buildFullUrl(message, path);
                
                // Parse response
                burp.IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
                int statusCode = extractStatusCode(responseInfo);
                String contentType = extractContentType(responseInfo);
                long responseSize = response.length - responseInfo.getBodyOffset();
                
                // Create transaction
                HttpTransaction transaction = new HttpTransaction(
                    id, timestamp, method, fullUrl, contentType, statusCode,
                    responseSize, request, response, message
                );
                
                // Add to buffer
                bufferManager.addTransaction(transaction);
                
                callbacks.printOutput("[Traffic Monitor] Captured: " + method + " " + fullUrl);
                
            } catch (Exception e) {
                callbacks.printError("[Traffic Monitor] Error capturing message: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }
    
    /**
     * Builds full URL from IHttpService and path.
     * 
     * @param message The HTTP message containing service info
     * @param path The request path
     * @return Full URL (e.g., https://example.com:443/api/users)
     */
    private String buildFullUrl(IHttpRequestResponse message, String path) {
        try {
            burp.IHttpService httpService = message.getHttpService();
            if (httpService == null) {
                return path;
            }
            
            String protocol = httpService.getProtocol();
            String host = httpService.getHost();
            int port = httpService.getPort();
            
            // Build URL
            StringBuilder url = new StringBuilder();
            url.append(protocol).append("://").append(host);
            
            // Add port if non-standard
            if ((protocol.equals("https") && port != 443) || 
                (protocol.equals("http") && port != 80)) {
                url.append(":").append(port);
            }
            
            // Add path
            if (!path.startsWith("/")) {
                url.append("/");
            }
            url.append(path);
            
            return url.toString();
            
        } catch (Exception e) {
            return path;
        }
    }
    
    private String extractMethod(burp.IRequestInfo requestInfo) {
        try {
            java.util.List<String> headers = requestInfo.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                if (parts.length > 0) {
                    return parts[0];
                }
            }
        } catch (Exception e) {
        }
        return "GET";
    }
    
    private int extractStatusCode(burp.IResponseInfo responseInfo) {
        try {
            java.util.List<String> headers = responseInfo.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                if (parts.length > 1) {
                    return Integer.parseInt(parts[1]);
                }
            }
        } catch (Exception e) {
        }
        return 200;
    }
    
    private String extractUrl(byte[] request) {
        try {
            burp.IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(request);
            java.util.List<String> headers = requestInfo.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                if (parts.length > 1) {
                    return parts[1];
                }
            }
        } catch (Exception e) {
        }
        return "unknown";
    }
    
    private String extractContentType(burp.IResponseInfo responseInfo) {
        try {
            java.util.List<String> headers = responseInfo.getHeaders();
            if (headers == null) {
                return null;
            }
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    String value = header.substring(13).trim();
                    int semicolon = value.indexOf(';');
                    if (semicolon > 0) {
                        value = value.substring(0, semicolon).trim();
                    }
                    return value;
                }
            }
        } catch (Exception e) {
        }
        return null;
    }
    
    /**
     * Creates context menu for traffic table with scope management options.
     */
    private JPopupMenu createTrafficContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        
        JMenuItem addToScopeItem = new JMenuItem("➕ Add Host to Scope");
        addToScopeItem.addActionListener(e -> {
            int selectedRow = trafficTable.getSelectedRow();
            if (selectedRow >= 0) {
                List<HttpTransaction> transactions = bufferManager.getAllTransactions();
                if (selectedRow < transactions.size()) {
                    HttpTransaction tx = transactions.get(selectedRow);
                    String host = tx.getHost();
                    scopeManager.addScope(host);
                    callbacks.printOutput("[Traffic Monitor] Added to scope: " + host);
                    JOptionPane.showMessageDialog(
                        this,
                        "Added to scope: " + host + "\n\nEnable scope filtering to see only in-scope traffic.",
                        "Scope Updated",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            }
        });
        
        JMenuItem addDomainToScopeItem = new JMenuItem("➕ Add Domain to Scope (*.domain.com)");
        addDomainToScopeItem.addActionListener(e -> {
            int selectedRow = trafficTable.getSelectedRow();
            if (selectedRow >= 0) {
                List<HttpTransaction> transactions = bufferManager.getAllTransactions();
                if (selectedRow < transactions.size()) {
                    HttpTransaction tx = transactions.get(selectedRow);
                    String host = tx.getHost();
                    // Extract domain (remove subdomain)
                    String[] parts = host.split("\\.");
                    String domain = parts.length >= 2 
                        ? parts[parts.length - 2] + "." + parts[parts.length - 1]
                        : host;
                    String pattern = "*." + domain;
                    scopeManager.addScope(pattern);
                    callbacks.printOutput("[Traffic Monitor] Added to scope: " + pattern);
                    JOptionPane.showMessageDialog(
                        this,
                        "Added to scope: " + pattern + "\n\nThis will match all subdomains.\nEnable scope filtering to see only in-scope traffic.",
                        "Scope Updated",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            }
        });
        
        menu.add(addToScopeItem);
        menu.add(addDomainToScopeItem);
        menu.addSeparator();
        
        JMenuItem manageScopeItem = new JMenuItem("⚙️ Manage Scope...");
        manageScopeItem.addActionListener(e -> showScopeManager());
        menu.add(manageScopeItem);
        
        return menu;
    }
    
    /**
     * Shows the scope manager dialog.
     */
    private void showScopeManager() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Scope Manager", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(600, 400);
        dialog.setLocationRelativeTo(this);
        
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        JLabel titleLabel = new JLabel("In-Scope Domains");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        JLabel subtitleLabel = new JLabel("Add domains to filter traffic. Supports wildcards (*.example.com)");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        subtitleLabel.setForeground(Color.GRAY);
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(subtitleLabel, BorderLayout.SOUTH);
        
        // Scope list
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (String scope : scopeManager.getScopes()) {
            listModel.addElement(scope);
        }
        JList<String> scopeList = new JList<>(listModel);
        scopeList.setFont(new Font("Consolas", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(scopeList);
        
        // Add/Remove panel
        JPanel controlPanel = new JPanel(new BorderLayout(5, 5));
        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        JPanel addPanel = new JPanel(new BorderLayout(5, 0));
        JTextField addField = new JTextField();
        addField.setToolTipText("Enter domain (e.g., example.com or *.example.com)");
        JButton addButton = new JButton("➕ Add");
        addButton.addActionListener(e -> {
            String domain = addField.getText().trim();
            if (!domain.isEmpty()) {
                scopeManager.addScope(domain);
                listModel.addElement(domain);
                addField.setText("");
                callbacks.printOutput("[Traffic Monitor] Added to scope: " + domain);
            }
        });
        addField.addActionListener(e -> addButton.doClick());
        addPanel.add(addField, BorderLayout.CENTER);
        addPanel.add(addButton, BorderLayout.EAST);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton removeButton = new JButton("➖ Remove Selected");
        removeButton.addActionListener(e -> {
            String selected = scopeList.getSelectedValue();
            if (selected != null) {
                scopeManager.removeScope(selected);
                listModel.removeElement(selected);
                callbacks.printOutput("[Traffic Monitor] Removed from scope: " + selected);
            }
        });
        
        JButton clearButton = new JButton("🗑 Clear All");
        clearButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                dialog,
                "Remove all scope rules?",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION
            );
            if (result == JOptionPane.YES_OPTION) {
                scopeManager.clearScopes();
                listModel.clear();
                callbacks.printOutput("[Traffic Monitor] Cleared all scope rules");
            }
        });
        
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> {
            dialog.dispose();
            applyFilters(); // Refresh traffic table
        });
        
        buttonPanel.add(removeButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(closeButton);
        
        controlPanel.add(addPanel, BorderLayout.NORTH);
        controlPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Info panel
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        JTextArea infoArea = new JTextArea(
            "💡 Tips:\n" +
            "• example.com - Matches any URL containing 'example.com'\n" +
            "• *.example.com - Matches all subdomains of example.com\n" +
            "• api.example.com - Matches specific subdomain\n" +
            "• Right-click traffic entries for quick scope addition\n" +
            "• Enable 'Enable Scope' checkbox to activate filtering"
        );
        infoArea.setEditable(false);
        infoArea.setBackground(new Color(245, 245, 245));
        infoArea.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        infoPanel.add(infoArea, BorderLayout.CENTER);
        
        dialog.add(headerPanel, BorderLayout.NORTH);
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(controlPanel, BorderLayout.SOUTH);
        dialog.add(infoPanel, BorderLayout.EAST);
        
        dialog.setVisible(true);
    }
    
    /**
     * Creates AI service from current configuration.
     * 
     * @return Configured AI service instance
     */
    private com.vista.security.service.AIService createAIService() {
        AIConfigManager config = AIConfigManager.getInstance();
        
        if (!config.isConfigured()) {
            callbacks.printOutput("[Traffic Monitor] AI not configured, using pattern-based detection only");
            return new DummyAIService();
        }
        
        try {
            if ("Azure AI".equalsIgnoreCase(config.getProvider())) {
                com.vista.security.service.AzureAIService.Configuration azureConfig = 
                    new com.vista.security.service.AzureAIService.Configuration();
                azureConfig.setEndpoint(config.getEndpoint());
                azureConfig.setDeploymentName(config.getDeployment());
                azureConfig.setApiKey(config.getAzureApiKey());
                azureConfig.setTemperature(config.getTemperature());
                // Removed misleading log - only log when AI is actually USED
                return new com.vista.security.service.AzureAIService(azureConfig);
                
            } else if ("OpenRouter".equalsIgnoreCase(config.getProvider())) {
                com.vista.security.service.OpenRouterService.Configuration openRouterConfig = 
                    new com.vista.security.service.OpenRouterService.Configuration();
                openRouterConfig.setApiKey(config.getOpenRouterApiKey());
                openRouterConfig.setModel(config.getOpenRouterModel());
                openRouterConfig.setTemperature(config.getTemperature());
                // Removed misleading log - only log when AI is actually USED
                return new com.vista.security.service.OpenRouterService(openRouterConfig);
                
            } else {
                com.vista.security.service.OpenAIService.Configuration openaiConfig = 
                    new com.vista.security.service.OpenAIService.Configuration();
                openaiConfig.setApiKey(config.getOpenAIApiKey());
                openaiConfig.setModel(config.getModel());
                openaiConfig.setTemperature(config.getTemperature());
                // Removed misleading log - only log when AI is actually USED
                return new com.vista.security.service.OpenAIService(openaiConfig);
            }
        } catch (Exception e) {
            callbacks.printError("[Traffic Monitor] Error creating AI service: " + e.getMessage());
            return new DummyAIService();
        }
    }
    
    /**
     * Checks if AI is configured without creating a new service instance.
     * 
     * @return True if AI is configured, false otherwise
     */
    private boolean isAIConfigured() {
        return cachedAIService != null && !cachedAIService.getClass().getSimpleName().equals("DummyAIService");
    }
    
    /**
     * Shows informational dialog explaining how Traffic Monitor works.
     * This is NOT blocking - user can start monitoring and add scope later.
     */
    private void showScopeInformationDialog() {
        SwingUtilities.invokeLater(() -> {
            JPanel panel = new JPanel(new BorderLayout(10, 10));
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            
            // Title
            JLabel titleLabel = new JLabel("ℹ️ How Traffic Monitor Works");
            titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
            titleLabel.setForeground(new Color(0, 100, 200));
            
            // Message
            JTextArea messageArea = new JTextArea();
            messageArea.setEditable(false);
            messageArea.setBackground(panel.getBackground());
            messageArea.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            messageArea.setLineWrap(true);
            messageArea.setWrapStyleWord(true);
            
            boolean aiConfigured = isAIConfigured();
            boolean scopeEnabled = scopeManager.isScopeEnabled();
            int domainsCount = scopeManager.size();
            
            String message = "Traffic Monitor is now running and capturing traffic.\n\n";
            message += "📋 CURRENT STATUS:\n";
            message += "   • Monitoring: ✅ ACTIVE\n";
            message += "   • Scope Enabled: " + (scopeEnabled ? "✅ YES" : "❌ NO") + "\n";
            message += "   • Domains in Scope: " + domainsCount + "\n";
            message += "   • AI Configured: " + (aiConfigured ? "✅ YES" : "❌ NO") + "\n\n";
            
            if (!scopeEnabled || domainsCount == 0) {
                message += "⚠️ IMPORTANT:\n";
                message += "   Traffic is being captured but NOT analyzed yet.\n";
                message += "   You need to configure scope to start analysis.\n\n";
            }
            
            message += "🎯 HOW IT WORKS:\n";
            message += "   1. Traffic Monitor captures all HTTP traffic\n";
            message += "   2. You can browse and add domains to scope anytime\n";
            message += "   3. Once scope is configured, analysis starts automatically\n";
            message += "   4. Only in-scope traffic will be analyzed\n\n";
            
            message += "💡 TO START ANALYSIS:\n";
            message += "   1. Browse your target website\n";
            message += "   2. Right-click traffic entries → 'Add to Scope'\n";
            message += "   3. Or click '⚙️ Manage Scope' to add domains manually\n";
            message += "   4. Check '☑ Enable Scope' checkbox\n";
            message += "   5. Analysis will start automatically for in-scope traffic\n\n";
            
            message += "💰 COST CONTROL:\n";
            message += "   • Pattern Detection: FREE (for in-scope domains)\n";
            message += "   • AI Analysis: PAID (~$0.01 per request, for in-scope domains)\n";
            message += "   • Out-of-scope traffic: NOT analyzed (no cost)\n";
            
            messageArea.setText(message);
            
            panel.add(titleLabel, BorderLayout.NORTH);
            panel.add(messageArea, BorderLayout.CENTER);
            
            // Buttons
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton manageScopeBtn = new JButton("⚙️ Manage Scope");
            manageScopeBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
            manageScopeBtn.addActionListener(e -> {
                Window window = SwingUtilities.getWindowAncestor(panel);
                if (window != null) {
                    window.dispose();
                }
                showScopeManager();
            });
            
            JButton okBtn = new JButton("Got It");
            okBtn.addActionListener(e -> {
                Window window = SwingUtilities.getWindowAncestor(panel);
                if (window != null) {
                    window.dispose();
                }
            });
            
            buttonPanel.add(manageScopeBtn);
            buttonPanel.add(okBtn);
            panel.add(buttonPanel, BorderLayout.SOUTH);
            
            JOptionPane.showMessageDialog(
                this,
                panel,
                "Traffic Monitor - How It Works",
                JOptionPane.INFORMATION_MESSAGE
            );
        });
    }
    
    /**
     * Shows dialog explaining scope is required for Traffic Monitor.
     * This is NOT blocking - user can start monitoring and add scope later.
     */
    private void showScopeRequiredDialog() {
        SwingUtilities.invokeLater(() -> {
            JPanel panel = new JPanel(new BorderLayout(10, 10));
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            
            // Title
            JLabel titleLabel = new JLabel("⚠️ Scope Configuration Required");
            titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
            titleLabel.setForeground(new Color(200, 100, 0));
            
            // Message
            JTextArea messageArea = new JTextArea();
            messageArea.setEditable(false);
            messageArea.setBackground(panel.getBackground());
            messageArea.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            messageArea.setLineWrap(true);
            messageArea.setWrapStyleWord(true);
            
            boolean aiConfigured = isAIConfigured();
            
            String message = "Traffic Monitor requires scope configuration to prevent unnecessary costs.\n\n";
            message += "📋 CURRENT STATUS:\n";
            message += "   • Scope Enabled: " + (scopeManager.isScopeEnabled() ? "✅ YES" : "❌ NO") + "\n";
            message += "   • Domains in Scope: " + scopeManager.size() + "\n";
            message += "   • AI Configured: " + (aiConfigured ? "✅ YES" : "❌ NO") + "\n\n";
            message += "🎯 REQUIRED STEPS:\n";
            message += "   1. Check the 'Enable Scope' checkbox\n";
            message += "   2. Click '⚙️ Manage Scope' button\n";
            message += "   3. Add your target domains (e.g., example.com)\n";
            message += "   4. Click 'Start Monitoring' again\n\n";
            message += "💡 WHY IS THIS REQUIRED?\n";
            message += "   • Prevents analyzing unwanted traffic\n";
            message += "   • Saves AI API costs (only analyze what you need)\n";
            message += "   • Focuses findings on your target domains\n\n";
            message += "💰 COST CONTROL:\n";
            message += "   • Pattern Detection: FREE (always active for in-scope domains)\n";
            message += "   • AI Analysis: PAID (~$0.01 per request, only for in-scope domains)\n";
            
            messageArea.setText(message);
            
            panel.add(titleLabel, BorderLayout.NORTH);
            panel.add(messageArea, BorderLayout.CENTER);
            
            // Buttons
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton manageScopeBtn = new JButton("⚙️ Manage Scope Now");
            manageScopeBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
            manageScopeBtn.addActionListener(e -> {
                Window window = SwingUtilities.getWindowAncestor(panel);
                if (window != null) {
                    window.dispose();
                }
                showScopeManager();
            });
            
            JButton cancelBtn = new JButton("Cancel");
            cancelBtn.addActionListener(e -> {
                Window window = SwingUtilities.getWindowAncestor(panel);
                if (window != null) {
                    window.dispose();
                }
            });
            
            buttonPanel.add(manageScopeBtn);
            buttonPanel.add(cancelBtn);
            panel.add(buttonPanel, BorderLayout.SOUTH);
            
            JOptionPane.showMessageDialog(
                this,
                panel,
                "Scope Configuration Required",
                JOptionPane.WARNING_MESSAGE
            );
        });
    }
    
    /**
     * Checks AI configuration and prompts user if not configured.
     */
    private void checkAIConfiguration() {
        AIConfigManager config = AIConfigManager.getInstance();
        
        if (!config.isConfigured()) {
            SwingUtilities.invokeLater(() -> {
                int result = JOptionPane.showConfirmDialog(
                    this,
                    "Traffic Monitor AI Analysis Not Configured\n\n" +
                    "The Traffic Monitor can use AI to perform deep analysis of JavaScript files\n" +
                    "and detect security issues that pattern matching might miss.\n\n" +
                    "Current Status:\n" +
                    "✅ Pattern-based detection: ACTIVE (API keys, secrets, tokens, etc.)\n" +
                    "❌ AI deep analysis: NOT CONFIGURED\n\n" +
                    "Would you like to configure AI now?\n\n" +
                    "Note: Pattern-based detection works without AI configuration.",
                    "AI Configuration",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.INFORMATION_MESSAGE
                );
                
                if (result == JOptionPane.YES_OPTION) {
                    JOptionPane.showMessageDialog(
                        this,
                        "Please configure AI in the Settings tab:\n\n" +
                        "1. Go to the '⚙️ Settings' tab\n" +
                        "2. Choose your AI provider (OpenAI, Azure AI, or OpenRouter)\n" +
                        "3. Enter your API key\n" +
                        "4. Click 'Test Connection' to verify\n" +
                        "5. Click 'Save Configuration'\n\n" +
                        "After configuration, restart the Traffic Monitor for AI analysis.",
                        "Configure AI",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            });
        }
    }
    
    /**
     * Dummy AI service for when AI is not configured.
     * Pattern-based detection still works without AI.
     */
    private static class DummyAIService implements com.vista.security.service.AIService {
        @Override
        public String ask(String systemPrompt, String userPrompt) throws Exception {
            // Pattern-based detection works without AI
            return "";
        }
        
        @Override
        public String testConnection() throws Exception {
            return "Pattern-based detection only (AI not configured)";
        }
    }
}
