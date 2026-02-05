package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.vista.security.core.*;
import com.vista.security.model.HttpTransaction;
import com.vista.security.model.PromptTemplate;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Simplified Traffic Monitor with AI Analysis.
 * 
 * Features:
 * - Real-time traffic capture
 * - Scope-based filtering (domain/subdomain)
 * - Traffic table display
 * - Request/Response viewer
 * - AI-based analysis for JavaScript/HTML files (in-scope only)
 */
public class TrafficMonitorPanelSimple extends JPanel implements TrafficBufferListener {
    
    private final IBurpExtenderCallbacks callbacks;
    private final TrafficBufferManager bufferManager;
    private final TrafficMonitorService monitorService;
    private final ScopeManager scopeManager;
    private final TrafficAIAnalyzer aiAnalyzer;
    
    // UI Components
    private JTabbedPane tabbedPane;
    private JTable trafficTable;
    private DefaultTableModel trafficTableModel;
    private JTextArea requestResponseArea;
    private JTable findingsTable;
    private DefaultTableModel findingsTableModel;
    private JTextArea findingDetailsArea;
    private JLabel statsLabel;
    private JLabel aiStatsLabel;
    
    // UI Controls
    private JTextField urlFilterField;
    private JComboBox<String> methodFilterCombo;
    private JCheckBox scopeEnabledCheckbox;
    private JCheckBox aiEnabledCheckbox;
    private JButton startStopButton;
    private JButton clearButton;
    private JButton manageScopeButton;
    private JButton configureAIButton;
    private JComboBox<String> templateCombo;
    private JButton editTemplateButton;
    
    // Data
    private int requestCounter = 0;
    private boolean reverseOrder = false; // Toggle for sort order (not renumbering!)
    private java.util.Set<Integer> highlightedRows = new java.util.HashSet<>(); // Track highlighted row numbers
    private java.util.Map<HttpTransaction, Integer> transactionToRequestNumber = new java.util.HashMap<>(); // Map transaction to original request number
    private final List<TrafficAIAnalyzer.TrafficFinding> findings = new ArrayList<>();
    
    public TrafficMonitorPanelSimple(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        // Initialize core components
        this.bufferManager = new TrafficBufferManager(1000);
        this.scopeManager = new ScopeManager();
        this.aiAnalyzer = new TrafficAIAnalyzer(callbacks, scopeManager);
        
        TrafficCaptureListener captureListener = new TrafficCaptureListener(callbacks, bufferManager);
        this.monitorService = new TrafficMonitorService(callbacks, bufferManager, captureListener, 5);
        
        // Add listeners
        bufferManager.addListener(this);
        aiAnalyzer.addListener(finding -> {
            SwingUtilities.invokeLater(() -> addFinding(finding));
        });
        
        // Initialize UI
        setLayout(new BorderLayout());
        initializeUI();
        
        callbacks.printOutput("[Traffic Monitor] Simple panel with AI analysis initialized");
    }
    
    private void initializeUI() {
        // Add controls at top
        add(createControlsPanel(), BorderLayout.NORTH);
        
        // Add tabbed pane in center
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Traffic", createTrafficPanel());
        tabbedPane.addTab("AI Findings", createFindingsPanel());
        add(tabbedPane, BorderLayout.CENTER);
        
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
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // HTTP Method filter
        panel.add(new JLabel("Method:"));
        methodFilterCombo = new JComboBox<>(new String[]{"All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"});
        methodFilterCombo.setToolTipText("Filter by HTTP method");
        methodFilterCombo.addActionListener(e -> applyFilters());
        panel.add(methodFilterCombo);
        
        // URL filter
        panel.add(new JLabel("URL:"));
        urlFilterField = new JTextField(20);
        urlFilterField.setToolTipText("Filter by URL pattern (e.g., example.com/api)");
        urlFilterField.addActionListener(e -> applyFilters());
        panel.add(urlFilterField);
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // Scope controls
        scopeEnabledCheckbox = new JCheckBox("Enable Scope Filter", false);
        scopeEnabledCheckbox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        scopeEnabledCheckbox.setToolTipText("Filter traffic to show only in-scope domains");
        scopeEnabledCheckbox.addActionListener(e -> {
            scopeManager.setScopeEnabled(scopeEnabledCheckbox.isSelected());
            applyFilters();
        });
        panel.add(scopeEnabledCheckbox);
        
        manageScopeButton = new JButton("⚙️ Manage Scope");
        manageScopeButton.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        manageScopeButton.setToolTipText("Add/remove in-scope domains");
        manageScopeButton.addActionListener(e -> showScopeManager());
        panel.add(manageScopeButton);
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // AI Analysis controls
        aiEnabledCheckbox = new JCheckBox("Enable AI Analysis", false);
        aiEnabledCheckbox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        aiEnabledCheckbox.setToolTipText("Enable AI-based analysis of JavaScript/HTML files (requires scope + AI config)");
        aiEnabledCheckbox.addActionListener(e -> {
            aiAnalyzer.setEnabled(aiEnabledCheckbox.isSelected());
            updateStats();
        });
        panel.add(aiEnabledCheckbox);
        
        // Template selection
        panel.add(new JLabel("Template:"));
        templateCombo = new JComboBox<>();
        templateCombo.setToolTipText("Select AI analysis template");
        loadTemplates();
        templateCombo.addActionListener(e -> {
            String selected = (String) templateCombo.getSelectedItem();
            if (selected != null) {
                PromptTemplate template = PromptTemplateManager.getInstance().getTemplateByName(selected);
                if (template != null) {
                    aiAnalyzer.setTemplate(template.getId());
                    callbacks.printOutput("[Traffic Monitor] Using template: " + selected);
                }
            }
        });
        panel.add(templateCombo);
        
        editTemplateButton = new JButton("✏️ Edit");
        editTemplateButton.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        editTemplateButton.setToolTipText("Edit selected template");
        editTemplateButton.addActionListener(e -> editSelectedTemplate());
        panel.add(editTemplateButton);
        
        configureAIButton = new JButton("🤖 Configure AI");
        configureAIButton.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        configureAIButton.setToolTipText("Configure AI analysis settings");
        configureAIButton.addActionListener(e -> showAIConfiguration());
        panel.add(configureAIButton);
        
        panel.add(new JSeparator(SwingConstants.VERTICAL));
        
        // Clear button
        clearButton = new JButton("🗑 Clear");
        clearButton.addActionListener(e -> clearAll());
        panel.add(clearButton);
        
        return panel;
    }
    
    private JPanel createTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Traffic table
        String[] columnNames = {
            "#",           // Request number
            "Host",        // Domain
            "Method",      // HTTP method
            "URL",         // Full URL
            "Params",      // Has parameters?
            "Status",      // Status code
            "Length",      // Response size
            "MIME",        // Content type
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
        trafficTable.setAutoCreateRowSorter(true);
        trafficTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                displayTrafficDetails();
            }
        });
        
        // Add custom cell renderer for highlighting
        trafficTable.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(
                    javax.swing.JTable table, Object value, boolean isSelected, 
                    boolean hasFocus, int row, int column) {
                java.awt.Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
                
                // Get the request number from column 0
                Object reqNumObj = table.getValueAt(row, 0);
                if (reqNumObj instanceof Integer) {
                    int reqNum = (Integer) reqNumObj;
                    if (highlightedRows.contains(reqNum)) {
                        // Highlighted row - use orange background
                        if (!isSelected) {
                            c.setBackground(new Color(255, 200, 100));
                        }
                    } else {
                        // Normal row
                        if (!isSelected) {
                            c.setBackground(table.getBackground());
                        }
                    }
                }
                
                return c;
            }
        });
        
        // Add double-click listener on # column header to toggle sort order
        trafficTable.getTableHeader().addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int column = trafficTable.columnAtPoint(e.getPoint());
                    if (column == 0) { // # column
                        reverseOrder = !reverseOrder;
                        callbacks.printOutput("[Traffic Monitor] Sort order: " + 
                            (reverseOrder ? "Newest First" : "Oldest First"));
                        updateTrafficTable();
                    }
                }
            }
        });
        
        // Add double-click listener on # column cells to toggle highlight
        trafficTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = trafficTable.rowAtPoint(e.getPoint());
                    int column = trafficTable.columnAtPoint(e.getPoint());
                    if (row >= 0 && column == 0) { // # column
                        Object reqNumObj = trafficTable.getValueAt(row, 0);
                        if (reqNumObj instanceof Integer) {
                            int reqNum = (Integer) reqNumObj;
                            if (highlightedRows.contains(reqNum)) {
                                highlightedRows.remove(reqNum);
                                callbacks.printOutput("[Traffic Monitor] Unhighlighted request #" + reqNum);
                            } else {
                                highlightedRows.add(reqNum);
                                callbacks.printOutput("[Traffic Monitor] Highlighted request #" + reqNum);
                            }
                            trafficTable.repaint();
                        }
                    }
                }
            }
        });
        
        // Set column widths
        trafficTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        trafficTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Host
        trafficTable.getColumnModel().getColumn(2).setPreferredWidth(60);   // Method
        trafficTable.getColumnModel().getColumn(3).setPreferredWidth(400);  // URL
        trafficTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // Params
        trafficTable.getColumnModel().getColumn(5).setPreferredWidth(60);   // Status
        trafficTable.getColumnModel().getColumn(6).setPreferredWidth(80);   // Length
        trafficTable.getColumnModel().getColumn(7).setPreferredWidth(80);   // MIME
        trafficTable.getColumnModel().getColumn(8).setPreferredWidth(100);  // Time
        
        // Add right-click context menu
        JPopupMenu contextMenu = createTrafficContextMenu();
        trafficTable.setComponentPopupMenu(contextMenu);
        
        JScrollPane tableScrollPane = new JScrollPane(trafficTable);
        
        // Request/Response area
        requestResponseArea = new JTextArea();
        requestResponseArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        requestResponseArea.setEditable(false);
        JScrollPane detailsScrollPane = new JScrollPane(requestResponseArea);
        
        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, detailsScrollPane);
        splitPane.setDividerLocation(400);
        splitPane.setResizeWeight(0.6);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        statsLabel = new JLabel("Ready");
        statsLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        panel.add(statsLabel, BorderLayout.WEST);
        
        aiStatsLabel = new JLabel("AI: Disabled");
        aiStatsLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        panel.add(aiStatsLabel, BorderLayout.EAST);
        
        return panel;
    }
    
    private JPanel createFindingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Findings table
        String[] columnNames = {
            "Time",        // Timestamp
            "Severity",    // CRITICAL, HIGH, MEDIUM, LOW
            "Type",        // Finding type
            "Finding",     // Short description
            "URL"          // Source URL
        };
        findingsTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        findingsTable = new JTable(findingsTableModel);
        findingsTable.setFont(new Font("Consolas", Font.PLAIN, 11));
        findingsTable.setRowHeight(22);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                displayFindingDetails();
            }
        });
        
        // Color code by severity
        findingsTable.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(
                    javax.swing.JTable table, Object value, boolean isSelected, 
                    boolean hasFocus, int row, int column) {
                java.awt.Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
                
                if (!isSelected) {
                    String severity = (String) table.getValueAt(row, 1);
                    switch (severity.toUpperCase()) {
                        case "CRITICAL":
                            c.setBackground(new Color(255, 200, 200));
                            break;
                        case "HIGH":
                            c.setBackground(new Color(255, 220, 180));
                            break;
                        case "MEDIUM":
                            c.setBackground(new Color(255, 255, 200));
                            break;
                        case "LOW":
                            c.setBackground(new Color(220, 255, 220));
                            break;
                        default:
                            c.setBackground(table.getBackground());
                    }
                }
                
                return c;
            }
        });
        
        // Set column widths
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(80);   // Time
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(80);   // Severity
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(120);  // Type
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(300);  // Finding
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(400);  // URL
        
        JScrollPane tableScrollPane = new JScrollPane(findingsTable);
        
        // Finding details area
        findingDetailsArea = new JTextArea();
        findingDetailsArea.setFont(new Font("Consolas", Font.PLAIN, 11));
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
    
    private JPopupMenu createTrafficContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        
        JMenuItem addToScopeItem = new JMenuItem("Add to Scope");
        addToScopeItem.addActionListener(e -> addSelectedToScope());
        menu.add(addToScopeItem);
        
        JMenuItem removeFromScopeItem = new JMenuItem("Remove from Scope");
        removeFromScopeItem.addActionListener(e -> removeSelectedFromScope());
        menu.add(removeFromScopeItem);
        
        menu.addSeparator();
        
        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> sendToRepeater());
        menu.add(sendToRepeaterItem);
        
        return menu;
    }
    
    private void toggleMonitoring() {
        if (monitorService.isRunning()) {
            monitorService.stop();
            startStopButton.setText("▶ Start Monitoring");
            callbacks.printOutput("[Traffic Monitor] Monitoring stopped");
        } else {
            monitorService.start();
            startStopButton.setText("⏸ Stop Monitoring");
            callbacks.printOutput("[Traffic Monitor] Monitoring started");
        }
    }
    
    private void applyFilters() {
        updateTrafficTable();
    }
    
    private void clearAll() {
        int result = JOptionPane.showConfirmDialog(
            this,
            "Clear all traffic data and findings?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        );
        
        if (result == JOptionPane.YES_OPTION) {
            bufferManager.clear();
            requestCounter = 0;
            transactionToRequestNumber.clear();
            highlightedRows.clear();
            findings.clear();
            updateTrafficTable();
            updateFindingsTable();
            callbacks.printOutput("[Traffic Monitor] All data cleared");
        }
    }
    
    private void showAIConfiguration() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "AI Analysis Configuration", true);
        dialog.setSize(500, 300);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(10, 10));
        
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        JLabel titleLabel = new JLabel("AI Analysis Configuration");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        headerPanel.add(titleLabel, BorderLayout.WEST);
        
        // Info panel
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        AIConfigManager aiConfig = AIConfigManager.getInstance();
        
        JLabel statusLabel = new JLabel("Status: " + aiConfig.getStatusMessage());
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        infoPanel.add(statusLabel);
        infoPanel.add(Box.createVerticalStrut(10));
        
        JTextArea infoText = new JTextArea();
        infoText.setEditable(false);
        infoText.setLineWrap(true);
        infoText.setWrapStyleWord(true);
        infoText.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        infoText.setText(
            "AI Analysis Requirements:\n\n" +
            "1. ✓ AI must be configured in Settings tab\n" +
            "2. ✓ Scope must be enabled\n" +
            "3. ✓ At least one domain must be in scope\n" +
            "4. ✓ 'Enable AI Analysis' checkbox must be checked\n\n" +
            "AI will analyze JavaScript and HTML files from in-scope domains only.\n\n" +
            "Findings include:\n" +
            "• Hidden API endpoints\n" +
            "• Hardcoded secrets and API keys\n" +
            "• Hidden parameters\n" +
            "• Debug code\n" +
            "• Sensitive comments\n\n" +
            "Template Customization:\n" +
            "• Select a template from the dropdown\n" +
            "• Click 'Edit' to customize the prompt\n" +
            "• Modify rules to reduce false positives\n" +
            "• Save changes to improve AI accuracy"
        );
        infoPanel.add(new JScrollPane(infoText));
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        JButton openSettingsButton = new JButton("Open Settings");
        openSettingsButton.addActionListener(e -> {
            dialog.dispose();
            // Switch to Settings tab (assuming it's in the parent tabbed pane)
            Container parent = TrafficMonitorPanelSimple.this.getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) {
                parent = parent.getParent();
            }
            if (parent instanceof JTabbedPane) {
                JTabbedPane tabs = (JTabbedPane) parent;
                for (int i = 0; i < tabs.getTabCount(); i++) {
                    if (tabs.getTitleAt(i).equals("Settings")) {
                        tabs.setSelectedIndex(i);
                        break;
                    }
                }
            }
        });
        
        JButton openTemplatesButton = new JButton("Manage Templates");
        openTemplatesButton.addActionListener(e -> {
            dialog.dispose();
            // Switch to Prompt Templates tab
            Container parent = TrafficMonitorPanelSimple.this.getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) {
                parent = parent.getParent();
            }
            if (parent instanceof JTabbedPane) {
                JTabbedPane tabs = (JTabbedPane) parent;
                for (int i = 0; i < tabs.getTabCount(); i++) {
                    if (tabs.getTitleAt(i).equals("Prompt Templates")) {
                        tabs.setSelectedIndex(i);
                        break;
                    }
                }
            }
        });
        
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(openSettingsButton);
        buttonPanel.add(openTemplatesButton);
        buttonPanel.add(closeButton);
        
        dialog.add(headerPanel, BorderLayout.NORTH);
        dialog.add(infoPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setVisible(true);
    }
    
    /**
     * Load available templates into combo box.
     */
    private void loadTemplates() {
        templateCombo.removeAllItems();
        
        PromptTemplateManager templateManager = PromptTemplateManager.getInstance();
        List<PromptTemplate> templates = templateManager.getTemplatesByCategory("Traffic Monitor");
        
        if (templates.isEmpty()) {
            templateCombo.addItem("No templates available");
            templateCombo.setEnabled(false);
            if (editTemplateButton != null) {
                editTemplateButton.setEnabled(false);
            }
        } else {
            for (PromptTemplate template : templates) {
                templateCombo.addItem(template.getName());
            }
            
            // Select default template
            if (templateCombo.getItemCount() > 0) {
                templateCombo.setSelectedIndex(0);
                PromptTemplate firstTemplate = templates.get(0);
                aiAnalyzer.setTemplate(firstTemplate.getId());
            }
            
            templateCombo.setEnabled(true);
            if (editTemplateButton != null) {
                editTemplateButton.setEnabled(true);
            }
        }
    }
    
    /**
     * Edit the selected template.
     */
    private void editSelectedTemplate() {
        String selectedName = (String) templateCombo.getSelectedItem();
        if (selectedName == null || selectedName.equals("No templates available")) {
            return;
        }
        
        PromptTemplateManager templateManager = PromptTemplateManager.getInstance();
        PromptTemplate template = templateManager.getTemplateByName(selectedName);
        
        if (template == null) {
            JOptionPane.showMessageDialog(this,
                "Template not found: " + selectedName,
                "Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        showTemplateEditor(template);
    }
    
    /**
     * Show template editor dialog.
     */
    private void showTemplateEditor(PromptTemplate template) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), 
            "Edit Template: " + template.getName(), true);
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(10, 10));
        
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        JLabel titleLabel = new JLabel("Edit Template: " + template.getName());
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        headerPanel.add(titleLabel, BorderLayout.WEST);
        
        JLabel infoLabel = new JLabel(template.isBuiltIn() ? "(Built-in - will create copy)" : "(Custom)");
        infoLabel.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        headerPanel.add(infoLabel, BorderLayout.EAST);
        
        // Editor panel
        JPanel editorPanel = new JPanel(new BorderLayout(5, 5));
        editorPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // System prompt
        JLabel systemLabel = new JLabel("System Prompt:");
        systemLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        JTextArea systemPromptArea = new JTextArea(template.getSystemPrompt());
        systemPromptArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        JScrollPane systemScroll = new JScrollPane(systemPromptArea);
        systemScroll.setPreferredSize(new Dimension(750, 100));
        
        // User prompt
        JLabel userLabel = new JLabel("User Prompt:");
        userLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        JTextArea userPromptArea = new JTextArea(template.getUserPrompt());
        userPromptArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        userPromptArea.setLineWrap(true);
        userPromptArea.setWrapStyleWord(true);
        JScrollPane userScroll = new JScrollPane(userPromptArea);
        userScroll.setPreferredSize(new Dimension(750, 350));
        
        // Info panel
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(BorderFactory.createTitledBorder("Available Variables"));
        
        JTextArea variablesArea = new JTextArea();
        variablesArea.setEditable(false);
        variablesArea.setFont(new Font("Consolas", Font.PLAIN, 10));
        variablesArea.setText(
            "{{URL}} - Request URL\n" +
            "{{METHOD}} - HTTP method\n" +
            "{{STATUS}} - Status code\n" +
            "{{CONTENT_TYPE}} - Content type\n" +
            "{{SIZE}} - Response size\n" +
            "{{CONTENT}} - Response body\n" +
            "{{RESPONSE_BODY}} - Response body"
        );
        infoPanel.add(new JScrollPane(variablesArea));
        
        // Layout
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.add(systemLabel);
        mainPanel.add(systemScroll);
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(userLabel);
        mainPanel.add(userScroll);
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mainPanel, infoPanel);
        splitPane.setDividerLocation(600);
        splitPane.setResizeWeight(0.8);
        
        editorPanel.add(splitPane, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        JButton resetButton = new JButton("Reset to Default");
        resetButton.addActionListener(e -> {
            systemPromptArea.setText(template.getSystemPrompt());
            userPromptArea.setText(template.getUserPrompt());
        });
        
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            try {
                String newSystemPrompt = systemPromptArea.getText();
                String newUserPrompt = userPromptArea.getText();
                
                PromptTemplateManager templateManager = PromptTemplateManager.getInstance();
                
                // If built-in, create a copy
                if (template.isBuiltIn()) {
                    PromptTemplate newTemplate = new PromptTemplate(
                        template.getName() + " (Custom)",
                        template.getCategory(),
                        "User",
                        template.getDescription(),
                        newSystemPrompt,
                        newUserPrompt
                    );
                    newTemplate.setTags(template.getTags());
                    templateManager.saveTemplate(newTemplate);
                    
                    JOptionPane.showMessageDialog(dialog,
                        "Created custom copy: " + newTemplate.getName(),
                        "Success",
                        JOptionPane.INFORMATION_MESSAGE);
                } else {
                    // Update existing custom template
                    PromptTemplate updated = new PromptTemplate(
                        template.getName(),
                        template.getCategory(),
                        template.getAuthor(),
                        template.getDescription(),
                        newSystemPrompt,
                        newUserPrompt
                    );
                    updated.setTags(template.getTags());
                    templateManager.saveTemplate(updated);
                    
                    JOptionPane.showMessageDialog(dialog,
                        "Template saved successfully!",
                        "Success",
                        JOptionPane.INFORMATION_MESSAGE);
                }
                
                // Reload templates
                loadTemplates();
                dialog.dispose();
                
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog,
                    "Error saving template: " + ex.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(resetButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        
        dialog.add(headerPanel, BorderLayout.NORTH);
        dialog.add(editorPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setVisible(true);
    }
    
    private void addFinding(TrafficAIAnalyzer.TrafficFinding finding) {
        // Check if similar finding already exists (for grouping)
        boolean merged = false;
        for (TrafficAIAnalyzer.TrafficFinding existing : findings) {
            if (existing.isSimilarTo(finding)) {
                existing.mergeWith(finding);
                merged = true;
                break;
            }
        }
        
        if (!merged) {
            findings.add(finding);
        }
        
        updateFindingsTable();
        updateStats();
        
        // Show notification badge on AI Findings tab
        int findingsTabIndex = 1; // AI Findings is second tab
        String tabTitle = "AI Findings (" + findings.size() + ")";
        tabbedPane.setTitleAt(findingsTabIndex, tabTitle);
    }
    
    private void updateFindingsTable() {
        findingsTableModel.setRowCount(0);
        
        for (TrafficAIAnalyzer.TrafficFinding finding : findings) {
            // Show count if finding appears multiple times
            String findingDesc = finding.getDescription();
            if (finding.getCount() > 1) {
                findingDesc = "[" + finding.getCount() + "x] " + findingDesc;
            }
            
            // Show first URL, but indicate if there are more
            String urlDisplay = finding.getUrl();
            if (finding.getUrls().size() > 1) {
                urlDisplay = finding.getUrls().get(0) + " (+" + (finding.getUrls().size() - 1) + " more)";
            }
            
            Object[] row = {
                finding.getFormattedTime(),
                finding.getSeverity(),
                finding.getType(),
                findingDesc,
                urlDisplay
            };
            findingsTableModel.addRow(row);
        }
    }
    
    private void displayFindingDetails() {
        int selectedRow = findingsTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= findings.size()) {
            return;
        }
        
        TrafficAIAnalyzer.TrafficFinding finding = findings.get(selectedRow);
        
        StringBuilder details = new StringBuilder();
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append("FINDING DETAILS\n");
        details.append("═══════════════════════════════════════════════════════════\n\n");
        details.append("Time: ").append(finding.getFormattedTime()).append("\n");
        details.append("Severity: ").append(finding.getSeverity()).append("\n");
        details.append("Type: ").append(finding.getType()).append("\n");
        
        // Show count if grouped
        if (finding.getCount() > 1) {
            details.append("Occurrences: ").append(finding.getCount()).append("\n");
        }
        
        // Show all URLs where this finding appears
        details.append("\nAffected URLs:\n");
        for (String url : finding.getUrls()) {
            details.append("  • ").append(url).append("\n");
        }
        
        details.append("\nDescription:\n");
        details.append(finding.getDescription()).append("\n\n");
        details.append("Evidence:\n");
        details.append(finding.getEvidence()).append("\n");
        
        findingDetailsArea.setText(details.toString());
        findingDetailsArea.setCaretPosition(0);
    }
    
    private void displayTrafficDetails() {
        int selectedRow = trafficTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        String selectedUrl = (String) trafficTableModel.getValueAt(selectedRow, 3);
        
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
        // Assign permanent request number to this transaction
        requestCounter++;
        transactionToRequestNumber.put(transaction, requestCounter);
        
        // Trigger AI analysis if enabled
        if (aiEnabledCheckbox.isSelected()) {
            aiAnalyzer.analyzeTransaction(transaction);
        }
        
        SwingUtilities.invokeLater(() -> {
            updateTrafficTable();
            updateStats();
        });
    }
    
    @Override
    public void onBufferCleared() {
        SwingUtilities.invokeLater(() -> {
            updateTrafficTable();
            updateStats();
        });
    }
    
    private void updateTrafficTable() {
        // Save selection
        int selectedRow = trafficTable.getSelectedRow();
        String selectedUrl = null;
        if (selectedRow >= 0 && selectedRow < trafficTableModel.getRowCount()) {
            selectedUrl = (String) trafficTableModel.getValueAt(selectedRow, 3);
        }
        
        // Clear table
        trafficTableModel.setRowCount(0);
        
        // Get all transactions
        List<HttpTransaction> transactions = bufferManager.getAllTransactions();
        
        // Apply filters
        String urlFilter = urlFilterField.getText().toLowerCase();
        String methodFilter = (String) methodFilterCombo.getSelectedItem();
        boolean scopeEnabled = scopeEnabledCheckbox.isSelected();
        
        // Collect filtered transactions with their permanent request numbers
        List<TransactionWithNumber> filteredTransactions = new ArrayList<>();
        for (HttpTransaction tx : transactions) {
            // Apply scope filter
            if (scopeEnabled && !scopeManager.isInScope(tx.getUrl())) {
                continue;
            }
            
            // Apply method filter
            if (!"All".equals(methodFilter) && !tx.getMethod().equalsIgnoreCase(methodFilter)) {
                continue;
            }
            
            // Apply URL filter
            if (!urlFilter.isEmpty() && !tx.getUrl().toLowerCase().contains(urlFilter)) {
                continue;
            }
            
            // Get permanent request number
            Integer reqNum = transactionToRequestNumber.get(tx);
            if (reqNum != null) {
                filteredTransactions.add(new TransactionWithNumber(tx, reqNum));
            }
        }
        
        // Sort by request number (ascending or descending based on reverseOrder)
        filteredTransactions.sort((a, b) -> {
            if (reverseOrder) {
                return Integer.compare(b.requestNumber, a.requestNumber); // Descending
            } else {
                return Integer.compare(a.requestNumber, b.requestNumber); // Ascending
            }
        });
        
        int rowToSelect = -1;
        
        // Add to table with permanent request numbers
        for (TransactionWithNumber txWithNum : filteredTransactions) {
            HttpTransaction tx = txWithNum.transaction;
            int reqNum = txWithNum.requestNumber;
            
            Object[] row = {
                reqNum, // Permanent request number
                extractHost(tx.getUrl()),
                tx.getMethod(),
                tx.getUrl(),
                tx.getUrl().contains("?") ? "✓" : "",
                tx.getStatusCode(),
                formatSize(tx.getResponseSize()),
                extractMimeType(tx.getContentType()),
                tx.getFormattedTimestamp()
            };
            trafficTableModel.addRow(row);
            
            // Check if this is the previously selected row
            if (selectedUrl != null && tx.getUrl().equals(selectedUrl)) {
                rowToSelect = trafficTableModel.getRowCount() - 1;
            }
        }
        
        // Restore selection
        if (rowToSelect >= 0) {
            trafficTable.setRowSelectionInterval(rowToSelect, rowToSelect);
        }
    }
    
    // Helper class to pair transaction with its permanent request number
    private static class TransactionWithNumber {
        final HttpTransaction transaction;
        final int requestNumber;
        
        TransactionWithNumber(HttpTransaction transaction, int requestNumber) {
            this.transaction = transaction;
            this.requestNumber = requestNumber;
        }
    }
    
    private void updateStats() {
        int total = bufferManager.getAllTransactions().size();
        int displayed = trafficTableModel.getRowCount();
        int scopeCount = scopeManager.size();
        
        String status = monitorService.isRunning() ? "Monitoring" : "Stopped";
        statsLabel.setText(String.format("%s | Total: %d | Displayed: %d | Scope Domains: %d", 
            status, total, displayed, scopeCount));
        
        // Update AI stats
        String aiStatus = aiAnalyzer.isEnabled() ? "Enabled" : "Disabled";
        aiStatsLabel.setText(String.format("AI: %s | %s", aiStatus, aiAnalyzer.getStatistics()));
    }
    
    private void showScopeManager() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Scope Manager", true);
        dialog.setSize(600, 400);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(10, 10));
        
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        JLabel titleLabel = new JLabel("Manage In-Scope Domains");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        headerPanel.add(titleLabel, BorderLayout.WEST);
        
        // Scope list
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (String pattern : scopeManager.getScopes()) {
            listModel.addElement(pattern);
        }
        JList<String> scopeList = new JList<>(listModel);
        scopeList.setFont(new Font("Consolas", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(scopeList);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        // Controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        JTextField domainField = new JTextField(20);
        domainField.setToolTipText("Enter domain (e.g., example.com)");
        
        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
            String domain = domainField.getText().trim();
            if (!domain.isEmpty()) {
                scopeManager.addScope(domain);
                listModel.addElement(domain);
                domainField.setText("");
                updateStats();
                callbacks.printOutput("[Traffic Monitor] Added to scope: " + domain);
            }
        });
        
        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> {
            String selected = scopeList.getSelectedValue();
            if (selected != null) {
                scopeManager.removeScope(selected);
                listModel.removeElement(selected);
                updateStats();
                callbacks.printOutput("[Traffic Monitor] Removed from scope: " + selected);
            }
        });
        
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        
        controlPanel.add(new JLabel("Domain:"));
        controlPanel.add(domainField);
        controlPanel.add(addButton);
        controlPanel.add(removeButton);
        controlPanel.add(closeButton);
        
        dialog.add(headerPanel, BorderLayout.NORTH);
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(controlPanel, BorderLayout.SOUTH);
        
        dialog.setVisible(true);
    }
    
    private void addSelectedToScope() {
        int selectedRow = trafficTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        String url = (String) trafficTableModel.getValueAt(selectedRow, 3);
        String host = extractHost(url);
        
        scopeManager.addScope(host);
        callbacks.printOutput("[Traffic Monitor] Added to scope: " + host);
        updateStats();
        
        JOptionPane.showMessageDialog(this, 
            "Added to scope: " + host + "\n\nEnable 'Scope Filter' to see only in-scope traffic.",
            "Added to Scope",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void removeSelectedFromScope() {
        int selectedRow = trafficTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        String url = (String) trafficTableModel.getValueAt(selectedRow, 3);
        String host = extractHost(url);
        
        scopeManager.removeScope(host);
        callbacks.printOutput("[Traffic Monitor] Removed from scope: " + host);
        updateStats();
        applyFilters();
    }
    
    private void sendToRepeater() {
        int selectedRow = trafficTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        String selectedUrl = (String) trafficTableModel.getValueAt(selectedRow, 3);
        
        List<HttpTransaction> transactions = bufferManager.getAllTransactions();
        for (HttpTransaction tx : transactions) {
            if (tx.getUrl().equals(selectedUrl)) {
                try {
                    callbacks.sendToRepeater(
                        extractHost(tx.getUrl()),
                        extractPort(tx.getUrl()),
                        tx.getUrl().startsWith("https"),
                        tx.getRequest(),
                        null
                    );
                    callbacks.printOutput("[Traffic Monitor] Sent to Repeater: " + tx.getUrl());
                } catch (Exception e) {
                    callbacks.printError("[Traffic Monitor] Error sending to Repeater: " + e.getMessage());
                }
                break;
            }
        }
    }
    
    // Helper methods
    
    private String extractHost(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            return u.getHost();
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    private int extractPort(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            int port = u.getPort();
            return port == -1 ? (url.startsWith("https") ? 443 : 80) : port;
        } catch (Exception e) {
            return 80;
        }
    }
    
    private String extractMimeType(String contentType) {
        if (contentType == null) {
            return "";
        }
        int semicolon = contentType.indexOf(';');
        if (semicolon > 0) {
            return contentType.substring(0, semicolon).trim();
        }
        return contentType;
    }
    
    private String formatSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        }
    }
}
