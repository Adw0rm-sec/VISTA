package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.vista.security.core.*;
import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.vista.security.ui.VistaTheme.*;

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
    private IntelligentTrafficAnalyzer analyzer; // NOT final - can be updated when AI config changes
    private final ScopeManager scopeManager; // NEW: Scope management
    
    // Preserved custom template (survives analyzer recreation on AI config change)
    private String savedCustomTemplate = null;
    
    // UI Components - Findings View (now using hierarchical tree)
    // Old table components removed - using TrafficFindingsTreePanel and FindingDetailsPanel
    private JLabel statsLabel;
    private FindingDetailsPanel findingDetailsPanel; // Reference for clearing on scope change
    
    // UI Components - Traffic View
    private JTable trafficTable;
    private DefaultTableModel trafficTableModel;
    
    // UI Components - Controls
    private JTextField urlFilterField;
    private JCheckBox scopeEnabledCheckbox; // Enable scope filtering
    private JButton startStopButton;
    private JButton clearButton;
    private JButton exportButton;
    private JButton manageScopeButton; // Manage scope button
    private JTabbedPane contentTabbedPane; // Inner tabbed pane for Traffic/Findings
    
    // Data
    private final List<TrafficFinding> allFindings;
    // Fast duplicate detection set: type+url keys for O(1) lookup instead of O(n) list scan
    private final java.util.Set<String> findingKeys = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final Timer updateTimer;
    private Timer warningTimer; // Store reference for cleanup
    private int requestCounter = 0; // NEW: Request numbering
    private boolean firstStart = true; // Track first monitoring start
    private com.vista.security.service.AIService cachedAIService; // Cache AI service to avoid recreating
    private int lastFindingsCount = 0; // Track findings count to avoid unnecessary tree updates
    
    // Sort order toggle: true = descending (newest first), false = ascending (original)
    private boolean sortDescending = false;
    
    // Row highlighting: maps request # → highlight color
    private final Map<Integer, Color> highlightedRows = new HashMap<>();
    
    public TrafficMonitorPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.allFindings = new ArrayList<>();
        
        // Print version information
        callbacks.printOutput("═══════════════════════════════════════");
        callbacks.printOutput("VISTA Traffic Monitor v2.10.10-FINAL");
        callbacks.printOutput("Content-Type Detection: ENABLED");
        callbacks.printOutput("URL Extension Fallback: ENABLED");
        callbacks.printOutput("═══════════════════════════════════════");
        
        // Initialize core components
        this.bufferManager = new TrafficBufferManager(10000); // Increased from 1000 to 10000
        this.bufferManager.registerAsGlobal(); // Register for persistence access
        this.filterEngine = new TrafficFilterEngine();
        this.scopeManager = new ScopeManager();
        
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
        
        // Listen for AI configuration changes and update analyzer
        AIConfigManager.getInstance().addListener(config -> {
            callbacks.printOutput("[Traffic Monitor] AI configuration changed, updating analyzer...");
            // Preserve custom template before recreating analyzer
            savedCustomTemplate = this.analyzer.getCustomTemplate();
            
            this.cachedAIService = createAIService();
            this.analyzer = new IntelligentTrafficAnalyzer(cachedAIService, findingsManager);
            this.analyzer.setScopeManager(this.scopeManager);
            
            // Restore custom template on the new analyzer
            if (savedCustomTemplate != null) {
                this.analyzer.setCustomTemplate(savedCustomTemplate);
            }
            callbacks.printOutput("[Traffic Monitor] Analyzer updated with new AI configuration (custom template preserved)");
        });
        
        // Initialize UI
        setLayout(new BorderLayout());
        initializeUI();
        
        // Start update timer for batch UI updates (2s interval balances responsiveness vs EDT load)
        this.updateTimer = new Timer(2000, e -> refreshUI());
        updateTimer.setCoalesce(true); // Coalesce multiple pending events into one
        updateTimer.start();
        
        callbacks.printOutput("[Traffic Monitor] Panel initialized with AI integration and scope management");
    }
    
    /**
     * Restores persisted data (traffic transactions and findings) into the panel.
     * Called by VistaPersistenceManager after data is loaded from disk.
     */
    public void restorePersistedData() {
        // Restore traffic findings from persistence holder
        List<TrafficFinding> persistedFindings = com.vista.security.core.TrafficFindingsHolder.getInstance().getFindings();
        if (persistedFindings != null && !persistedFindings.isEmpty()) {
            synchronized (allFindings) {
                for (TrafficFinding finding : persistedFindings) {
                    allFindings.add(finding);
                    // Also register in duplicate detection set
                    String url = finding.getSourceTransaction() != null ? finding.getSourceTransaction().getUrl() : "";
                    findingKeys.add(finding.getType() + "|" + url);
                }
            }
            callbacks.printOutput("[Traffic Monitor] ✓ Restored " + persistedFindings.size() + " persisted findings");
        }
        
        // Refresh UI to show restored data
        SwingUtilities.invokeLater(() -> {
            updateTrafficTable();
            updateStats();
            updateFindingsTree();
        });
    }
    
    private void initializeUI() {
        // Create tabbed pane for Traffic and Findings views
        contentTabbedPane = new JTabbedPane();
        contentTabbedPane.setFont(VistaTheme.FONT_TAB);
        contentTabbedPane.setBackground(VistaTheme.BG_PANEL);
        
        // Traffic tab (primary view - selected by default)
        JPanel trafficPanel = createTrafficPanel();
        contentTabbedPane.addTab("  Traffic  ", trafficPanel);
        
        // Findings tab (shows count when findings exist)
        JPanel findingsPanel = createFindingsPanel();
        contentTabbedPane.addTab("  Findings  ", findingsPanel);
        
        // Add to main panel
        add(contentTabbedPane, BorderLayout.CENTER);
        
        // Add controls at top
        add(createControlsPanel(), BorderLayout.NORTH);
        
        // Add statistics at bottom
        add(createStatsPanel(), BorderLayout.SOUTH);
    }
    
    private JPanel createControlsPanel() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());
        mainPanel.setBackground(VistaTheme.BG_CARD);
        mainPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, VistaTheme.BORDER),
            BorderFactory.createEmptyBorder(8, 12, 8, 12)
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        
        // Start/Stop button
        gbc.gridx = 0;
        gbc.gridy = 0;
        startStopButton = VistaTheme.primaryButton("▶ Start Monitoring");
        startStopButton.addActionListener(e -> toggleMonitoring());
        mainPanel.add(startStopButton, gbc);
        
        // Separator
        gbc.gridx = 1;
        JSeparator sep1 = new JSeparator(SwingConstants.VERTICAL);
        sep1.setPreferredSize(new Dimension(2, 25));
        mainPanel.add(sep1, gbc);
        
        // Enable Scope checkbox
        gbc.gridx = 2;
        scopeEnabledCheckbox = new JCheckBox("Enable Scope", false);
        scopeEnabledCheckbox.setFont(VistaTheme.FONT_BODY);
        scopeEnabledCheckbox.setForeground(VistaTheme.TEXT_PRIMARY);
        scopeEnabledCheckbox.setOpaque(false);
        scopeEnabledCheckbox.setToolTipText("Enable to analyze ONLY in-scope domains");
        scopeEnabledCheckbox.addActionListener(e -> {
            boolean enabled = scopeEnabledCheckbox.isSelected();
            scopeManager.setScopeEnabled(enabled);
            
            // Clear cache when scope is enabled to allow re-analysis with scope
            if (enabled && scopeManager.size() > 0) {
                clearAnalyzedUrlsCache();
            }
            
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
        mainPanel.add(scopeEnabledCheckbox, gbc);
        
        // Manage Scope button
        gbc.gridx = 3;
        manageScopeButton = VistaTheme.compactButton("Manage Scope");
        manageScopeButton.setToolTipText("Add/remove in-scope domains");
        manageScopeButton.addActionListener(e -> showScopeManager());
        mainPanel.add(manageScopeButton, gbc);
        
        // Separator
        gbc.gridx = 4;
        JSeparator sep2 = new JSeparator(SwingConstants.VERTICAL);
        sep2.setPreferredSize(new Dimension(2, 25));
        mainPanel.add(sep2, gbc);
        
        // Clear button
        gbc.gridx = 5;
        clearButton = VistaTheme.compactButton("Clear");
        clearButton.addActionListener(e -> clearAll());
        mainPanel.add(clearButton, gbc);
        
        // Export button
        gbc.gridx = 6;
        exportButton = VistaTheme.compactButton("Export");
        exportButton.addActionListener(e -> exportFindings());
        mainPanel.add(exportButton, gbc);
        
        // Separator
        gbc.gridx = 7;
        JSeparator sep3 = new JSeparator(SwingConstants.VERTICAL);
        sep3.setPreferredSize(new Dimension(2, 25));
        mainPanel.add(sep3, gbc);
        
        // Customize Template button
        gbc.gridx = 8;
        JButton customizePromptsButton = VistaTheme.compactButton("Edit Template");
        customizePromptsButton.setToolTipText("Customize the AI analysis template for HTTP traffic monitoring");
        customizePromptsButton.addActionListener(e -> showPromptCustomizationDialog());
        mainPanel.add(customizePromptsButton, gbc);
        
        return mainPanel;
    }
    
    private JPanel createFindingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create hierarchical tree panel (left side)
        TrafficFindingsTreePanel treePanel = new TrafficFindingsTreePanel();
        
        // Create details panel (right side)
        FindingDetailsPanel detailsPanel = new FindingDetailsPanel();
        this.findingDetailsPanel = detailsPanel; // Store reference for clearing on scope change
        
        // Connect tree selection to details panel
        treePanel.setSelectionListener(detailsPanel::showFinding);
        
        // Split pane: tree on left, details on right
        JSplitPane splitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, 
            treePanel, 
            detailsPanel
        );
        splitPane.setDividerLocation(400);
        splitPane.setResizeWeight(0.4);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        // Store references for updating
        panel.putClientProperty("treePanel", treePanel);
        panel.putClientProperty("detailsPanel", detailsPanel);
        
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
        VistaTheme.styleTable(trafficTable);
        trafficTable.setFont(VistaTheme.FONT_MONO_SMALL);
        trafficTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
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
        
        // ── Custom cell renderer for row highlighting ──
        DefaultTableCellRenderer highlightRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (!isSelected) {
                    // Get the request # from column 0 to check highlight map
                    try {
                        int modelRow = table.convertRowIndexToModel(row);
                        Object reqNum = table.getModel().getValueAt(modelRow, 0);
                        if (reqNum instanceof Integer) {
                            Color hlColor = highlightedRows.get((Integer) reqNum);
                            if (hlColor != null) {
                                c.setBackground(hlColor);
                                // Use dark text for light backgrounds, white for dark
                                int brightness = (hlColor.getRed() * 299 + hlColor.getGreen() * 587 + hlColor.getBlue() * 114) / 1000;
                                c.setForeground(brightness > 140 ? Color.BLACK : Color.WHITE);
                            } else {
                                c.setBackground(table.getBackground());
                                c.setForeground(table.getForeground());
                            }
                        }
                    } catch (Exception ignored) {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    }
                }
                return c;
            }
        };
        // Apply the renderer to all columns
        for (int i = 0; i < trafficTable.getColumnCount(); i++) {
            trafficTable.getColumnModel().getColumn(i).setCellRenderer(highlightRenderer);
        }
        
        // ── Header double-click listener: toggle sort on "#" column ──
        trafficTable.getTableHeader().addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int col = trafficTable.columnAtPoint(e.getPoint());
                    if (col == 0) { // "#" column
                        sortDescending = !sortDescending;
                        updateTrafficTable();
                        callbacks.printOutput("[Traffic Monitor] Sort order: " + 
                            (sortDescending ? "Newest first (descending)" : "Oldest first (ascending)"));
                    }
                }
            }
        });
        
        // Add right-click context menu for scope management
        JPopupMenu contextMenu = createTrafficContextMenu();
        trafficTable.setComponentPopupMenu(contextMenu);
        
        // Mouse listener for: right-click popup + double-click on # cell for color highlight
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
            
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = trafficTable.rowAtPoint(e.getPoint());
                    int col = trafficTable.columnAtPoint(e.getPoint());
                    if (col == 0 && row >= 0) { // Double-click on "#" column cell
                        showColorPickerForRow(row);
                    }
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
        
        // HTTP message viewer (side-by-side Request/Response)
        HttpMessageViewer httpViewer = new HttpMessageViewer();
        
        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, httpViewer);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.6);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        // Store reference to httpViewer for updates
        panel.putClientProperty("httpViewer", httpViewer);
        
        return panel;
    }
    
    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(VistaTheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, VistaTheme.BORDER),
            BorderFactory.createEmptyBorder(6, 14, 6, 14)
        ));
        
        // Stats label on the left
        statsLabel = new JLabel("Ready");
        statsLabel.setFont(VistaTheme.FONT_SMALL);
        statsLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        panel.add(statsLabel, BorderLayout.WEST);
        
        // Warning panel on the right (initially hidden)
        JPanel warningPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        
        // Clickable warning label
        JLabel warningLabel = new JLabel();
        warningLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        warningLabel.setForeground(VistaTheme.STATUS_WARNING);
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
        
        // Update warning based on scope and AI status (3s is sufficient for status checks)
        warningTimer = new Timer(3000, e -> {
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
            // REMOVED: Popup dialog on first start (user requested removal)
            // User can learn about Traffic Monitor from documentation
            
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
        // Apply filters to findings tree
        updateFindingsTree();
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
            findingKeys.clear(); // Clear duplicate detection cache
            bufferManager.clear();
            if (analyzer != null) {
                analyzer.clearAnalyzedUrls(); // Clear URL deduplication cache
            }
            updateFindingsTree();
            updateTrafficTable();
            callbacks.printOutput("[Traffic Monitor] All data cleared (including analyzed URLs cache)");
        }
    }
    
    private void exportFindings() {
        // TODO: Implement export functionality
        JOptionPane.showMessageDialog(this, "Export functionality coming soon!");
    }
    
    // displayFindingDetails method removed - now handled by FindingDetailsPanel
    
    private void displayTrafficDetails() {
        int selectedRow = trafficTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        // Convert view row to model row (handles sorting)
        int modelRow = selectedRow;
        try {
            modelRow = trafficTable.convertRowIndexToModel(selectedRow);
        } catch (Exception ignored) {}
        
        // Get the URL from the DISPLAYED table, not from transactions directly
        // because the table may be filtered
        if (modelRow >= trafficTableModel.getRowCount()) {
            return;
        }
        
        String selectedUrl = (String) trafficTableModel.getValueAt(modelRow, 3); // URL column
        if (selectedUrl == null) return;
        
        // Find the transaction with this URL
        List<HttpTransaction> transactions = bufferManager.getAllTransactions();
        HttpTransaction transaction = null;
        for (HttpTransaction tx : transactions) {
            if (selectedUrl.equals(tx.getUrl())) {
                transaction = tx;
                break;
            }
        }
        
        if (transaction == null) {
            return;
        }
        
        // Get the HttpMessageViewer from the Traffic panel (index 0)
        if (contentTabbedPane != null) {
            Component trafficTab = contentTabbedPane.getComponentAt(0); // First tab is Traffic
            
            if (trafficTab instanceof JPanel) {
                JPanel trafficPanel = (JPanel) trafficTab;
                HttpMessageViewer httpViewer = 
                    (HttpMessageViewer) trafficPanel.getClientProperty("httpViewer");
                
                if (httpViewer != null) {
                    httpViewer.setHttpMessage(transaction.getRequest(), transaction.getResponse());
                }
            }
        }
    }
    
    @Override
    public void onTransactionAdded(HttpTransaction transaction) {
        // CRITICAL: Check scope FIRST - don't analyze out-of-scope traffic at all
        boolean scopeEnabled = scopeManager.isScopeEnabled();
        boolean hasScopeDomains = scopeManager.size() > 0;
        boolean inScope = scopeManager.isInScope(transaction.getUrl());
        
        // SKIP ANALYSIS ENTIRELY if scope is enabled and URL is out of scope
        if (scopeEnabled && hasScopeDomains && !inScope) {
            return; // EARLY RETURN - no analysis at all
        }
        
        // Check if AI is configured
        boolean aiConfigured = isAIConfigured();
        if (!aiConfigured) {
            return;
        }
        
        // Get the queue manager and submit for async analysis
        AnalysisQueueManager queueManager = AnalysisQueueManager.getInstance();
        
        // Configure queue manager if not already done
        if (queueManager.getAnalyzedCount() == 0 || analyzer != null) {
            queueManager.setAnalyzer(analyzer);
            queueManager.setLogCallback(msg -> callbacks.printOutput(msg));
            queueManager.setResultCallback(result -> handleAnalysisResult(result));
        }
        
        // Submit to queue (non-blocking, handles deduplication)
        boolean queued = queueManager.submitForAnalysis(transaction);
        
        // Update status
        if (queued) {
            SwingUtilities.invokeLater(() -> {
                statsLabel.setText("📥 Queued for analysis [" + queueManager.getStatus() + "] " + 
                    truncateUrl(transaction.getUrl(), 60));
            });
        }
    }
    
    /**
     * Handle analysis result from the queue manager
     */
    private void handleAnalysisResult(AnalysisQueueManager.AnalysisResult result) {
        if (!result.success) {
            callbacks.printError("[Traffic Monitor] Analysis error: " + result.error);
            SwingUtilities.invokeLater(this::updateStats);
            return;
        }
        
        List<TrafficFinding> findings = result.findings;
        HttpTransaction transaction = result.transaction;
        
        if (findings != null && !findings.isEmpty()) {
            int addedCount = 0;
            synchronized (allFindings) {
                for (TrafficFinding finding : findings) {
                    // Check for duplicates before adding
                    if (!isDuplicateFinding(finding)) {
                        allFindings.add(finding);
                        // Also register with persistence holder
                        com.vista.security.core.TrafficFindingsHolder.getInstance().addFinding(finding);
                        addedCount++;
                        callbacks.printOutput("[Traffic Monitor] ➕ ADDED: " + finding.getType() + 
                            " (" + finding.getSeverity() + ") - " + truncateUrl(finding.getSourceTransaction().getUrl(), 50));
                    } else {
                        callbacks.printOutput("[Traffic Monitor] ⏭️ SKIPPED DUPLICATE: " + finding.getType() + 
                            " - " + truncateUrl(finding.getSourceTransaction().getUrl(), 50));
                    }
                }
                
                if (addedCount > 0) {
                    callbacks.printOutput("[Traffic Monitor] 📊 Added " + addedCount + " new findings (Total: " + allFindings.size() + ")");
                }
            }
            
            if (addedCount > 0) {
                callbacks.printOutput("[Traffic Monitor] ✅ Found " + addedCount + " new issues in " + truncateUrl(transaction.getUrl(), 60));
                
                // Update findings tree UI only if new findings were added
                updateFindingsTree();
                
                // Log critical/high findings to console
                for (TrafficFinding finding : findings) {
                    if ("CRITICAL".equals(finding.getSeverity()) || "HIGH".equals(finding.getSeverity())) {
                        callbacks.printOutput("[Traffic Monitor] ⚠️ " + finding.getSeverity() + ": " + 
                            finding.getTitle() + " - " + truncateUrl(transaction.getUrl(), 60));
                    }
                }
            }
        } else {
            // Only log "no issues" for non-trivial URLs (avoid spam)
            String url = transaction.getUrl();
            if (!url.contains(".css") && !url.contains(".png") && !url.contains(".svg") && !url.contains(".woff")) {
                callbacks.printOutput("[Traffic Monitor] ℹ️ No issues found in " + truncateUrl(url, 60));
            }
        }
        
        // Update stats
        SwingUtilities.invokeLater(this::updateStats);
    }
    
    /**
     * Check if a finding is a duplicate of an existing one.
     * Uses O(1) hash set lookup instead of O(n) list scan for performance.
     * Duplicate = same type + same URL
     */
    private boolean isDuplicateFinding(TrafficFinding newFinding) {
        String newType = newFinding.getType();
        String newUrl = newFinding.getSourceTransaction() != null ? newFinding.getSourceTransaction().getUrl() : "";
        String key = newType + "|" + newUrl;
        return !findingKeys.add(key); // returns false if already present = duplicate
    }
    
    /**
     * Truncate URL for display
     */
    private String truncateUrl(String url, int maxLen) {
        if (url == null) return "";
        return url.length() > maxLen ? url.substring(0, maxLen) + "..." : url;
    }
    
    @Override
    public void onBufferCleared() {
        SwingUtilities.invokeLater(() -> {
            updateTrafficTable();
        });
    }
    
    private void refreshUI() {
        updateFindingsTree();
        updateTrafficTable();
        updateStats();
    }
    
    private void updateFindingsTree() {
        SwingUtilities.invokeLater(() -> {
            // Get the findings panel from contentTabbedPane directly
            if (contentTabbedPane != null && contentTabbedPane.getTabCount() > 1) {
                    Component findingsTab = contentTabbedPane.getComponentAt(1); // Second tab is Findings
                    
                    if (findingsTab instanceof JPanel) {
                        JPanel findingsPanel = (JPanel) findingsTab;
                        TrafficFindingsTreePanel treePanel = 
                            (TrafficFindingsTreePanel) findingsPanel.getClientProperty("treePanel");
                        
                        if (treePanel != null) {
                            // Filter findings based on scope and other filters
                            List<TrafficFinding> filteredFindings = new ArrayList<>();
                            
                            synchronized (allFindings) {
                                for (TrafficFinding finding : allFindings) {
                                    // Apply scope filter
                                    if (scopeManager.isScopeEnabled() && 
                                        !scopeManager.isInScope(finding.getSourceTransaction().getUrl())) {
                                        continue;
                                    }
                                    
                                    // Apply other filters
                                    if (!matchesFilters(finding)) {
                                        continue;
                                    }
                                    
                                    filteredFindings.add(finding);
                                }
                            }
                            
                            // Update Findings tab title with count
                            int count = filteredFindings.size();
                            if (count > 0) {
                                contentTabbedPane.setTitleAt(1, "  🔍 Findings (" + count + ")  ");
                            } else {
                                contentTabbedPane.setTitleAt(1, "  🔍 Findings  ");
                            }
                            
                            // Only update tree if findings count changed (avoid unnecessary rebuilds)
                            if (filteredFindings.size() != lastFindingsCount) {
                                lastFindingsCount = filteredFindings.size();
                                treePanel.updateFindings(filteredFindings);
                            }
                        }
                    }
            }
        });
    }
    
    private void updateTrafficTable() {
        SwingUtilities.invokeLater(() -> {
            // Save current selection by request # (stable across sort changes)
            int selectedRow = trafficTable.getSelectedRow();
            Integer selectedReqNum = null;
            if (selectedRow >= 0 && selectedRow < trafficTableModel.getRowCount()) {
                Object val = trafficTableModel.getValueAt(selectedRow, 0); // # column
                if (val instanceof Integer) {
                    selectedReqNum = (Integer) val;
                }
            }
            
            // Clear table
            trafficTableModel.setRowCount(0);
            
            List<HttpTransaction> transactions = bufferManager.getAllTransactions();
            String urlFilter = urlFilterField != null ? urlFilterField.getText().trim() : "";
            
            // Build filtered list first
            List<HttpTransaction> filteredTransactions = new ArrayList<>();
            for (HttpTransaction tx : transactions) {
                // Apply scope filter if enabled
                if (scopeManager.isScopeEnabled() && scopeManager.size() > 0) {
                    if (!scopeManager.isInScope(tx.getUrl())) {
                        continue;
                    }
                }
                // Apply URL filter
                if (!urlFilter.isEmpty()) {
                    if (!tx.getUrl().toLowerCase().contains(urlFilter.toLowerCase())) {
                        continue;
                    }
                }
                filteredTransactions.add(tx);
            }
            
            int totalFiltered = filteredTransactions.size();
            int rowToSelect = -1;
            int currentRow = 0;
            
            for (int i = 0; i < totalFiltered; i++) {
                // When descending, iterate from the end so newest appears at top
                int idx = sortDescending ? (totalFiltered - 1 - i) : i;
                HttpTransaction tx = filteredTransactions.get(idx);
                int requestNumber = idx + 1; // Original sequential number
                
                trafficTableModel.addRow(new Object[]{
                    requestNumber,
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
                
                // Restore selection by request #
                if (selectedReqNum != null && requestNumber == selectedReqNum) {
                    rowToSelect = currentRow;
                }
                currentRow++;
            }
            
            // Restore selection if the same request # is still visible
            if (rowToSelect >= 0 && rowToSelect < trafficTableModel.getRowCount()) {
                final int finalRowToSelect = rowToSelect;
                SwingUtilities.invokeLater(() -> {
                    trafficTable.setRowSelectionInterval(finalRowToSelect, finalRowToSelect);
                });
            }
        });
    }
    
    /**
     * Clears the analyzed URLs cache in both the queue manager and analyzer.
     * Call this when scope configuration changes to allow re-analysis.
     * Also clears findings and UI panels.
     */
    private void clearAnalyzedUrlsCache() {
        // Clear queue manager cache
        AnalysisQueueManager queueManager = AnalysisQueueManager.getInstance();
        queueManager.clearAnalyzedUrls();
        
        // Clear analyzer cache
        if (analyzer != null) {
            analyzer.clearAnalyzedUrls();
        }
        
        // Clear all findings when scope changes
        synchronized (allFindings) {
            allFindings.clear();
        }
        findingKeys.clear(); // Clear duplicate detection cache
        
        // Update findings tree (will show empty)
        updateFindingsTree();
        
        // Clear the details panel (Finding Details and Request/Response)
        clearFindingDetailsPanel();
        
        callbacks.printOutput("[Traffic Monitor] 🗑️ Cleared analyzed URLs cache and findings - scope changed");
    }
    
    /**
     * Shows a color picker popup when user double-clicks on the "#" column cell.
     * Allows highlighting specific rows with chosen colors.
     */
    private void showColorPickerForRow(int viewRow) {
        try {
            int modelRow = trafficTable.convertRowIndexToModel(viewRow);
            Object reqNumObj = trafficTableModel.getValueAt(modelRow, 0);
            if (!(reqNumObj instanceof Integer)) return;
            int reqNum = (Integer) reqNumObj;
            
            // Create a popup with color swatches
            JPopupMenu colorMenu = new JPopupMenu();
            
            // Title label
            JLabel titleLabel = new JLabel("  Highlight Row #" + reqNum + "  ");
            titleLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
            titleLabel.setForeground(VistaTheme.TEXT_SECONDARY);
            titleLabel.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));
            colorMenu.add(titleLabel);
            colorMenu.addSeparator();
            
            // Color swatches panel
            JPanel swatchPanel = new JPanel(new GridLayout(2, 5, 3, 3));
            swatchPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
            swatchPanel.setOpaque(false);
            
            Color[] colors = {
                new Color(254, 226, 226),  // Red light
                new Color(255, 237, 213),  // Orange light
                new Color(254, 249, 195),  // Yellow light
                new Color(220, 252, 231),  // Green light
                new Color(219, 234, 254),  // Blue light
                new Color(239, 68, 68),    // Red
                new Color(249, 115, 22),   // Orange
                new Color(234, 179, 8),    // Yellow
                new Color(34, 197, 94),    // Green
                new Color(59, 130, 246),   // Blue
            };
            String[] colorNames = {
                "Light Red", "Light Orange", "Light Yellow", "Light Green", "Light Blue",
                "Red", "Orange", "Yellow", "Green", "Blue"
            };
            
            for (int i = 0; i < colors.length; i++) {
                final Color color = colors[i];
                JButton swatch = new JButton();
                swatch.setPreferredSize(new Dimension(26, 26));
                swatch.setBackground(color);
                swatch.setOpaque(true);
                swatch.setBorderPainted(true);
                swatch.setBorder(BorderFactory.createLineBorder(color.darker(), 1));
                swatch.setToolTipText(colorNames[i]);
                swatch.setFocusPainted(false);
                swatch.setCursor(new Cursor(Cursor.HAND_CURSOR));
                swatch.addActionListener(e -> {
                    highlightedRows.put(reqNum, color);
                    trafficTable.repaint();
                    colorMenu.setVisible(false);
                });
                swatchPanel.add(swatch);
            }
            
            colorMenu.add(swatchPanel);
            
            // "Remove Highlight" option
            if (highlightedRows.containsKey(reqNum)) {
                colorMenu.addSeparator();
                JMenuItem removeItem = new JMenuItem("Remove Highlight");
                removeItem.setFont(VistaTheme.FONT_SMALL);
                removeItem.addActionListener(e -> {
                    highlightedRows.remove(reqNum);
                    trafficTable.repaint();
                });
                colorMenu.add(removeItem);
            }
            
            // "Clear All Highlights" option
            if (!highlightedRows.isEmpty()) {
                JMenuItem clearAllItem = new JMenuItem("Clear All Highlights");
                clearAllItem.setFont(VistaTheme.FONT_SMALL);
                clearAllItem.addActionListener(e -> {
                    highlightedRows.clear();
                    trafficTable.repaint();
                });
                colorMenu.add(clearAllItem);
            }
            
            // Show popup near the cell
            Rectangle cellRect = trafficTable.getCellRect(viewRow, 0, true);
            colorMenu.show(trafficTable, cellRect.x + cellRect.width, cellRect.y);
            
        } catch (Exception ex) {
            callbacks.printError("[Traffic Monitor] Error showing color picker: " + ex.getMessage());
        }
    }
    
    /**
     * Clears the Finding Details panel including Request/Response viewers.
     */
    private void clearFindingDetailsPanel() {
        if (findingDetailsPanel != null) {
            findingDetailsPanel.clear();
        }
    }
    
    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            int trafficCount = bufferManager.size();
            long dataVolume = bufferManager.getTotalDataVolume();
            
            int findingsCount;
            int criticalCount = 0;
            int highCount = 0;
            
            synchronized (allFindings) {
                findingsCount = allFindings.size();
                for (TrafficFinding finding : allFindings) {
                    if ("CRITICAL".equals(finding.getSeverity())) {
                        criticalCount++;
                    } else if ("HIGH".equals(finding.getSeverity())) {
                        highCount++;
                    }
                }
            }
            
            // Determine detection mode - AI ONLY MODE
            boolean aiConfigured = isAIConfigured();
            String detectionMode = aiConfigured ? "🤖 AI Only" : "⚠️ AI Not Configured";
            
            // Get queue status
            AnalysisQueueManager queueManager = AnalysisQueueManager.getInstance();
            int queueSize = queueManager.getQueueSize();
            int analyzedCount = queueManager.getAnalyzedCount();
            
            String status = monitorService.isRunning() ? "🟢 Monitoring" : "🔴 Stopped";
            String queueStatus = queueSize > 0 ? " | 📥 Queue: " + queueSize : "";
            String stats = String.format(
                "%s [%s] | Findings: %d (Critical: %d, High: %d) | Traffic: %d | Analyzed: %d URLs%s",
                status, detectionMode, findingsCount, criticalCount, highCount, trafficCount, analyzedCount, queueStatus
            );
            
            statsLabel.setText(stats);
        });
    }
    
    private boolean matchesFilters(TrafficFinding finding) {
        // URL filter only (other filters were removed from UI)
        String urlFilter = urlFilterField != null ? urlFilterField.getText().trim() : "";
        if (!urlFilter.isEmpty()) {
            String url = finding.getSourceTransaction().getUrl();
            if (!url.contains(urlFilter)) {
                return false;
            }
        }
        
        return true;
    }
    
    public void cleanup() {
        if (updateTimer != null) {
            updateTimer.stop();
        }
        if (warningTimer != null) {
            warningTimer.stop();
        }
        if (monitorService != null) {
            monitorService.stop();
        }
        // Shutdown analysis queue
        try {
            AnalysisQueueManager.getInstance().shutdown();
        } catch (Exception ignored) {}
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
                
                // Log original content-type from header
                callbacks.printOutput("[Traffic Monitor] 📋 Header Content-Type: " + (contentType == null ? "null" : contentType));
                
                // If content-type is unknown, try to detect from URL extension
                if (contentType == null || contentType.equals("unknown")) {
                    String detectedType = detectContentTypeFromUrl(fullUrl);
                    if (!detectedType.equals("unknown")) {
                        callbacks.printOutput("[Traffic Monitor] 🔍 Detected from URL extension: " + detectedType);
                        contentType = detectedType;
                    }
                }
                
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
                return "unknown";
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
        return "unknown";
    }
    
    /**
     * Detects content-type from URL extension when Content-Type header is missing.
     * This is critical for analyzing JavaScript files that don't send Content-Type headers.
     */
    private String detectContentTypeFromUrl(String url) {
        if (url == null) {
            return "unknown";
        }
        
        String lowerUrl = url.toLowerCase();
        
        // Remove query parameters
        int queryIndex = lowerUrl.indexOf('?');
        if (queryIndex > 0) {
            lowerUrl = lowerUrl.substring(0, queryIndex);
        }
        
        // Check file extension
        if (lowerUrl.endsWith(".js")) {
            return "application/javascript";
        } else if (lowerUrl.endsWith(".html") || lowerUrl.endsWith(".htm")) {
            return "text/html";
        } else if (lowerUrl.endsWith(".json")) {
            return "application/json";
        } else if (lowerUrl.endsWith(".css")) {
            return "text/css";
        } else if (lowerUrl.endsWith(".xml")) {
            return "application/xml";
        }
        
        return "unknown";
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
                    // Clear analyzed URLs cache to allow re-analysis with new scope
                    clearAnalyzedUrlsCache();
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
                    // Clear analyzed URLs cache to allow re-analysis with new scope
                    clearAnalyzedUrlsCache();
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
        titleLabel.setFont(VistaTheme.FONT_HEADING);
        titleLabel.setForeground(VistaTheme.TEXT_PRIMARY);
        JLabel subtitleLabel = new JLabel("Add domains to filter traffic. Supports wildcards (*.example.com)");
        subtitleLabel.setFont(VistaTheme.FONT_SMALL);
        subtitleLabel.setForeground(VistaTheme.TEXT_MUTED);
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(subtitleLabel, BorderLayout.SOUTH);
        
        // Scope list
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (String scope : scopeManager.getScopes()) {
            listModel.addElement(scope);
        }
        JList<String> scopeList = new JList<>(listModel);
        scopeList.setFont(VistaTheme.FONT_MONO);
        JScrollPane scrollPane = new JScrollPane(scopeList);
        
        // Add/Remove panel
        JPanel controlPanel = new JPanel(new BorderLayout(5, 5));
        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        JPanel addPanel = new JPanel(new BorderLayout(5, 0));
        JTextField addField = new JTextField();
        addField.setToolTipText("Enter domain (e.g., example.com or *.example.com)");
        JButton addButton = VistaTheme.primaryButton("Add");
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
        JButton removeButton = VistaTheme.secondaryButton("Remove Selected");
        removeButton.addActionListener(e -> {
            String selected = scopeList.getSelectedValue();
            if (selected != null) {
                scopeManager.removeScope(selected);
                listModel.removeElement(selected);
                callbacks.printOutput("[Traffic Monitor] Removed from scope: " + selected);
            }
        });
        
        JButton clearButton = VistaTheme.secondaryButton("Clear All");
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
        
        JButton closeButton = VistaTheme.compactButton("Close");
        closeButton.addActionListener(e -> {
            // Clear cache to allow re-analysis with any scope changes
            if (scopeManager.size() > 0 && scopeManager.isScopeEnabled()) {
                clearAnalyzedUrlsCache();
            }
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
        infoArea.setBackground(VistaTheme.BG_PANEL);
        infoArea.setFont(VistaTheme.FONT_SMALL);
        infoArea.setForeground(VistaTheme.TEXT_SECONDARY);
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
     * Checks if AI is configured by querying AIConfigManager directly.
     * This ensures we always have the latest configuration status.
     * 
     * @return True if AI is configured, false otherwise
     */
    private boolean isAIConfigured() {
        // FIXED: Check AIConfigManager directly instead of cached service
        // This ensures we get real-time configuration status
        return AIConfigManager.getInstance().isConfigured();
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
            JLabel titleLabel = new JLabel("How Traffic Monitor Works");
            titleLabel.setFont(VistaTheme.FONT_HEADING);
            titleLabel.setForeground(VistaTheme.PRIMARY);
            
            // Message
            JTextArea messageArea = new JTextArea();
            messageArea.setEditable(false);
            messageArea.setBackground(panel.getBackground());
            messageArea.setFont(VistaTheme.FONT_BODY);
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
            JButton manageScopeBtn = VistaTheme.primaryButton("Manage Scope");
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
            JLabel titleLabel = new JLabel("Scope Configuration Required");
            titleLabel.setFont(VistaTheme.FONT_HEADING);
            titleLabel.setForeground(VistaTheme.STATUS_WARNING);
            
            // Message
            JTextArea messageArea = new JTextArea();
            messageArea.setEditable(false);
            messageArea.setBackground(panel.getBackground());
            messageArea.setFont(VistaTheme.FONT_BODY);
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
            JButton manageScopeBtn = VistaTheme.primaryButton("Manage Scope Now");
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
     * Show dialog to customize AI prompts for traffic analysis
     */
    private void showPromptCustomizationDialog() {
        // Get current template from analyzer (preserves user edits)
        String currentTemplate = analyzer.getCustomTemplate();
        
        // Create and show dialog with single unified template
        PromptCustomizationDialog dialog = new PromptCustomizationDialog(
            (Frame) SwingUtilities.getWindowAncestor(this),
            currentTemplate
        );
        dialog.setVisible(true);
        
        // If user saved, apply the template
        if (dialog.isSaved()) {
            String template = dialog.getTemplate();
            
            // Set the unified template in the analyzer (used as system prompt)
            analyzer.setCustomTemplate(template);
            
            // Also update saved copy for config change preservation
            savedCustomTemplate = template;
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
