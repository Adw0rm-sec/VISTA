package com.vista.security.ui;

import burp.*;
import com.vista.security.core.*;
import com.vista.security.model.PromptTemplate;
import com.vista.security.service.AzureAIService;
import com.vista.security.service.OpenAIService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Testing Suggestions Panel - AI provides methodology and guidance without automatic testing.
 * 
 * Features:
 * - Systematic testing methodology
 * - WAF detection and bypass suggestions
 * - PayloadsAllTheThings knowledge
 * - Step-by-step exploitation guidance
 * - Conversation-style interaction
 */
public class TestingSuggestionsPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ReflectionAnalyzer reflectionAnalyzer;
    private final DeepRequestAnalyzer deepRequestAnalyzer;
    private final ResponseAnalyzer responseAnalyzer;
    private final PromptTemplateManager templateManager;
    private final PayloadLibraryAIIntegration payloadLibraryAI;

    // Request/Response display
    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();
    
    // Multi-request support
    private final java.util.List<IHttpRequestResponse> attachedRequests = new ArrayList<>();
    private JLabel multiRequestLabel;
    private JButton manageRequestsButton;
    
    // Template selector
    private JComboBox<String> templateSelector;
    
    // Search components
    private final JTextField requestSearchField = new JTextField(15);
    private final JTextField responseSearchField = new JTextField(15);
    private final JLabel requestMatchLabel = new JLabel("");
    private final JLabel responseMatchLabel = new JLabel("");

    // Suggestions area (main output)
    private final JTextArea suggestionsArea = new JTextArea();
    private final JTextField queryField = new JTextField();

    // Status
    private final JLabel statusLabel = new JLabel("Ready");
    private final JLabel configStatusLabel = new JLabel();
    private JLabel loadingLabel; // Loading indicator

    // Interactive mode chat UI (always active now - no mode selection)
    private JPanel interactiveChatPanel;
    private JPanel chatMessagesPanel;
    private JTextField interactiveChatField;
    private JComboBox<String> repeaterRequestDropdown;

    // Current state
    private IHttpRequestResponse currentRequest;
    private final List<ConversationMessage> conversationHistory = new ArrayList<>();
    private final List<TestingStep> testingSteps = new ArrayList<>(); // Track testing history
    private String currentTestingPlan = null; // For interactive mode
    private int currentStep = 0; // Track current step in interactive mode

    public TestingSuggestionsPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.reflectionAnalyzer = new ReflectionAnalyzer(helpers);
        this.deepRequestAnalyzer = new DeepRequestAnalyzer(helpers);
        this.responseAnalyzer = new ResponseAnalyzer(helpers);
        this.templateManager = PromptTemplateManager.getInstance();
        this.payloadLibraryAI = new PayloadLibraryAIIntegration();

        setLayout(new BorderLayout(0, 0));
        buildUI();
        updateConfigStatus();
        
        AIConfigManager.getInstance().addListener(config -> 
            SwingUtilities.invokeLater(this::updateConfigStatus));
    }

    private void buildUI() {
        JPanel headerPanel = buildHeaderPanel();
        JSplitPane mainSplit = buildMainContent();
        JPanel footerPanel = buildFooterPanel();

        add(headerPanel, BorderLayout.NORTH);
        add(mainSplit, BorderLayout.CENTER);
        add(footerPanel, BorderLayout.SOUTH);
    }

    private JPanel buildHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(12, 12, 8, 12));

        JPanel titleRow = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("AI Security Advisor");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        
        JLabel subtitleLabel = new JLabel("Interactive testing guidance with WAF bypass intelligence");
        subtitleLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        subtitleLabel.setForeground(new Color(100, 100, 110));
        
        configStatusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        
        JPanel titleStack = new JPanel();
        titleStack.setLayout(new BoxLayout(titleStack, BoxLayout.Y_AXIS));
        titleStack.add(titleLabel);
        titleStack.add(Box.createVerticalStrut(2));
        titleStack.add(subtitleLabel);
        
        titleRow.add(titleStack, BorderLayout.WEST);
        titleRow.add(configStatusLabel, BorderLayout.EAST);
        
        // Template selector row
        JPanel templateRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        templateRow.add(new JLabel("📝 Template:"));
        
        templateSelector = new JComboBox<>();
        templateSelector.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        templateSelector.setPreferredSize(new Dimension(250, 25));
        templateSelector.addItem("-- Default (No Template) --");
        
        // Load active templates
        for (PromptTemplate template : templateManager.getActiveTemplates()) {
            templateSelector.addItem(template.getName());
        }
        
        templateRow.add(templateSelector);
        
        JButton manageTemplatesBtn = new JButton("⚙️ Manage");
        manageTemplatesBtn.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        manageTemplatesBtn.setToolTipText("Open Prompt Templates tab");
        manageTemplatesBtn.setFocusPainted(false);
        manageTemplatesBtn.setMargin(new Insets(2, 8, 2, 8));
        manageTemplatesBtn.addActionListener(e -> {
            // Switch to Prompt Templates tab
            Container parent = getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) {
                parent = parent.getParent();
            }
            if (parent instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) parent;
                // Find the Prompt Templates tab (should be index 4)
                for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                    if (tabbedPane.getTitleAt(i).contains("Prompt Templates")) {
                        tabbedPane.setSelectedIndex(i);
                        break;
                    }
                }
            }
        });
        templateRow.add(manageTemplatesBtn);
        
        JLabel templateHint = new JLabel("(Select a template for specialized testing)");
        templateHint.setFont(new Font("Segoe UI", Font.ITALIC, 9));
        templateHint.setForeground(new Color(120, 120, 125));
        templateRow.add(templateHint);

        JPanel queryRow = new JPanel(new BorderLayout(8, 0));
        
        queryField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        queryField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(180, 180, 185)),
            new EmptyBorder(8, 10, 8, 10)));
        installPlaceholder(queryField, "Ask: 'How to test for XSS?' or 'Bypass this WAF'");

        JButton askBtn = new JButton("Send");
        askBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        askBtn.setFocusPainted(false);
        askBtn.addActionListener(e -> getSuggestions());

        JButton clearBtn = new JButton("Clear");
        clearBtn.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        clearBtn.addActionListener(e -> clearConversation());
        
        JButton newSessionBtn = new JButton("🆕 New Session");
        newSessionBtn.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        newSessionBtn.setToolTipText("Start fresh session (clears conversation but keeps current request)");
        newSessionBtn.addActionListener(e -> startNewSession());

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        btnPanel.add(newSessionBtn);
        btnPanel.add(clearBtn);
        btnPanel.add(askBtn);

        queryRow.add(queryField, BorderLayout.CENTER);
        queryRow.add(btnPanel, BorderLayout.EAST);

        JPanel quickPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        String[] quickQueries = {"XSS Testing", "SQLi Testing", "SSTI Testing", "Command Injection", "SSRF Testing", "Bypass WAF"};
        for (String query : quickQueries) {
            JButton btn = createQuickButton(query);
            quickPanel.add(btn);
        }

        JPanel topSection = new JPanel();
        topSection.setLayout(new BoxLayout(topSection, BoxLayout.Y_AXIS));
        topSection.add(titleRow);
        topSection.add(Box.createVerticalStrut(4));
        topSection.add(templateRow);
        topSection.add(Box.createVerticalStrut(8));

        panel.add(topSection, BorderLayout.NORTH);
        panel.add(queryRow, BorderLayout.CENTER);
        panel.add(quickPanel, BorderLayout.SOUTH);

        return panel;
    }
    
    private JButton createQuickButton(String label) {
        JButton btn = new JButton(label);
        btn.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        btn.setFocusPainted(false);
        btn.addActionListener(e -> {
            queryField.setText("How to test for " + label + "?");
            getSuggestions();
        });
        return btn;
    }

    private JSplitPane buildMainContent() {
        // Left: Request/Response tabs with search
        JTabbedPane leftTabs = new JTabbedPane();
        leftTabs.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        
        Font monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        requestArea.setFont(monoFont);
        requestArea.setEditable(false);
        
        responseArea.setFont(monoFont);
        responseArea.setEditable(false);

        JPanel requestPanel = createSearchablePanel(requestArea, requestSearchField, requestMatchLabel);
        JPanel responsePanel = createSearchablePanel(responseArea, responseSearchField, responseMatchLabel);

        leftTabs.addTab("Request", requestPanel);
        leftTabs.addTab("Response", responsePanel);

        // Right: Suggestions area with interactive chat
        JPanel rightPanel = new JPanel(new BorderLayout());
        
        suggestionsArea.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        suggestionsArea.setEditable(false);
        suggestionsArea.setLineWrap(true);
        suggestionsArea.setWrapStyleWord(true);
        
        JScrollPane suggestionsScroll = new JScrollPane(suggestionsArea);
        suggestionsScroll.setBorder(BorderFactory.createTitledBorder("AI Conversation"));
        
        // Loading indicator (initially hidden)
        loadingLabel = new JLabel();
        loadingLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        loadingLabel.setForeground(new Color(0, 120, 215));
        loadingLabel.setHorizontalAlignment(SwingConstants.CENTER);
        loadingLabel.setBorder(new EmptyBorder(10, 10, 10, 10));
        loadingLabel.setVisible(false);
        
        JPanel suggestionsPanel = new JPanel(new BorderLayout());
        suggestionsPanel.add(suggestionsScroll, BorderLayout.CENTER);
        suggestionsPanel.add(loadingLabel, BorderLayout.SOUTH);

        rightPanel.add(suggestionsPanel, BorderLayout.CENTER);
        
        // Interactive chat panel (shown only in Interactive mode)
        interactiveChatPanel = buildInteractiveChatPanel();
        interactiveChatPanel.setVisible(false);
        rightPanel.add(interactiveChatPanel, BorderLayout.SOUTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftTabs, rightPanel);
        mainSplit.setResizeWeight(0.4);

        return mainSplit;
    }
    
    private JPanel buildInteractiveChatPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(2, 0, 0, 0, new Color(200, 200, 205)),
            new EmptyBorder(12, 12, 12, 12)
        ));
        
        // Top section with multi-request management and dropdown
        JPanel topSection = new JPanel(new BorderLayout(8, 4));
        
        // Multi-request info panel
        JPanel multiRequestPanel = new JPanel(new BorderLayout(8, 0));
        multiRequestLabel = new JLabel("No requests attached");
        multiRequestLabel.setFont(new Font("Segoe UI", Font.ITALIC, 10));
        multiRequestLabel.setForeground(new Color(120, 120, 125));
        
        manageRequestsButton = new JButton("📎 Manage Requests (0)");
        manageRequestsButton.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        manageRequestsButton.setToolTipText("View, add, or remove attached requests");
        manageRequestsButton.setFocusPainted(false);
        manageRequestsButton.setMargin(new Insets(2, 8, 2, 8));
        manageRequestsButton.addActionListener(e -> showMultiRequestManager());
        
        multiRequestPanel.add(multiRequestLabel, BorderLayout.CENTER);
        multiRequestPanel.add(manageRequestsButton, BorderLayout.EAST);
        
        // Dropdown for recent Repeater requests
        JPanel dropdownPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JLabel dropdownLabel = new JLabel("Quick attach from Repeater:");
        dropdownLabel.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        
        JComboBox<String> repeaterDropdown = new JComboBox<>();
        repeaterDropdown.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        repeaterDropdown.setPrototypeDisplayValue("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        repeaterDropdown.addItem("-- Select recent Repeater request --");
        repeaterDropdown.addActionListener(e -> {
            int selectedIndex = repeaterDropdown.getSelectedIndex();
            if (selectedIndex > 0) { // 0 is the placeholder
                attachFromRepeaterHistory(selectedIndex - 1);
                repeaterDropdown.setSelectedIndex(0); // Reset to placeholder
            }
        });
        
        // Refresh button to update dropdown
        JButton refreshBtn = new JButton("🔄");
        refreshBtn.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        refreshBtn.setToolTipText("Refresh Repeater request list");
        refreshBtn.setFocusPainted(false);
        refreshBtn.setMargin(new Insets(2, 6, 2, 6));
        refreshBtn.addActionListener(e -> updateRepeaterDropdown(repeaterDropdown));
        
        dropdownPanel.add(dropdownLabel);
        dropdownPanel.add(repeaterDropdown);
        dropdownPanel.add(refreshBtn);
        
        topSection.add(multiRequestPanel, BorderLayout.NORTH);
        topSection.add(dropdownPanel, BorderLayout.SOUTH);
        
        // Input row
        JPanel inputRow = new JPanel(new BorderLayout(8, 0));
        
        interactiveChatField = new JTextField();
        interactiveChatField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        interactiveChatField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(180, 180, 185)),
            new EmptyBorder(8, 10, 8, 10)));
        installPlaceholder(interactiveChatField, "Report what you observed or ask for bypass suggestions...");
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        
        JButton sendBtn = new JButton("Send");
        sendBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        sendBtn.setFocusPainted(false);
        sendBtn.addActionListener(e -> sendInteractiveMessage());
        
        buttonPanel.add(sendBtn);
        
        inputRow.add(interactiveChatField, BorderLayout.CENTER);
        inputRow.add(buttonPanel, BorderLayout.EAST);
        
        panel.add(topSection, BorderLayout.NORTH);
        panel.add(inputRow, BorderLayout.CENTER);
        
        // Enter key to send
        interactiveChatField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    sendInteractiveMessage();
                }
            }
        });
        
        // Store dropdown reference for later updates
        this.repeaterRequestDropdown = repeaterDropdown;
        
        return panel;
    }
    
    
    /**
     * Shows the multi-request manager dialog
     */
    private void showMultiRequestManager() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Manage Attached Requests", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(800, 600);
        
        // List of attached requests
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (int i = 0; i < attachedRequests.size(); i++) {
            IHttpRequestResponse req = attachedRequests.get(i);
            String summary = getRequestSummary(req, i + 1);
            listModel.addElement(summary);
        }
        
        JList<String> requestList = new JList<>(listModel);
        requestList.setFont(new Font("Monospaced", Font.PLAIN, 11));
        requestList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION); // Allow multi-select
        
        JScrollPane listScroll = new JScrollPane(requestList);
        listScroll.setBorder(BorderFactory.createTitledBorder("Attached Requests (" + attachedRequests.size() + ")"));
        
        // Preview area
        JTextArea previewArea = new JTextArea();
        previewArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        previewArea.setEditable(false);
        JScrollPane previewScroll = new JScrollPane(previewArea);
        previewScroll.setBorder(BorderFactory.createTitledBorder("Preview"));
        
        // Update preview when selection changes
        requestList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedIndex = requestList.getSelectedIndex();
                if (selectedIndex >= 0 && selectedIndex < attachedRequests.size()) {
                    IHttpRequestResponse req = attachedRequests.get(selectedIndex);
                    String reqText = new String(req.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                    String respText = req.getResponse() != null ? 
                        new String(req.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "(No response)";
                    previewArea.setText("=== REQUEST ===\n" + reqText + "\n\n=== RESPONSE ===\n" + respText);
                    previewArea.setCaretPosition(0);
                }
            }
        });
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, previewScroll);
        splitPane.setResizeWeight(0.4);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        
        JButton addBtn = new JButton("➕ Add Request");
        addBtn.addActionListener(e -> {
            attachTestRequest();
            dialog.dispose();
            showMultiRequestManager(); // Reopen to show updated list
        });
        
        JButton removeBtn = new JButton("➖ Remove Selected");
        removeBtn.addActionListener(e -> {
            int[] selectedIndices = requestList.getSelectedIndices();
            if (selectedIndices.length > 0) {
                // Remove in reverse order to maintain indices
                for (int i = selectedIndices.length - 1; i >= 0; i--) {
                    attachedRequests.remove(selectedIndices[i]);
                }
                updateMultiRequestLabel();
                dialog.dispose();
                showMultiRequestManager(); // Reopen to show updated list
            } else {
                JOptionPane.showMessageDialog(dialog, 
                    "Please select one or more requests to remove",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });
        
        JButton clearAllBtn = new JButton("🗑️ Clear All");
        clearAllBtn.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(dialog, 
                "Remove all " + attachedRequests.size() + " attached requests?",
                "Confirm Clear All", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                attachedRequests.clear();
                updateMultiRequestLabel();
                dialog.dispose();
            }
        });
        
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(addBtn);
        buttonPanel.add(removeBtn);
        buttonPanel.add(clearAllBtn);
        buttonPanel.add(closeBtn);
        
        dialog.add(splitPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    /**
     * Gets a summary string for a request
     */
    private String getRequestSummary(IHttpRequestResponse req, int index) {
        try {
            byte[] request = req.getRequest();
            if (request != null && request.length > 0) {
                String requestStr = new String(request, 0, Math.min(200, request.length));
                String[] lines = requestStr.split("\r?\n");
                if (lines.length > 0) {
                    return String.format("#%d: %s", index, lines[0]);
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return String.format("#%d: Unknown request", index);
    }
    
    /**
     * Updates the multi-request label
     */
    private void updateMultiRequestLabel() {
        int count = attachedRequests.size();
        if (count == 0) {
            multiRequestLabel.setText("No requests attached");
            multiRequestLabel.setForeground(new Color(120, 120, 125));
            multiRequestLabel.setFont(new Font("Segoe UI", Font.ITALIC, 10));
        } else if (count == 1) {
            multiRequestLabel.setText("✓ 1 request attached");
            multiRequestLabel.setForeground(new Color(0, 150, 0));
            multiRequestLabel.setFont(new Font("Segoe UI", Font.BOLD, 10));
        } else {
            multiRequestLabel.setText("✓ " + count + " requests attached");
            multiRequestLabel.setForeground(new Color(0, 150, 0));
            multiRequestLabel.setFont(new Font("Segoe UI", Font.BOLD, 10));
        }
        
        if (manageRequestsButton != null) {
            manageRequestsButton.setText("📎 Manage Requests (" + count + ")");
        }
        
        // Update chat field background
        if (interactiveChatField != null) {
            if (count > 0) {
                interactiveChatField.setBackground(new Color(230, 255, 230)); // Light green
            } else {
                interactiveChatField.setBackground(Color.WHITE);
            }
        }
    }
    
    private void attachTestRequest() {
        // Show dialog to paste request/response
        JPanel dialogPanel = new JPanel(new BorderLayout(8, 8));
        
        JLabel infoLabel = new JLabel("<html><b>Paste the request/response you tested from Burp Repeater:</b><br>" +
            "This helps AI understand what you actually tested and observed.</html>");
        
        JTextArea requestArea = new JTextArea(10, 60);
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        requestArea.setLineWrap(false);
        JScrollPane requestScroll = new JScrollPane(requestArea);
        requestScroll.setBorder(BorderFactory.createTitledBorder("Request"));
        
        JTextArea responseArea = new JTextArea(10, 60);
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        responseArea.setLineWrap(false);
        JScrollPane responseScroll = new JScrollPane(responseArea);
        responseScroll.setBorder(BorderFactory.createTitledBorder("Response (optional)"));
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestScroll, responseScroll);
        splitPane.setResizeWeight(0.5);
        
        dialogPanel.add(infoLabel, BorderLayout.NORTH);
        dialogPanel.add(splitPane, BorderLayout.CENTER);
        
        int result = JOptionPane.showConfirmDialog(this, dialogPanel, 
            "Attach Test Request/Response", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        
        if (result == JOptionPane.OK_OPTION) {
            String reqText = requestArea.getText().trim();
            String respText = responseArea.getText().trim();
            
            if (!reqText.isEmpty()) {
                // Create a mock IHttpRequestResponse and add to list
                IHttpRequestResponse newRequest = new IHttpRequestResponse() {
                    private byte[] request = reqText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    private byte[] response = respText.isEmpty() ? null : respText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    
                    @Override public byte[] getRequest() { return request; }
                    @Override public byte[] getResponse() { return response; }
                    @Override public burp.IHttpService getHttpService() { return null; }
                };
                
                attachedRequests.add(newRequest);
                updateMultiRequestLabel();
                
                appendSuggestion("SYSTEM", "✓ Request attached (" + reqText.length() + " bytes). Total: " + attachedRequests.size());
            }
        }
    }
    
    private void sendInteractiveMessage() {
        String message = interactiveChatField.getText().trim();
        if (message.isEmpty() || message.startsWith("Report what")) return;
        
        interactiveChatField.setText("");
        
        callbacks.printOutput("[VISTA] sendInteractiveMessage called with: " + message);
        callbacks.printOutput("[VISTA] Attached requests count: " + attachedRequests.size());
        
        // Add user message to conversation
        appendSuggestion("YOU", message);
        conversationHistory.add(new ConversationMessage("user", message));
        
        // If requests attached, add them to context
        if (!attachedRequests.isEmpty()) {
            callbacks.printOutput("[VISTA] Processing " + attachedRequests.size() + " attached request(s)...");
            
            for (int i = 0; i < attachedRequests.size(); i++) {
                IHttpRequestResponse req = attachedRequests.get(i);
                String reqText = new String(req.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                String respText = req.getResponse() != null ? 
                    new String(req.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";
                
                callbacks.printOutput("[VISTA] Request #" + (i+1) + " length: " + reqText.length());
                callbacks.printOutput("[VISTA] Response #" + (i+1) + " length: " + respText.length());
                
                // Store this test step
                testingSteps.add(new TestingStep(
                    "Step " + (testingSteps.size() + 1) + (attachedRequests.size() > 1 ? " (Request " + (i+1) + ")" : ""),
                    reqText,
                    respText,
                    message
                ));
            }
            
            callbacks.printOutput("[VISTA] Added to testingSteps. Total steps: " + testingSteps.size());
            
            // Show clear feedback
            if (attachedRequests.size() == 1) {
                String reqText = new String(attachedRequests.get(0).getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                String respText = attachedRequests.get(0).getResponse() != null ? 
                    new String(attachedRequests.get(0).getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";
                appendSuggestion("SYSTEM", "📎 Request/Response attached and sent to AI for analysis");
                appendSuggestion("SYSTEM", "   Request: " + truncate(reqText.split("\n")[0], 80));
                appendSuggestion("SYSTEM", "   Response: " + (respText.isEmpty() ? "(empty)" : respText.length() + " bytes"));
            } else {
                appendSuggestion("SYSTEM", "📎 " + attachedRequests.size() + " requests/responses sent to AI for analysis");
                for (int i = 0; i < attachedRequests.size(); i++) {
                    String reqText = new String(attachedRequests.get(i).getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                    appendSuggestion("SYSTEM", "   #" + (i+1) + ": " + truncate(reqText.split("\n")[0], 70));
                }
            }
            
            // Clear attachments after sending
            attachedRequests.clear();
            updateMultiRequestLabel();
            
            callbacks.printOutput("[VISTA] Attachments cleared");
        } else {
            callbacks.printOutput("[VISTA] No requests attached - sending message only");
        }
        
        // Process with AI
        statusLabel.setText("Processing your observation...");
        callbacks.printOutput("[VISTA] Starting AI processing thread");
        new Thread(() -> handleInteractiveAssistant(message), "VISTA-Interactive").start();
    }

    private JPanel createSearchablePanel(JTextArea textArea, JTextField searchField, JLabel matchLabel) {
        JPanel panel = new JPanel(new BorderLayout());
        
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        
        JLabel searchIcon = new JLabel("🔍");
        searchField.setPreferredSize(new Dimension(150, 24));
        
        JButton prevBtn = new JButton("◀");
        JButton nextBtn = new JButton("▶");
        prevBtn.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        nextBtn.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        prevBtn.setMargin(new Insets(2, 6, 2, 6));
        nextBtn.setMargin(new Insets(2, 6, 2, 6));
        
        matchLabel.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        
        searchBar.add(searchIcon);
        searchBar.add(searchField);
        searchBar.add(prevBtn);
        searchBar.add(nextBtn);
        searchBar.add(matchLabel);
        
        int[] currentMatch = {-1};
        List<int[]> matches = new ArrayList<>();
        
        Runnable doSearch = () -> {
            String searchText = searchField.getText();
            String content = textArea.getText();
            matches.clear();
            currentMatch[0] = -1;
            textArea.getHighlighter().removeAllHighlights();
            
            if (searchText.isEmpty() || content.isEmpty()) {
                matchLabel.setText("");
                return;
            }
            
            String lowerContent = content.toLowerCase();
            String lowerSearch = searchText.toLowerCase();
            int index = 0;
            
            while ((index = lowerContent.indexOf(lowerSearch, index)) != -1) {
                matches.add(new int[]{index, index + searchText.length()});
                try {
                    textArea.getHighlighter().addHighlight(index, index + searchText.length(),
                        new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 255, 0, 150)));
                } catch (BadLocationException ignored) {}
                index += searchText.length();
            }
            
            if (!matches.isEmpty()) {
                currentMatch[0] = 0;
                matchLabel.setText("1/" + matches.size());
                scrollToMatch(textArea, matches.get(0));
            } else {
                matchLabel.setText("0/0");
            }
        };
        
        searchField.addActionListener(e -> doSearch.run());
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (e.getKeyCode() != KeyEvent.VK_ENTER) doSearch.run();
            }
        });
        
        nextBtn.addActionListener(e -> {
            if (!matches.isEmpty()) {
                currentMatch[0] = (currentMatch[0] + 1) % matches.size();
                matchLabel.setText((currentMatch[0] + 1) + "/" + matches.size());
                scrollToMatch(textArea, matches.get(currentMatch[0]));
            }
        });
        
        prevBtn.addActionListener(e -> {
            if (!matches.isEmpty()) {
                currentMatch[0] = (currentMatch[0] - 1 + matches.size()) % matches.size();
                matchLabel.setText((currentMatch[0] + 1) + "/" + matches.size());
                scrollToMatch(textArea, matches.get(currentMatch[0]));
            }
        });
        
        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setBorder(null);
        
        panel.add(searchBar, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void scrollToMatch(JTextArea textArea, int[] match) {
        try {
            textArea.setCaretPosition(match[0]);
            Rectangle rect = textArea.modelToView(match[0]);
            if (rect != null) textArea.scrollRectToVisible(rect);
        } catch (BadLocationException ignored) {}
    }

    private JPanel buildFooterPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        panel.setBorder(new EmptyBorder(8, 12, 8, 12));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftPanel.add(statusLabel);

        panel.add(leftPanel, BorderLayout.WEST);

        return panel;
    }

    private void updateConfigStatus() {
        AIConfigManager config = AIConfigManager.getInstance();
        if (config.isConfigured()) {
            configStatusLabel.setText("✓ " + config.getProvider() + " ready");
            configStatusLabel.setForeground(new Color(0, 150, 0));
        } else {
            configStatusLabel.setText("⚠ Configure AI in Settings tab");
            configStatusLabel.setForeground(new Color(255, 180, 100));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Request Management
    // ═══════════════════════════════════════════════════════════════

    public void setRequest(IHttpRequestResponse request) {
        // Check if this is a NEW request (different from current)
        boolean isNewRequest = (this.currentRequest == null) || 
                               !isSameRequest(this.currentRequest, request);
        
        this.currentRequest = request;
        
        if (request != null) {
            String reqText = HttpMessageParser.requestToText(helpers, request.getRequest());
            requestArea.setText(reqText);
            requestArea.setCaretPosition(0);

            if (request.getResponse() != null) {
                String respText = HttpMessageParser.responseToText(helpers, request.getResponse());
                responseArea.setText(respText);
                responseArea.setCaretPosition(0);
            } else {
                responseArea.setText("(No response captured)");
            }

            String summary = extractRequestSummary(reqText);
            
            // If this is a NEW request, start a NEW session
            if (isNewRequest) {
                // Save current session before clearing
                if (!conversationHistory.isEmpty()) {
                    SessionManager.getInstance().saveConversationHistory(conversationHistory);
                }
                
                // Clear conversation for new request
                clearConversation();
                
                statusLabel.setText("New Session: " + summary);
                appendSuggestion("SYSTEM", "🆕 NEW SESSION STARTED\n\n" +
                    "Request loaded: " + summary + "\n\n" +
                    "Previous conversation cleared. This is a fresh session for this request.\n\n" +
                    "Ask me how to test for vulnerabilities!");
                
                callbacks.printOutput("[VISTA] New session started for: " + summary);
            } else {
                // Same request, continue existing session
                statusLabel.setText("Loaded: " + summary);
                appendSuggestion("SYSTEM", "Request reloaded: " + summary + "\n\n" +
                    "Continuing existing session. Ask follow-up questions!");
            }
        }
    }
    
    /**
     * Check if two requests are the same (same URL and method).
     */
    private boolean isSameRequest(IHttpRequestResponse req1, IHttpRequestResponse req2) {
        if (req1 == null || req2 == null) return false;
        
        try {
            // Compare request bytes
            byte[] bytes1 = req1.getRequest();
            byte[] bytes2 = req2.getRequest();
            
            if (bytes1 == null || bytes2 == null) return false;
            
            // Extract first line (method + URL)
            String line1 = extractFirstLine(bytes1);
            String line2 = extractFirstLine(bytes2);
            
            return line1.equals(line2);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Extract first line from request bytes.
     */
    private String extractFirstLine(byte[] requestBytes) {
        String request = new String(requestBytes);
        String[] lines = request.split("\r?\n");
        return lines.length > 0 ? lines[0] : "";
    }

    private String extractRequestSummary(String reqText) {
        String[] lines = reqText.split("\r?\n");
        if (lines.length > 0) {
            String firstLine = lines[0];
            return firstLine.length() > 60 ? firstLine.substring(0, 60) + "..." : firstLine;
        }
        return "Request";
    }

    // ═══════════════════════════════════════════════════════════════
    // AI Suggestions System
    // ═══════════════════════════════════════════════════════════════

    private void getSuggestions() {
        String userQuery = queryField.getText().trim();
        if (userQuery.isEmpty() || userQuery.startsWith("Ask:")) return;
        
        if (currentRequest == null) {
            appendSuggestion("SYSTEM", "⚠️ No request loaded. Right-click a request in Burp and select 'Send to VISTA AI'.");
            return;
        }

        if (!AIConfigManager.getInstance().isConfigured()) {
            appendSuggestion("SYSTEM", "⚠️ AI not configured. Go to Settings tab to configure your AI provider.");
            return;
        }

        appendSuggestion("YOU", userQuery);
        queryField.setText("");
        conversationHistory.add(new ConversationMessage("user", userQuery));
        
        // Always use Interactive Assistant mode
        statusLabel.setText("Processing your request...");
        new Thread(() -> handleInteractiveAssistant(userQuery), "VISTA-Interactive").start();
        
        // Show interactive chat panel after first query
        if (interactiveChatPanel != null) {
            interactiveChatPanel.setVisible(true);
        }
    }
    
    private void handleQuickSuggestions(String userQuery) {
        try {
            String requestText = new String(currentRequest.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
            String responseText = currentRequest.getResponse() != null ? 
                new String(currentRequest.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";

            // Build comprehensive prompt with methodology
            String prompt = buildQuickSuggestionsPrompt(userQuery, requestText, responseText);
            
            // Call AI
            String suggestions = callAI(prompt);
            
            conversationHistory.add(new ConversationMessage("assistant", suggestions));
            
            SwingUtilities.invokeLater(() -> {
                appendSuggestion("VISTA", suggestions);
                statusLabel.setText("Ready");
            });

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                appendSuggestion("SYSTEM", "❌ Error: " + e.getMessage());
                statusLabel.setText("Error");
            });
        }
    }
    
    private void handleInteractiveAssistant(String userQuery) {
        try {
            // Show loading indicator
            showLoadingIndicator(true);
            
            String requestText = new String(currentRequest.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
            String responseText = currentRequest.getResponse() != null ? 
                new String(currentRequest.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";

            // Check if a template is selected
            String selectedTemplate = (String) templateSelector.getSelectedItem();
            String prompt;
            
            if (selectedTemplate != null && !selectedTemplate.startsWith("--")) {
                // Use template
                PromptTemplate template = templateManager.getTemplateByName(selectedTemplate);
                if (template != null) {
                    // Build variable context
                    VariableContext context = buildVariableContext(userQuery, requestText, responseText);
                    context.setUserQuery(userQuery); // Set the user's actual question
                    
                    // Process template with variables
                    String processedTemplate = templateManager.processTemplate(template, context);
                    
                    // IMPORTANT: Append user's query to ensure AI responds to their specific question
                    prompt = processedTemplate + "\n\n=== USER'S SPECIFIC QUESTION ===\n" + userQuery + 
                             "\n\nIMPORTANT: Address the user's specific question above while following the template guidance.";
                } else {
                    // Fallback to default
                    prompt = buildInteractivePrompt(userQuery, requestText, responseText);
                }
            } else {
                // Use default prompt building
                prompt = buildInteractivePrompt(userQuery, requestText, responseText);
            }
            
            // Call AI
            String response = callAI(prompt);
            
            conversationHistory.add(new ConversationMessage("assistant", response));
            
            SwingUtilities.invokeLater(() -> {
                // Hide loading indicator
                showLoadingIndicator(false);
                
                appendSuggestion("VISTA", response);
                statusLabel.setText("Waiting for your test results...");
                
                // Show interactive chat panel after first AI response
                if (interactiveChatPanel != null) {
                    interactiveChatPanel.setVisible(true);
                }
            });

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                // Hide loading indicator
                showLoadingIndicator(false);
                
                appendSuggestion("SYSTEM", "❌ Error: " + e.getMessage());
                statusLabel.setText("Error");
            });
        }
    }
    
    /**
     * Show or hide loading indicator with animation.
     */
    private void showLoadingIndicator(boolean show) {
        SwingUtilities.invokeLater(() -> {
            if (show) {
                loadingLabel.setText("🤖 AI is thinking...");
                loadingLabel.setVisible(true);
                
                // Start animation
                Timer animationTimer = new Timer(500, new ActionListener() {
                    private int dots = 0;
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        dots = (dots + 1) % 4;
                        String dotString = ".".repeat(dots);
                        loadingLabel.setText("🤖 AI is thinking" + dotString);
                    }
                });
                animationTimer.start();
                loadingLabel.putClientProperty("animationTimer", animationTimer);
            } else {
                // Stop animation
                Timer animationTimer = (Timer) loadingLabel.getClientProperty("animationTimer");
                if (animationTimer != null) {
                    animationTimer.stop();
                }
                loadingLabel.setVisible(false);
            }
        });
    }

    private String buildQuickSuggestionsPrompt(String userQuery, String request, String response) {
        // Analyze reflections
        String reflectionAnalysis = "Not available (no request loaded)";
        if (currentRequest != null) {
            ReflectionAnalyzer.ReflectionAnalysis analysis = reflectionAnalyzer.analyze(currentRequest);
            reflectionAnalysis = analysis.getSummary();
        }
        
        // Detect WAF
        List<WAFDetector.WAFInfo> wafList = WAFDetector.detectWAF(response, response, extractStatusCode(response));
        String wafInfo = wafList.isEmpty() ? "No WAF detected" : WAFDetector.getBypassSuggestions(wafList);
        
        // Get systematic methodology
        String methodology = SystematicTestingEngine.getMethodology(userQuery, request, response).toFormattedString();
        
        // Get bypass knowledge
        String bypassKnowledge = BypassKnowledgeBase.getBypassKnowledge(userQuery);
        
        // Build context from conversation
        StringBuilder conversationContext = new StringBuilder();
        if (!conversationHistory.isEmpty()) {
            conversationContext.append("\n\nPREVIOUS CONVERSATION:\n");
            for (ConversationMessage msg : conversationHistory) {
                conversationContext.append(msg.role.toUpperCase()).append(": ").append(msg.content).append("\n");
            }
        }
        
        return """
            You are a senior penetration testing consultant providing expert testing guidance.
            Your role is to provide SUGGESTIONS and METHODOLOGY, not to perform automatic testing.
            
            USER'S QUESTION: %s
            %s
            
            === REQUEST ===
            %s
            
            === RESPONSE ===
            %s
            
            === REFLECTION ANALYSIS ===
            %s
            
            === WAF DETECTION ===
            %s
            
            === SYSTEMATIC TESTING METHODOLOGY ===
            %s
            
            === BYPASS KNOWLEDGE BASE (PayloadsAllTheThings) ===
            %s
            
            CRITICAL INSTRUCTIONS:
            1. START with reflection analysis - tell user EXACTLY where parameters are reflected
            2. Based on reflection context (HTML body, attribute, JavaScript, etc.), suggest SPECIFIC payloads
            3. If parameter is encoded, suggest encoding bypass techniques
            4. If parameter is in exploitable context, provide ready-to-use payloads
            5. Include WAF bypass techniques if WAF detected
            6. Reference PayloadsAllTheThings techniques
            7. Explain WHY each payload works for that specific context
            8. Provide expected results for each test
            9. Be conversational and educational
            
            Format your response as:
            
            🔍 REFLECTION POINTS:
            [Summarize where and how parameters are reflected - be specific!]
            [Example: "Parameter 'q' is reflected in HTML body without encoding - EXPLOITABLE!"]
            [Example: "Parameter 'search' is reflected in JavaScript string with quotes - need to break out"]
            
            📋 TESTING APPROACH:
            [Step-by-step methodology based on reflection analysis]
            
            🎯 CONTEXT-SPECIFIC PAYLOADS:
            [Payloads tailored to the exact reflection context]
            [Example: For HTML body: <script>alert(1)</script>]
            [Example: For JS string: '; alert(1);//]
            [Example: For HTML attribute: " onload="alert(1)]
            
            🛡️ WAF BYPASS (if applicable):
            [WAF-specific techniques]
            
            ✅ EXPECTED RESULTS:
            [What to look for]
            
            💡 PRO TIPS:
            [Additional insights]
            
            REMEMBER: User should NOT need to test for reflections - you already have that info!
            Provide actionable, context-aware guidance based on actual reflection analysis.
            """.formatted(userQuery, conversationContext.toString(), 
                         truncate(request, 2000), truncate(response, 1500),
                         reflectionAnalysis,
                         wafInfo, truncate(methodology, 3000), truncate(bypassKnowledge, 2000));
    }
    
    private String buildInteractivePrompt(String userQuery, String request, String response) {
        // Deep request analysis
        String deepRequestAnalysis = "Not available (no request loaded)";
        String detectedVulnType = null;
        String reflectionContext = "unknown";
        
        if (currentRequest != null) {
            RequestAnalysis reqAnalysis = deepRequestAnalyzer.analyze(currentRequest);
            deepRequestAnalysis = reqAnalysis.toFormattedString();
            
            // Extract vulnerability type for payload library
            if (!reqAnalysis.predictedVulnerabilities.isEmpty()) {
                detectedVulnType = reqAnalysis.predictedVulnerabilities.get(0);
            }
        }
        
        // Deep response analysis
        String deepResponseAnalysis = "Not available (no response)";
        if (currentRequest != null && currentRequest.getResponse() != null) {
            ResponseAnalysis respAnalysis = responseAnalyzer.analyze(currentRequest);
            deepResponseAnalysis = respAnalysis.toFormattedString();
        }
        
        // Analyze reflections (keep existing for compatibility)
        String reflectionAnalysis = "Not available (no request loaded)";
        if (currentRequest != null) {
            ReflectionAnalyzer.ReflectionAnalysis analysis = reflectionAnalyzer.analyze(currentRequest);
            reflectionAnalysis = analysis.getSummary();
            
            // Extract reflection context for payload library
            if (!analysis.getReflections().isEmpty()) {
                List<ReflectionAnalyzer.ReflectionContext> contexts = analysis.getReflections().get(0).getContexts();
                if (!contexts.isEmpty()) {
                    reflectionContext = contexts.get(0).getContextType();
                }
            }
        }
        
        // Get relevant payloads from library based on detected vulnerability and context
        String payloadLibraryContext = "";
        if (detectedVulnType != null) {
            // Get context-aware payloads
            payloadLibraryContext = payloadLibraryAI.getPayloadContextForAI(
                detectedVulnType, reflectionContext, true, 8);
            
            // Add top performing payloads if available
            String topPayloads = payloadLibraryAI.getTopPayloadsForAI(detectedVulnType, 5);
            if (!topPayloads.isEmpty()) {
                payloadLibraryContext += topPayloads;
            }
        }
        
        // If no specific vuln detected, show recently successful payloads
        if (payloadLibraryContext.isEmpty()) {
            payloadLibraryContext = payloadLibraryAI.getRecentSuccessfulPayloadsForAI(5);
        }
        
        // Add library stats
        payloadLibraryContext += payloadLibraryAI.getLibraryStatsForAI();
        
        // Detect WAF
        List<WAFDetector.WAFInfo> wafList = WAFDetector.detectWAF(response, response, extractStatusCode(response));
        String wafInfo = wafList.isEmpty() ? "No WAF detected" : WAFDetector.getBypassSuggestions(wafList);
        
        // If WAF detected, add bypass payloads
        if (!wafList.isEmpty() && detectedVulnType != null) {
            String wafType = wafList.get(0).name;
            payloadLibraryContext += payloadLibraryAI.getWAFBypassPayloadsForAI(detectedVulnType, wafType);
        }
        
        // Get systematic methodology
        String methodology = SystematicTestingEngine.getMethodology(userQuery, request, response).toFormattedString();
        
        // Get bypass knowledge
        String bypassKnowledge = BypassKnowledgeBase.getBypassKnowledge(userQuery);
        
        // Build context from conversation
        StringBuilder conversationContext = new StringBuilder();
        if (!conversationHistory.isEmpty()) {
            conversationContext.append("\n\nPREVIOUS CONVERSATION:\n");
            for (ConversationMessage msg : conversationHistory) {
                conversationContext.append(msg.role.toUpperCase()).append(": ").append(msg.content).append("\n");
            }
        }
        
        // Build testing history context
        StringBuilder testingHistory = new StringBuilder();
        if (!testingSteps.isEmpty()) {
            testingHistory.append("\n\nTESTING HISTORY (What user actually tested):\n");
            for (int i = 0; i < testingSteps.size(); i++) {
                TestingStep step = testingSteps.get(i);
                testingHistory.append("\n--- TEST ").append(i + 1).append(" ---\n");
                testingHistory.append("User's Observation: ").append(step.observation).append("\n");
                testingHistory.append("Request Tested:\n").append(truncate(step.request, 1000)).append("\n");
                if (step.response != null && !step.response.isEmpty()) {
                    testingHistory.append("Response Received:\n").append(truncate(step.response, 800)).append("\n");
                }
            }
        }
        
        // Determine if this is initial request or follow-up
        boolean isInitialRequest = conversationHistory.size() <= 1;
        
        if (isInitialRequest) {
            return """
                You are an expert penetration testing mentor providing personalized, context-aware guidance.
                
                USER'S QUESTION: %s
                
                === DEEP REQUEST ANALYSIS ===
                %s
                
                === DEEP RESPONSE ANALYSIS ===
                %s
                
                === REFLECTION ANALYSIS ===
                %s
                
                === WAF DETECTION ===
                %s
                
                === SYSTEMATIC METHODOLOGY ===
                %s
                
                === BYPASS KNOWLEDGE BASE ===
                %s
                
                === PAYLOAD LIBRARY (Proven Payloads) ===
                %s
                
                INSTRUCTIONS:
                Provide a SINGLE, COHESIVE response that naturally integrates ALL the above context.
                
                Your response should flow naturally and include:
                1. Start with a brief analysis of what you see in the request/response (2-3 sentences)
                2. Identify the most promising vulnerability based on the deep analysis
                3. Provide ONE specific test with a payload (preferably from the library)
                4. Explain WHY this payload will work in this specific context
                5. Give clear testing instructions
                6. Tell them what to look for
                
                CRITICAL RULES:
                - Write in a natural, conversational tone (not bullet points or sections)
                - Integrate all context seamlessly into your narrative
                - Prioritize payloads from the library (they have proven success rates!)
                - Reference the deep analysis findings naturally in your explanation
                - If WAF detected, explain how your payload bypasses it
                - If high-risk issues found, mention them naturally in context
                - Keep it focused on ONE test at a time
                - End by asking them to test and report back
                
                DO NOT use section headers like "🔍 ANALYSIS" or "🎯 STEP 1".
                Instead, write a flowing narrative that guides them naturally through the testing process.
                
                Example of good response:
                "Looking at your request to /search?q=test, I can see this is a high-risk endpoint (8/10) 
                with an unvalidated search parameter. The response shows the input is reflected in the HTML 
                without encoding, which is perfect for XSS testing. I also notice there's no Content-Security-Policy 
                header, making exploitation easier.
                
                Let's start with a proven XSS payload from the library. Try payload #3: <img src=x onerror=alert(1)>
                This payload works well in HTML context because it doesn't rely on script tags, which are often 
                filtered. The onerror event fires immediately when the browser tries to load the invalid image.
                
                In Burp Repeater, replace 'test' with this payload in the q parameter and send the request. 
                Look for the <img> tag in the response - if it appears unencoded, the XSS is confirmed. 
                Let me know what you see in the response!"
                """.formatted(userQuery, deepRequestAnalysis, deepResponseAnalysis,
                             reflectionAnalysis,
                             wafInfo, truncate(methodology, 2000), truncate(bypassKnowledge, 1500),
                             payloadLibraryContext);
        } else {
            // Follow-up - adapt based on user's reported results AND actual tested requests
            return """
                You are an expert penetration testing mentor in an ongoing conversation.
                
                === CONVERSATION HISTORY ===
                %s
                
                === TESTING HISTORY (Actual Tests Performed) ===
                %s
                
                === CURRENT REQUEST ANALYSIS ===
                %s
                
                === CURRENT RESPONSE ANALYSIS ===
                %s
                
                === WAF DETECTION ===
                %s
                
                === BYPASS KNOWLEDGE ===
                %s
                
                === PAYLOAD LIBRARY ===
                %s
                
                INSTRUCTIONS:
                Provide a SINGLE, COHESIVE response that naturally continues the conversation.
                
                Your response should flow naturally and include:
                1. Acknowledge what they tested and the results (2-3 sentences)
                2. Analyze what the results mean (success, failure, or partial success)
                3. Provide the NEXT logical test based on what you learned
                4. Use a payload from the library when available
                5. Explain why this next test makes sense given previous results
                6. Give clear instructions
                7. Ask them to test and report back
                
                CRITICAL RULES:
                - Write in a natural, conversational tone (not bullet points or sections)
                - Reference previous tests naturally ("Since the basic payload was filtered...")
                - Learn from what worked/failed and adapt accordingly
                - Prioritize library payloads with high success rates
                - If they're stuck, suggest a different approach from the library
                - If they succeeded, congratulate and suggest verification
                - Integrate all context seamlessly into your narrative
                
                DO NOT use section headers like "✅ ANALYSIS" or "📍 NEXT STEP".
                Instead, write a flowing narrative that builds on the conversation naturally.
                
                Example of good response:
                "I see the basic <script>alert(1)</script> payload was blocked - the response shows it was 
                HTML-encoded. This tells us there's input sanitization happening. However, looking at the 
                testing history, I notice the response still reflects our input, just encoded.
                
                Let's try a different approach using an event handler. From the payload library, try payload #7: 
                <img src=x onerror=alert(1)>. This has a 78%% success rate and works well when script tags are 
                filtered because it uses the onerror event instead. The key is that many filters focus on 
                <script> tags but miss event handlers.
                
                Test this in Repeater and check if the <img> tag appears in the response. If it does, we've 
                bypassed the filter. What do you see?"
                
                Adapt your suggestions intelligently based on the complete testing history and analysis.
                """.formatted(conversationContext.toString(), testingHistory.toString(),
                             deepRequestAnalysis, deepResponseAnalysis,
                             wafInfo, truncate(bypassKnowledge, 1500),
                             payloadLibraryContext);
        }
    }

    private String callAI(String prompt) throws Exception {
        AIConfigManager config = AIConfigManager.getInstance();
        
        if ("Azure AI".equalsIgnoreCase(config.getProvider())) {
            AzureAIService.Configuration c = new AzureAIService.Configuration();
            c.setEndpoint(config.getEndpoint());
            c.setDeploymentName(config.getDeployment());
            c.setApiKey(config.getAzureApiKey());
            c.setTemperature(config.getTemperature());
            return new AzureAIService(c).ask(
                "You are an expert penetration testing consultant.", prompt);
        } else if ("OpenRouter".equalsIgnoreCase(config.getProvider())) {
            com.vista.security.service.OpenRouterService.Configuration c = 
                new com.vista.security.service.OpenRouterService.Configuration();
            c.setApiKey(config.getOpenRouterApiKey());
            c.setModel(config.getOpenRouterModel());
            c.setTemperature(config.getTemperature());
            return new com.vista.security.service.OpenRouterService(c).ask(
                "You are an expert penetration testing consultant.", prompt);
        } else {
            OpenAIService.Configuration c = new OpenAIService.Configuration();
            c.setApiKey(config.getOpenAIApiKey());
            c.setModel(config.getModel());
            c.setTemperature(config.getTemperature());
            return new OpenAIService(c).ask(
                "You are an expert penetration testing consultant.", prompt);
        }
    }
    
    private VariableContext buildVariableContext(String userQuery, String requestText, String responseText) {
        // Gather all required data
        ReflectionAnalyzer.ReflectionAnalysis reflectionAnalysis = null;
        RequestAnalysis reqAnalysis = null;
        ResponseAnalysis respAnalysis = null;
        
        if (currentRequest != null) {
            reflectionAnalysis = reflectionAnalyzer.analyze(currentRequest);
            reqAnalysis = deepRequestAnalyzer.analyze(currentRequest);
            
            if (currentRequest.getResponse() != null) {
                respAnalysis = responseAnalyzer.analyze(currentRequest);
            }
        }
        
        // WAF detection
        List<WAFDetector.WAFInfo> wafList = WAFDetector.detectWAF(responseText, responseText, extractStatusCode(responseText));
        
        // Create context with all required parameters
        VariableContext context = new VariableContext(
            helpers,
            currentRequest,
            reqAnalysis,
            respAnalysis,
            reflectionAnalysis,
            wafList,
            testingSteps,
            conversationHistory
        );
        
        return context;
    }

    private int extractStatusCode(String response) {
        try {
            String[] parts = response.split("\r?\n")[0].split(" ");
            return parts.length >= 2 ? Integer.parseInt(parts[1]) : 0;
        } catch (Exception e) { return 0; }
    }

    private void clearConversation() {
        conversationHistory.clear();
        testingSteps.clear();
        attachedRequests.clear();
        suggestionsArea.setText("");
        currentTestingPlan = null;
        currentStep = 0;
        statusLabel.setText("Ready");
        
        updateMultiRequestLabel();
        
        if (interactiveChatPanel != null) {
            interactiveChatPanel.setVisible(false);
        }
        
        appendSuggestion("SYSTEM", "Conversation cleared. Start a new interactive testing session!");
    }
    
    /**
     * Start a new session - clears conversation but keeps current request.
     */
    private void startNewSession() {
        // Save current session before clearing
        if (!conversationHistory.isEmpty()) {
            SessionManager.getInstance().saveConversationHistory(conversationHistory);
        }
        
        // Clear conversation
        conversationHistory.clear();
        testingSteps.clear();
        attachedRequests.clear();
        suggestionsArea.setText("");
        currentTestingPlan = null;
        currentStep = 0;
        
        updateMultiRequestLabel();
        
        if (interactiveChatPanel != null) {
            interactiveChatPanel.setVisible(false);
        }
        
        // Show new session message
        String requestSummary = "current request";
        if (currentRequest != null) {
            String reqText = HttpMessageParser.requestToText(helpers, currentRequest.getRequest());
            requestSummary = extractRequestSummary(reqText);
        }
        
        statusLabel.setText("New Session Started");
        appendSuggestion("SYSTEM", "🆕 NEW SESSION STARTED\n\n" +
            "Previous conversation saved and cleared.\n" +
            "Current request: " + requestSummary + "\n\n" +
            "This is a fresh session. Ask me how to test for vulnerabilities!");
        
        callbacks.printOutput("[VISTA] New session started manually by user");
    }

    private void appendSuggestion(String sender, String message) {
        SwingUtilities.invokeLater(() -> {
            String prefix = switch (sender) {
                case "YOU" -> "👤 You: ";
                case "VISTA" -> "🤖 VISTA: ";
                case "SYSTEM" -> "ℹ️ ";
                default -> sender + ": ";
            };
            suggestionsArea.append(prefix + message + "\n\n");
            suggestionsArea.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            suggestionsArea.setCaretPosition(suggestionsArea.getDocument().getLength());
        });
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private void installPlaceholder(JTextField field, String placeholder) {
        Color hintColor = new Color(150, 150, 155);
        Color normalColor = Color.BLACK;

        field.setForeground(hintColor);
        field.setText(placeholder);

        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (field.getForeground().equals(hintColor)) {
                    field.setText("");
                    field.setForeground(normalColor);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (field.getText().isBlank()) {
                    field.setForeground(hintColor);
                    field.setText(placeholder);
                }
            }
        });

        field.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) getSuggestions();
            }
        });
    }
    
    /**
     * Shows the testing history in a dialog
     */
    private void showTestingHistory() {
        if (testingSteps.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "No testing history yet.\n\nAttach requests from Repeater and send them to build history.",
                "Testing History",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        StringBuilder history = new StringBuilder();
        history.append("TESTING HISTORY\n");
        history.append("=".repeat(80)).append("\n\n");
        
        for (int i = 0; i < testingSteps.size(); i++) {
            TestingStep step = testingSteps.get(i);
            history.append("TEST #").append(i + 1).append("\n");
            history.append("-".repeat(80)).append("\n");
            history.append("Observation: ").append(step.observation).append("\n\n");
            history.append("Request:\n");
            history.append(step.request.substring(0, Math.min(500, step.request.length())));
            if (step.request.length() > 500) {
                history.append("\n... (truncated)");
            }
            history.append("\n\n");
            
            if (step.response != null && !step.response.isEmpty()) {
                history.append("Response:\n");
                history.append(step.response.substring(0, Math.min(500, step.response.length())));
                if (step.response.length() > 500) {
                    history.append("\n... (truncated)");
                }
                history.append("\n\n");
            }
            history.append("\n");
        }
        
        JTextArea textArea = new JTextArea(history.toString(), 30, 80);
        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        textArea.setCaretPosition(0);
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        
        JOptionPane.showMessageDialog(this,
            scrollPane,
            "Testing History (" + testingSteps.size() + " tests)",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Updates the Repeater request dropdown with recent requests
     */
    private void updateRepeaterDropdown(JComboBox<String> dropdown) {
        dropdown.removeAllItems();
        dropdown.addItem("-- Select recent Repeater request --");
        
        List<com.vista.security.core.RepeaterRequestTracker.RepeaterRequest> requests = 
            com.vista.security.core.RepeaterRequestTracker.getInstance().getRecentRequests();
        
        for (com.vista.security.core.RepeaterRequestTracker.RepeaterRequest req : requests) {
            dropdown.addItem(req.getDisplayString());
        }
        
        if (requests.isEmpty()) {
            dropdown.addItem("(No Repeater requests yet - use context menu in Repeater)");
        }
    }
    
    /**
     * Attaches a request from Repeater history by index
     */
    private void attachFromRepeaterHistory(int index) {
        com.vista.security.core.RepeaterRequestTracker.RepeaterRequest req = 
            com.vista.security.core.RepeaterRequestTracker.getInstance().getRequest(index);
        
        if (req != null) {
            attachedRequests.add(req.getRequestResponse());
            updateMultiRequestLabel();
            appendSuggestion("SYSTEM", "✓ Request attached from history: " + req.getMethod() + " " + 
                truncate(req.getUrl(), 60) + " [" + req.getStatusCode() + "]");
        }
    }
    
    /**
     * Public method to attach a request from Repeater (called from context menu)
     */
    public void attachRepeaterRequest(IHttpRequestResponse requestResponse) {
        callbacks.printOutput("[VISTA] attachRepeaterRequest called");
        
        // Check if this request is already attached (avoid duplicates)
        if (isRequestAlreadyAttached(requestResponse)) {
            callbacks.printOutput("[VISTA] Request already attached, skipping duplicate");
            statusLabel.setText("⚠️ This request is already attached");
            return;
        }
        
        // Make sure interactive chat panel is visible
        if (interactiveChatPanel != null) {
            interactiveChatPanel.setVisible(true);
            callbacks.printOutput("[VISTA] Interactive chat panel set to visible");
        }
        
        // Add the request to the list
        attachedRequests.add(requestResponse);
        callbacks.printOutput("[VISTA] Request added to list. Total: " + attachedRequests.size());
        
        // Update multi-request label
        updateMultiRequestLabel();
        
        // Update dropdown
        if (repeaterRequestDropdown != null) {
            updateRepeaterDropdown(repeaterRequestDropdown);
            callbacks.printOutput("[VISTA] Dropdown updated");
        }
        
        // Show success message
        statusLabel.setText("✓ Request attached from Repeater - Type your observation and click Send");
        
        // Add a helpful message to the conversation if it's empty
        if (conversationHistory.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                suggestionsArea.append("📎 Request attached from Repeater!\n\n");
                suggestionsArea.append("💡 Quick Start:\n");
                suggestionsArea.append("1. Type what you observed (e.g., 'I see HTML encoding' or 'WAF blocked my payload')\n");
                suggestionsArea.append("2. Click Send\n");
                suggestionsArea.append("3. AI will analyze and provide bypass suggestions\n\n");
                suggestionsArea.append("Or ask a question like:\n");
                suggestionsArea.append("• 'How can I bypass this WAF?'\n");
                suggestionsArea.append("• 'Test for XSS'\n");
                suggestionsArea.append("• 'Suggest SQLi bypass payloads'\n\n");
                suggestionsArea.append("💡 TIP: You can attach multiple requests for comparison!\n\n");
                suggestionsArea.append("─".repeat(60) + "\n\n");
                suggestionsArea.setCaretPosition(suggestionsArea.getDocument().getLength());
                callbacks.printOutput("[VISTA] Help message added to conversation");
            });
        }
        
        // Focus on the chat input field
        if (interactiveChatField != null) {
            SwingUtilities.invokeLater(() -> {
                interactiveChatField.requestFocusInWindow();
                callbacks.printOutput("[VISTA] Focus set to chat input field");
            });
        }
        
        callbacks.printOutput("[VISTA] attachRepeaterRequest completed successfully");
    }

    /**
     * Check if a request is already attached (to avoid duplicates).
     */
    private boolean isRequestAlreadyAttached(IHttpRequestResponse newRequest) {
        if (newRequest == null || newRequest.getRequest() == null) return false;
        
        String newFirstLine = extractFirstLine(newRequest.getRequest());
        
        for (IHttpRequestResponse attached : attachedRequests) {
            if (attached != null && attached.getRequest() != null) {
                String attachedFirstLine = extractFirstLine(attached.getRequest());
                if (newFirstLine.equals(attachedFirstLine)) {
                    return true; // Duplicate found
                }
            }
        }
        
        return false; // Not a duplicate
    }
    
    // Data classes
    public static class ConversationMessage {
        public final String role;
        public final String content;

        public ConversationMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }
    
    public static class TestingStep {
        public final String stepName;
        public final String request;
        public final String response;
        public final String observation;
        
        public TestingStep(String stepName, String request, String response, String observation) {
            this.stepName = stepName;
            this.request = request;
            this.response = response;
            this.observation = observation;
        }
    }
}
