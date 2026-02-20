package com.vista.security.ui;

import burp.*;
import com.vista.security.core.*;
import com.vista.security.model.ChatMessage;
import com.vista.security.model.ChatSession;
import com.vista.security.model.PromptTemplate;
import com.vista.security.service.AzureAIService;
import com.vista.security.service.OpenAIService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.vista.security.ui.VistaTheme.*;

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
    private final ChatSessionManager chatSessionManager;

    // Request/Response display — professional Burp-style viewer
    private HttpMessageViewer httpMessageViewer;
    
    // Multi-request support
    private final java.util.List<IHttpRequestResponse> attachedRequests = new ArrayList<>();
    private JLabel multiRequestLabel;
    private JButton manageRequestsButton;
    
    // Template selector
    private JComboBox<String> templateSelector;

    // Suggestions area (main output) — rich styled conversation
    private ChatConversationPane conversationPane;

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
    private final List<ConversationMessage> conversationHistory = Collections.synchronizedList(new ArrayList<>());
    // NOTE: testingSteps is now stored per-session in ChatSession, not globally
    private String currentTestingPlan = null; // For interactive mode
    private int currentStep = 0; // Track current step in interactive mode
    
    // Thread pool for AI tasks - prevents unbounded thread creation
    private final ExecutorService aiExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "VISTA-AI-Advisor");
        t.setDaemon(true);
        return t;
    });
    private volatile Future<?> currentAITask; // Track current AI task for cancellation

    public TestingSuggestionsPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.reflectionAnalyzer = new ReflectionAnalyzer(helpers);
        this.deepRequestAnalyzer = new DeepRequestAnalyzer(helpers);
        this.responseAnalyzer = new ResponseAnalyzer(helpers);
        this.templateManager = PromptTemplateManager.getInstance();
        this.payloadLibraryAI = new PayloadLibraryAIIntegration();
        this.chatSessionManager = ChatSessionManager.getInstance();

        // Auto-install built-in payload libraries so AI has payload data from the start
        Thread payloadInit = new Thread(() -> {
            try { BuiltInPayloads.installBuiltInLibraries(); } catch (Exception ignored) {}
        }, "VISTA-PayloadInit");
        payloadInit.setDaemon(true);
        payloadInit.start();

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
        // Compact single-row white toolbar — maximizes space for AI conversation
        JPanel panel = new JPanel(new BorderLayout(0, 0));
        panel.setBackground(VistaTheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, VistaTheme.BORDER),
            new EmptyBorder(5, 12, 5, 12)
        ));

        // Left: Brand title + config status
        JPanel leftSection = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftSection.setOpaque(false);
        
        JLabel titleLabel = new JLabel("🛡 AI Security Advisor");
        titleLabel.setFont(VistaTheme.FONT_HEADING);
        titleLabel.setForeground(VistaTheme.TEXT_PRIMARY);
        leftSection.add(titleLabel);
        
        JLabel sep1 = new JLabel("│");
        sep1.setForeground(VistaTheme.TEXT_MUTED);
        sep1.setFont(VistaTheme.FONT_SMALL);
        leftSection.add(sep1);
        
        configStatusLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        leftSection.add(configStatusLabel);
        
        // Center: Template selector + quick query pills
        JPanel centerSection = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 0));
        centerSection.setOpaque(false);
        
        JLabel templateLabel = new JLabel("Template");
        templateLabel.setFont(VistaTheme.FONT_SMALL);
        templateLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        centerSection.add(templateLabel);
        
        templateSelector = new JComboBox<>();
        VistaTheme.styleComboBox(templateSelector);
        templateSelector.setFont(VistaTheme.FONT_SMALL);
        templateSelector.setPreferredSize(new Dimension(150, 24));
        templateSelector.addItem("Default");
        for (PromptTemplate template : templateManager.getActiveTemplates()) {
            templateSelector.addItem(template.getName());
        }
        centerSection.add(templateSelector);
        
        JLabel sep2 = new JLabel("│");
        sep2.setForeground(VistaTheme.TEXT_MUTED);
        sep2.setFont(VistaTheme.FONT_SMALL);
        centerSection.add(sep2);
        
        // Quick query pills
        String[] quickQueries = {"XSS", "SQLi", "SSTI", "CMDi", "SSRF", "WAF"};
        String[] quickLabels = {"XSS Testing", "SQLi Testing", "SSTI Testing", "Command Injection", "SSRF Testing", "Bypass WAF"};
        for (int i = 0; i < quickQueries.length; i++) {
            JButton btn = createQuickButton(quickQueries[i], quickLabels[i]);
            centerSection.add(btn);
        }

        // Right: Action buttons
        JPanel rightSection = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        rightSection.setOpaque(false);
        
        JButton newSessionBtn = VistaTheme.compactButton("+ New Chat");
        newSessionBtn.setToolTipText("Start fresh conversation (keeps current request)");
        newSessionBtn.addActionListener(e -> startNewSession());
        
        JButton clearBtn = VistaTheme.compactButton("Clear");
        clearBtn.setToolTipText("Clear current conversation");
        clearBtn.addActionListener(e -> clearConversation());
        
        rightSection.add(newSessionBtn);
        rightSection.add(clearBtn);

        panel.add(leftSection, BorderLayout.WEST);
        panel.add(centerSection, BorderLayout.CENTER);
        panel.add(rightSection, BorderLayout.EAST);

        return panel;
    }
    
    private JButton createQuickButton(String shortLabel, String fullQuery) {
        JButton btn = VistaTheme.pillButton(shortLabel);
        btn.setToolTipText("Quick: How to test for " + fullQuery + "?");
        btn.addActionListener(e -> {
            String message = "How to test for " + fullQuery + "?";
            if (interactiveChatField != null) {
                interactiveChatField.setText(message);
            }
            sendQueryMessage(message);
        });
        return btn;
    }

    private JSplitPane buildMainContent() {
        // Left: Professional Request/Response viewer with Burp-style color coding
        httpMessageViewer = new HttpMessageViewer();

        // Right: Conversation area — maximized
        JPanel rightPanel = new JPanel(new BorderLayout(0, 0));
        rightPanel.setBackground(VistaTheme.BG_CARD);
        
        conversationPane = new ChatConversationPane();
        
        // Loading indicator (overlays bottom of conversation)
        loadingLabel = new JLabel();
        loadingLabel.setFont(VistaTheme.FONT_HEADING);
        loadingLabel.setForeground(VistaTheme.PRIMARY);
        loadingLabel.setHorizontalAlignment(SwingConstants.CENTER);
        loadingLabel.setBorder(new EmptyBorder(6, 12, 6, 12));
        loadingLabel.setVisible(false);
        
        JPanel conversationArea = new JPanel(new BorderLayout(0, 0));
        conversationArea.setBackground(VistaTheme.BG_CARD);
        conversationArea.setBorder(new EmptyBorder(0, 0, 0, 0));
        conversationArea.add(conversationPane, BorderLayout.CENTER);
        conversationArea.add(loadingLabel, BorderLayout.SOUTH);

        rightPanel.add(conversationArea, BorderLayout.CENTER);
        
        // Chat input panel — always visible at bottom
        interactiveChatPanel = buildInteractiveChatPanel();
        interactiveChatPanel.setVisible(true);
        rightPanel.add(interactiveChatPanel, BorderLayout.SOUTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, httpMessageViewer, rightPanel);
        mainSplit.setResizeWeight(0.35);
        mainSplit.setDividerSize(5);
        mainSplit.setBorder(null);

        return mainSplit;
    }
    
    private JPanel buildInteractiveChatPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBackground(VistaTheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, VistaTheme.BORDER),
            new EmptyBorder(8, 12, 8, 12)
        ));
        
        // Compact status row: multi-request info + quick attach
        JPanel statusRow = new JPanel(new BorderLayout(6, 0));
        statusRow.setOpaque(false);
        statusRow.setBorder(new EmptyBorder(0, 2, 2, 0));
        
        multiRequestLabel = new JLabel("No requests attached");
        multiRequestLabel.setFont(VistaTheme.FONT_SMALL);
        multiRequestLabel.setForeground(VistaTheme.TEXT_MUTED);
        
        JPanel attachPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        attachPanel.setOpaque(false);
        
        manageRequestsButton = VistaTheme.compactButton("📎 Attach");
        manageRequestsButton.setToolTipText("View, add, or remove attached requests");
        manageRequestsButton.addActionListener(e -> showMultiRequestManager());
        manageRequestsButton.setFont(VistaTheme.FONT_SMALL);
        
        // Dropdown for recent Repeater requests
        JComboBox<String> repeaterDropdown = new JComboBox<>();
        VistaTheme.styleComboBox(repeaterDropdown);
        repeaterDropdown.setFont(VistaTheme.FONT_SMALL);
        repeaterDropdown.setPreferredSize(new Dimension(190, 22));
        repeaterDropdown.addItem("Quick attach from Repeater...");
        repeaterDropdown.addActionListener(e -> {
            int selectedIndex = repeaterDropdown.getSelectedIndex();
            if (selectedIndex > 0) {
                attachFromRepeaterHistory(selectedIndex - 1);
                repeaterDropdown.setSelectedIndex(0);
            }
        });
        
        JButton refreshBtn = VistaTheme.compactButton("↻");
        refreshBtn.setFont(VistaTheme.FONT_SMALL);
        refreshBtn.setToolTipText("Refresh Repeater request list");
        refreshBtn.addActionListener(e -> updateRepeaterDropdown(repeaterDropdown));
        
        attachPanel.add(repeaterDropdown);
        attachPanel.add(refreshBtn);
        attachPanel.add(manageRequestsButton);
        
        statusRow.add(multiRequestLabel, BorderLayout.WEST);
        statusRow.add(attachPanel, BorderLayout.EAST);
        
        // Input row
        JPanel inputRow = new JPanel(new BorderLayout(6, 0));
        inputRow.setOpaque(false);
        
        interactiveChatField = new JTextField();
        interactiveChatField.setFont(VistaTheme.FONT_BODY);
        VistaTheme.styleTextField(interactiveChatField);
        installPlaceholder(interactiveChatField, "Ask anything — test for XSS, bypass WAF, analyze responses...");
        
        JButton sendBtn = VistaTheme.primaryButton("Send ⏎");
        sendBtn.addActionListener(e -> sendInteractiveMessage());
        
        inputRow.add(interactiveChatField, BorderLayout.CENTER);
        inputRow.add(sendBtn, BorderLayout.EAST);
        
        panel.add(statusRow, BorderLayout.NORTH);
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
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession == null) {
            JOptionPane.showMessageDialog(this,
                "No active session.\n\nPlease send a request from Burp Repeater first.",
                "No Active Session",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        List<IHttpRequestResponse> sessionAttachedRequests = new ArrayList<>(activeSession.getAttachedRequests());
        
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Manage Attached Requests (Active Session)", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(800, 600);
        
        // List of attached requests
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (int i = 0; i < sessionAttachedRequests.size(); i++) {
            IHttpRequestResponse req = sessionAttachedRequests.get(i);
            String summary = getRequestSummary(req, i + 1);
            listModel.addElement(summary);
        }
        
        JList<String> requestList = new JList<>(listModel);
        requestList.setFont(new Font("Monospaced", Font.PLAIN, 11));
        requestList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION); // Allow multi-select
        
        JScrollPane listScroll = new JScrollPane(requestList);
        listScroll.setBorder(BorderFactory.createTitledBorder("Attached Requests (" + sessionAttachedRequests.size() + ")"));
        
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
                if (selectedIndex >= 0 && selectedIndex < sessionAttachedRequests.size()) {
                    IHttpRequestResponse req = sessionAttachedRequests.get(selectedIndex);
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
                List<IHttpRequestResponse> toRemove = new ArrayList<>();
                for (int i = selectedIndices.length - 1; i >= 0; i--) {
                    toRemove.add(sessionAttachedRequests.get(selectedIndices[i]));
                }
                // Remove from session
                for (IHttpRequestResponse req : toRemove) {
                    sessionAttachedRequests.remove(req);
                }
                // Update session
                activeSession.clearAttachedRequests();
                for (IHttpRequestResponse req : sessionAttachedRequests) {
                    activeSession.addAttachedRequest(req);
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
                "Remove all " + sessionAttachedRequests.size() + " attached requests?",
                "Confirm Clear All", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                activeSession.clearAttachedRequests();
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
        ChatSession activeSession = chatSessionManager.getActiveSession();
        int count = activeSession != null ? activeSession.getAttachedRequestCount() : 0;
        
        if (count == 0) {
            multiRequestLabel.setText("No requests attached");
            multiRequestLabel.setForeground(VistaTheme.TEXT_MUTED);
            multiRequestLabel.setFont(VistaTheme.FONT_SMALL);
        } else if (count == 1) {
            multiRequestLabel.setText("● 1 request attached");
            multiRequestLabel.setForeground(VistaTheme.STATUS_SUCCESS);
            multiRequestLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        } else {
            multiRequestLabel.setText("● " + count + " requests attached");
            multiRequestLabel.setForeground(VistaTheme.STATUS_SUCCESS);
            multiRequestLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        }
        
        if (manageRequestsButton != null) {
            manageRequestsButton.setText("📎 Attach (" + count + ")");
        }
        
        // Update chat field background
        if (interactiveChatField != null) {
            if (count > 0) {
                interactiveChatField.setBackground(new Color(240, 253, 244)); // Green-50
            } else {
                interactiveChatField.setBackground(VistaTheme.BG_INPUT);
            }
        }
    }
    
    private void attachTestRequest() {
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession == null) {
            JOptionPane.showMessageDialog(this,
                "No active session.\n\nPlease send a request from Burp Repeater first.",
                "No Active Session",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
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
                // Create a mock IHttpRequestResponse and add to active session
                IHttpRequestResponse newRequest = new IHttpRequestResponse() {
                    private byte[] request = reqText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    private byte[] response = respText.isEmpty() ? null : respText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    
                    @Override public byte[] getRequest() { return request; }
                    @Override public byte[] getResponse() { return response; }
                    @Override public burp.IHttpService getHttpService() { return null; }
                };
                
                activeSession.addAttachedRequest(newRequest);
                updateMultiRequestLabel();
                
                appendSuggestion("SYSTEM", "✓ Request attached (" + reqText.length() + " bytes). Total: " + activeSession.getAttachedRequestCount());
            }
        }
    }
    
    private void sendInteractiveMessage() {
        String message = interactiveChatField.getText().trim();
        // Check for empty message or placeholder text
        if (message.isEmpty() || message.startsWith("Ask anything") || message.startsWith("Report what")) return;
        
        interactiveChatField.setText("");
        
        // Get active session
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession == null) {
            appendSuggestion("SYSTEM", "⚠️ No active session. Please send a request from Burp Repeater first.");
            return;
        }
        
        callbacks.printOutput("[VISTA] sendInteractiveMessage called with: " + message);
        callbacks.printOutput("[VISTA] Active session: " + activeSession.getSessionId());
        
        // Get attached requests from ACTIVE SESSION ONLY
        List<IHttpRequestResponse> sessionAttachedRequests = new ArrayList<>(activeSession.getAttachedRequests());
        callbacks.printOutput("[VISTA] Attached requests count for active session: " + sessionAttachedRequests.size());
        
        // Add user message to conversation
        appendSuggestion("YOU", message);
        conversationHistory.add(new ConversationMessage("user", message));
        
        // If requests attached, add them to context AND store in testingSteps
        if (!sessionAttachedRequests.isEmpty()) {
            callbacks.printOutput("[VISTA] Processing " + sessionAttachedRequests.size() + " attached request(s)...");
            
            for (int i = 0; i < sessionAttachedRequests.size(); i++) {
                IHttpRequestResponse req = sessionAttachedRequests.get(i);
                String reqText = new String(req.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                String respText = req.getResponse() != null ? 
                    new String(req.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";
                
                callbacks.printOutput("[VISTA] Request #" + (i+1) + " length: " + reqText.length());
                callbacks.printOutput("[VISTA] Response #" + (i+1) + " length: " + respText.length());
                
                // Store this test step in ACTIVE SESSION (IMPORTANT: Don't clear these until message is sent!)
                activeSession.addTestingStep(new ChatSession.TestingStep(
                    "Step " + (activeSession.getTestingStepCount() + 1) + (sessionAttachedRequests.size() > 1 ? " (Request " + (i+1) + ")" : ""),
                    reqText,
                    respText,
                    message
                ));
            }
            
            callbacks.printOutput("[VISTA] Added to session testingSteps. Total steps: " + activeSession.getTestingStepCount());
            
            // Show clear feedback
            if (sessionAttachedRequests.size() == 1) {
                String reqText = new String(sessionAttachedRequests.get(0).getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                String respText = sessionAttachedRequests.get(0).getResponse() != null ? 
                    new String(sessionAttachedRequests.get(0).getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";
                appendSuggestion("SYSTEM", "📎 Request/Response attached and sent to AI for analysis");
                appendSuggestion("SYSTEM", "   Request: " + truncate(reqText.split("\n")[0], 80));
                appendSuggestion("SYSTEM", "   Response: " + (respText.isEmpty() ? "(empty)" : respText.length() + " bytes"));
            } else {
                appendSuggestion("SYSTEM", "📎 " + sessionAttachedRequests.size() + " requests/responses sent to AI for analysis");
                for (int i = 0; i < sessionAttachedRequests.size(); i++) {
                    String reqText = new String(sessionAttachedRequests.get(i).getRequest(), java.nio.charset.StandardCharsets.UTF_8);
                    appendSuggestion("SYSTEM", "   #" + (i+1) + ": " + truncate(reqText.split("\n")[0], 70));
                }
            }
            
            // Clear attachments from ACTIVE SESSION ONLY (after storing in testingSteps)
            activeSession.clearAttachedRequests();
            updateMultiRequestLabel();
            
            callbacks.printOutput("[VISTA] Attachments cleared from active session");
        } else {
            callbacks.printOutput("[VISTA] No requests attached - sending message only");
        }
        
        // Process with AI (testingSteps will be used in handleInteractiveAssistant)
        statusLabel.setText("Processing your observation...");
        callbacks.printOutput("[VISTA] Starting AI processing task");
        // Cancel any previous pending AI task to prevent queue buildup
        if (currentAITask != null && !currentAITask.isDone()) {
            currentAITask.cancel(true);
        }
        currentAITask = aiExecutor.submit(() -> handleInteractiveAssistant(message));
    }



    private JPanel buildFooterPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 0));
        panel.setBackground(VistaTheme.BG_PANEL);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, VistaTheme.BORDER),
            new EmptyBorder(3, 12, 3, 12)
        ));

        statusLabel.setFont(VistaTheme.FONT_SMALL);
        statusLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        panel.add(statusLabel, BorderLayout.WEST);

        return panel;
    }

    private void updateConfigStatus() {
        AIConfigManager config = AIConfigManager.getInstance();
        if (config.isConfigured()) {
            configStatusLabel.setText("● " + config.getProvider() + " connected");
            configStatusLabel.setForeground(VistaTheme.STATUS_SUCCESS);
        } else {
            configStatusLabel.setText("● Configure AI in Settings");
            configStatusLabel.setForeground(VistaTheme.STATUS_WARNING);
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
            httpMessageViewer.setHttpMessage(request.getRequest(), request.getResponse());

            String reqText = HttpMessageParser.requestToText(helpers, request.getRequest());
            String summary = extractRequestSummary(reqText);
            
            // If this is a NEW request, create a NEW CHAT SESSION (don't clear old one!)
            if (isNewRequest) {
                // Use generic system prompt for session init (templates are processed on first message)
                String systemPrompt = "You are an expert penetration testing mentor in a Burp Suite extension called VISTA. " +
                    "You help security testers find and exploit vulnerabilities in web applications. " +
                    "Users can attach HTTP requests/responses for analysis. " +
                    "Provide specific, actionable testing guidance with real payloads.";
                String requestUrl = extractRequestUrl(reqText);
                
                // IMPORTANT: Get the previous session BEFORE creating a new one
                // (createSession() will change the active session)
                ChatSession previousSession = chatSessionManager.getActiveSession();
                
                // Close previous session so cleanupInactiveSessions() can reclaim it
                if (previousSession != null) {
                    chatSessionManager.closeSession(previousSession.getSessionId());
                }
                
                // Save old conversation to the previous session if it exists
                if (previousSession != null && !conversationHistory.isEmpty()) {
                    // Transfer old conversation history to previous session
                    for (ConversationMessage msg : conversationHistory) {
                        if ("USER".equals(msg.role) || "user".equals(msg.role)) {
                            previousSession.addUserMessage(msg.content, null);
                        } else if ("AI".equals(msg.role) || "assistant".equals(msg.role)) {
                            previousSession.addAssistantMessage(msg.content);
                        }
                    }
                }
                
                // Create new chat session (old sessions are preserved in ChatSessionManager)
                ChatSession newSession = chatSessionManager.createSession(requestUrl, systemPrompt);
                
                // Store the request/response in the session
                newSession.setRequestResponse(request);
                
                // Clear UI conversation for new session (but old session is saved in manager!)
                conversationHistory.clear();
                
                // Clear session-specific data from new session
                newSession.clearTestingSteps();
                newSession.clearAttachedRequests();
                
                attachedRequests.clear();
                conversationPane.clear();
                currentTestingPlan = null;
                currentStep = 0;
                
                // Set new session as active
                chatSessionManager.setActiveSession(newSession.getSessionId());
                
                statusLabel.setText("New Session: " + summary);
                
                appendSuggestion("SYSTEM", "🆕 NEW REQUEST LOADED\n\n" +
                    "Request: " + summary + "\n" +
                    "Session ID: " + newSession.getSessionId().substring(0, 12) + "...\n\n" +
                    "Previous conversation cleared. Starting fresh!\n\n" +
                    "Ask me how to test for vulnerabilities!");
                
                callbacks.printOutput("[VISTA] New chat session created: " + newSession.getSessionId());
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
        // Unified path: get text from the interactive chat field
        String userQuery = interactiveChatField != null ? interactiveChatField.getText().trim() : "";
        if (userQuery.isEmpty() || userQuery.startsWith("Ask")) return;
        sendQueryMessage(userQuery);
    }
    
    /**
     * Unified method to send a query message — used by quick buttons, getSuggestions, etc.
     */
    private void sendQueryMessage(String userQuery) {
        if (userQuery == null || userQuery.trim().isEmpty()) return;
        userQuery = userQuery.trim();
        
        if (currentRequest == null) {
            appendSuggestion("SYSTEM", "⚠️ No request loaded. Right-click a request in Burp and select 'Send to VISTA AI'.");
            return;
        }

        if (!AIConfigManager.getInstance().isConfigured()) {
            appendSuggestion("SYSTEM", "⚠️ AI not configured. Go to Settings tab to configure your AI provider.");
            return;
        }

        // Delegate to sendInteractiveMessage for unified attachment + session handling
        if (interactiveChatField != null) {
            interactiveChatField.setText(userQuery);
        }
        sendInteractiveMessage();
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
            // Check if this task was cancelled before starting expensive work
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            
            // Show loading indicator
            showLoadingIndicator(true);
            
            String requestText = new String(currentRequest.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
            String responseText = currentRequest.getResponse() != null ? 
                new String(currentRequest.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";

            // Get active chat session
            ChatSession activeSession = chatSessionManager.getActiveSession();
            
            // Build enhanced user message with attached requests if any
            String enhancedUserQuery = userQuery;
            boolean hasAttachedRequests = false;
            List<ChatSession.TestingStep> sessionTestingSteps = activeSession != null ? 
                activeSession.getTestingSteps() : new ArrayList<>();
            
            if (!sessionTestingSteps.isEmpty()) {
                hasAttachedRequests = true;
                // Get the most recent testing steps (attached requests)
                StringBuilder attachedContext = new StringBuilder();
                attachedContext.append(userQuery).append("\n\n");
                attachedContext.append("=== ATTACHED REQUEST/RESPONSE FOR ANALYSIS ===\n\n");
                
                // Include the most recent attached requests (last 3 max to avoid token overflow)
                int startIndex = Math.max(0, sessionTestingSteps.size() - 3);
                for (int i = startIndex; i < sessionTestingSteps.size(); i++) {
                    ChatSession.TestingStep step = sessionTestingSteps.get(i);
                    attachedContext.append("--- ").append(step.stepName).append(" ---\n");
                    attachedContext.append("User's Observation: ").append(step.observation).append("\n\n");
                    attachedContext.append("REQUEST:\n");
                    attachedContext.append(truncate(step.request, 2000)).append("\n\n");
                    if (step.response != null && !step.response.isEmpty()) {
                        attachedContext.append("RESPONSE:\n");
                        attachedContext.append(truncate(step.response, 1500)).append("\n\n");
                    }
                }
                
                enhancedUserQuery = attachedContext.toString();
                callbacks.printOutput("[VISTA] Enhanced user query with " + (sessionTestingSteps.size() - startIndex) + " attached requests");
                callbacks.printOutput("[VISTA] Enhanced query length: " + enhancedUserQuery.length());
            } else {
                callbacks.printOutput("[VISTA] No testingSteps found in session - using plain user query");
            }
            
            // Add user message to session
            if (activeSession != null) {
                String requestUrl = extractRequestUrl(requestText);
                activeSession.addUserMessage(enhancedUserQuery, requestUrl);
            }
            
            // Check if a template is selected
            String selectedTemplate = (String) templateSelector.getSelectedItem();
            String response;
            
            // Use chat session history if available
            if (activeSession != null && activeSession.getExchangeCount() > 0) {
                // Follow-up message — inject fresh security analysis context
                // The original system prompt is too generic for security testing.
                // We inject a rich context-aware system message before calling AI.
                String securityContext = buildFollowUpSecurityContext(requestText, responseText, 
                    sessionTestingSteps, hasAttachedRequests);
                activeSession.updateSystemPrompt(securityContext);
                
                response = callAIWithHistory(activeSession.getMessages());
                callbacks.printOutput("[VISTA] Using chat session history with refreshed security context");
            } else {
                // First message - build full prompt
                String systemPrompt;
                String userPrompt;
                String templateName = null;
                
                if (selectedTemplate != null && !selectedTemplate.startsWith("--")) {
                    // Use template
                    PromptTemplate template = templateManager.getTemplateByName(selectedTemplate);
                    if (template != null) {
                        // Build variable context
                        VariableContext context = buildVariableContext(userQuery, requestText, responseText);
                        context.setUserQuery(userQuery);
                        
                        // Process template with variables - get separate prompts
                        String[] prompts = templateManager.processTemplateWithSeparatePrompts(template, context);
                        systemPrompt = prompts[0];
                        userPrompt = prompts[1] + "\n\n=== USER'S SPECIFIC QUESTION ===\n" + enhancedUserQuery + 
                                     "\n\nIMPORTANT: Address the user's specific question above while following the template guidance.";
                        templateName = template.getName();
                        
                        callbacks.printOutput("[VISTA] Using template: " + templateName);
                    } else {
                        systemPrompt = "You are an expert penetration testing consultant.";
                        userPrompt = buildInteractivePrompt(userQuery, requestText, responseText);
                    }
                } else {
                    systemPrompt = "You are an expert penetration testing consultant.";
                    userPrompt = buildInteractivePrompt(userQuery, requestText, responseText);
                }
                
                response = callAIWithPrompts(systemPrompt, userPrompt, templateName, requestText, responseText);
            }
            
            // Add AI response to session
            if (activeSession != null) {
                activeSession.addAssistantMessage(response);
                callbacks.printOutput("[VISTA] Session " + activeSession.getSessionId() + 
                    " now has " + activeSession.getExchangeCount() + " exchanges");
            }
            
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
                e.printStackTrace();
            });
        }
    }
    
    /**
     * Build a rich security-focused system prompt for follow-up messages.
     * This ensures the AI has full security testing context on every exchange,
     * not just the first message. Includes deep analysis, WAF detection,
     * reflection analysis, payload library, and attached request awareness.
     */
    private String buildFollowUpSecurityContext(String requestText, String responseText,
                                                  List<ChatSession.TestingStep> testingSteps,
                                                  boolean hasNewAttachedRequests) {
        // Deep request analysis
        String deepRequestAnalysis = "Not available";
        String detectedVulnType = null;
        String reflectionContext = "unknown";
        
        if (currentRequest != null) {
            RequestAnalysis reqAnalysis = deepRequestAnalyzer.analyze(currentRequest);
            deepRequestAnalysis = truncate(reqAnalysis.toFormattedString(), 1500);
            if (!reqAnalysis.predictedVulnerabilities.isEmpty()) {
                detectedVulnType = reqAnalysis.predictedVulnerabilities.get(0);
            }
        }
        
        // Deep response analysis
        String deepResponseAnalysis = "Not available";
        if (currentRequest != null && currentRequest.getResponse() != null) {
            ResponseAnalysis respAnalysis = responseAnalyzer.analyze(currentRequest);
            deepResponseAnalysis = truncate(respAnalysis.toFormattedString(), 1200);
        }
        
        // Reflection analysis
        String reflectionAnalysis = "Not available";
        if (currentRequest != null) {
            ReflectionAnalyzer.ReflectionAnalysis analysis = reflectionAnalyzer.analyze(currentRequest);
            reflectionAnalysis = truncate(analysis.getSummary(), 1000);
            if (analysis.getReflections() != null && !analysis.getReflections().isEmpty()) {
                var firstReflection = analysis.getReflections().get(0);
                if (firstReflection != null) {
                    List<ReflectionAnalyzer.ReflectionContext> contexts = firstReflection.getContexts();
                    if (contexts != null && !contexts.isEmpty() && contexts.get(0) != null) {
                        reflectionContext = contexts.get(0).getContextType();
                    }
                }
            }
        }
        
        // Payload library context
        String payloadLibraryContext = "";
        if (detectedVulnType != null) {
            payloadLibraryContext = payloadLibraryAI.getPayloadContextForAI(
                detectedVulnType, reflectionContext, true, 5);
            String topPayloads = payloadLibraryAI.getTopPayloadsForAI(detectedVulnType, 3);
            if (!topPayloads.isEmpty()) payloadLibraryContext += topPayloads;
        }
        if (payloadLibraryContext.isEmpty()) {
            payloadLibraryContext = payloadLibraryAI.getRecentSuccessfulPayloadsForAI(3);
        }
        
        // WAF detection
        List<WAFDetector.WAFInfo> wafList = WAFDetector.detectWAF(responseText, responseText, extractStatusCode(responseText));
        String wafInfo = wafList.isEmpty() ? "No WAF detected" : WAFDetector.getBypassSuggestions(wafList);
        
        // Build testing history summary
        StringBuilder testingHistoryStr = new StringBuilder();
        if (!testingSteps.isEmpty()) {
            testingHistoryStr.append("\n\nTESTING HISTORY (User's previous tests in this session):\n");
            for (int i = 0; i < testingSteps.size(); i++) {
                ChatSession.TestingStep step = testingSteps.get(i);
                testingHistoryStr.append("- Test ").append(i + 1).append(": ");
                testingHistoryStr.append(step.observation);
                testingHistoryStr.append(" [Request: ").append(truncate(step.request.split("\r?\n")[0], 60)).append("]");
                if (step.response != null && !step.response.isEmpty()) {
                    testingHistoryStr.append(" [Response: ").append(step.response.length()).append(" bytes]");
                }
                testingHistoryStr.append("\n");
            }
        }
        
        // Get template context if a template is selected
        String templateContext = "";
        String selectedTemplate = (String) templateSelector.getSelectedItem();
        if (selectedTemplate != null && !selectedTemplate.startsWith("--") && !selectedTemplate.equals("Default")) {
            PromptTemplate template = templateManager.getTemplateByName(selectedTemplate);
            if (template != null) {
                templateContext = "\n\nACTIVE TEMPLATE: " + template.getName() + 
                    "\nTemplate Guidance: " + truncate(template.getSystemPrompt(), 2000);
            }
        }
        
        return """
            You are an expert penetration testing mentor in a Burp Suite extension called VISTA.
            You are in an ongoing conversation helping a security tester find and exploit vulnerabilities.
            
            CRITICAL CONTEXT:
            - The user can ATTACH HTTP request/response pairs to their messages
            - When the message contains "=== ATTACHED REQUEST/RESPONSE FOR ANALYSIS ===", that is REAL HTTP traffic
            - You have deep automated analysis of the target below
            - The REFLECTION ANALYSIS below tells you EXACTLY where and how input is reflected in the response
            
            === SESSION'S TARGET REQUEST ANALYSIS ===
            %s
            
            === SESSION'S TARGET RESPONSE ANALYSIS ===
            %s
            
            === REFLECTION ANALYSIS (MOST IMPORTANT — this is pre-computed for you) ===
            %s
            
            === WAF DETECTION ===
            %s
            
            === PAYLOAD LIBRARY (Proven Payloads for detected context) ===
            %s
            %s%s
            
            MANDATORY RESPONSE RULES:
            
            1. DEEP REFLECTION-BASED ANALYSIS (not generic):
               - You MUST use the REFLECTION ANALYSIS above to identify EXACT reflection points
               - For each reflected parameter, state: parameter name, WHERE it reflects (HTML body, JS string,
                 HTML attribute, HTTP header, JSON value, etc.), and WHETHER it is encoded/filtered
               - Example: "Parameter 'city' is reflected at line 42 inside a JavaScript string var x='REFLECTION'
                 without any encoding — this is directly exploitable for XSS"
            
            2. CONTEXT-SPECIFIC PAYLOADS ONLY (never list multiple contexts):
               - Based on the EXACT reflection context you identified, provide payloads ONLY for THAT context
               - If reflected in JS string → give JS string breakout payloads ONLY (e.g. ";alert(1);//)
               - If reflected in HTML body → give HTML injection payloads ONLY
               - If reflected in HTML attribute → give attribute breakout payloads ONLY
               - DO NOT list "Here's what to do for HTML context... here's for JS context..." — you KNOW the context!
               - Provide the EXACT modified request showing where to inject the payload
            
            3. ESCALATION PATH (if primary approach fails):
               - If the user reports a payload was blocked/filtered, analyze WHAT was filtered
               - Suggest bypass for THAT specific filter (encoding bypass, alternate syntax, etc.)
               - If the reflection context is not exploitable, suggest OTHER vulnerability types
                 that may apply to this specific endpoint (SSRF, SQLi, IDOR, etc.)
            
            4. RESPONSE FORMAT:
               - Start with what you found in the reflection analysis (2-3 sentences, specific)
               - Give ONE targeted payload with the exact modified request to send
               - Explain why this payload works for THIS specific reflection context
               - Tell them exactly what to look for in the response
               - End with what to do next based on the result
            
            NEVER say "I cannot see the request" — the data IS in the message or analysis above.
            NEVER list payloads for multiple contexts — you already know the exact context.
            NEVER give generic "try these categories" advice — be surgical and specific.
            """.formatted(
                deepRequestAnalysis, deepResponseAnalysis, reflectionAnalysis,
                wafInfo, payloadLibraryContext, testingHistoryStr.toString(), templateContext
            );
    }
    
    /**
     * Show or hide loading indicator with animation.
     */
    private void showLoadingIndicator(boolean show) {
        SwingUtilities.invokeLater(() -> {
            if (show) {
                // Stop any existing animation timer first to prevent duplicates
                Timer existingTimer = (Timer) loadingLabel.getClientProperty("animationTimer");
                if (existingTimer != null) {
                    existingTimer.stop();
                }
                
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
                    loadingLabel.putClientProperty("animationTimer", null);
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
            
            MANDATORY RESPONSE RULES:
            
            1. DEEP REFLECTION ANALYSIS (you already have the data — use it):
               - Use the REFLECTION ANALYSIS above to identify EXACT reflection points
               - For EACH reflected parameter state: the parameter name, WHERE in the response it reflects
                 (HTML body, inside <script> block, HTML attribute, JSON value, etc.), and whether it's encoded
               - Show the exact surrounding code context: e.g. "var city='YOUR_INPUT';" or "<div>YOUR_INPUT</div>"
               - The user should NOT need to find reflections — you already have that info
            
            2. TARGETED PAYLOADS FOR THE EXACT CONTEXT (do NOT list multiple contexts):
               - You KNOW the reflection context from the analysis — give payloads ONLY for that context
               - If JS string context → JS breakout payloads: ";alert(1);// or similar
               - If HTML body context → HTML injection payloads: <img src=x onerror=alert(1)>
               - If HTML attribute context → attribute breakout: " onload="alert(1)
               - DO NOT list "for HTML try X, for JS try Y" — be specific to what you found
               - Show the EXACT modified request with payload injected in the right place
               - If the value is encoded (Base64, URL-encoded), show decode→inject→re-encode steps
            
            3. IF PRIMARY CONTEXT IS NOT EXPLOITABLE:
               - Explain WHY (encoding, CSP, filtering)
               - Suggest specific bypass techniques for the identified defense
               - If no XSS path exists, suggest other vulnerability types for this specific endpoint
            
            4. WAF BYPASS (only if WAF detected):
               - Techniques specific to the detected WAF and the reflection context
            
            CRITICAL: Never list payloads for contexts that don't apply.
            You have the actual reflection data — be surgical, not encyclopedic.
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
            
            // Extract reflection context for payload library - with null safety
            if (analysis.getReflections() != null && !analysis.getReflections().isEmpty()) {
                var firstReflection = analysis.getReflections().get(0);
                if (firstReflection != null) {
                    List<ReflectionAnalyzer.ReflectionContext> contexts = firstReflection.getContexts();
                    if (contexts != null && !contexts.isEmpty() && contexts.get(0) != null) {
                        reflectionContext = contexts.get(0).getContextType();
                    }
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
        ChatSession activeSession = chatSessionManager.getActiveSession();
        List<ChatSession.TestingStep> sessionTestingSteps = activeSession != null ? 
            activeSession.getTestingSteps() : new ArrayList<>();
        
        if (!sessionTestingSteps.isEmpty()) {
            testingHistory.append("\n\nTESTING HISTORY (What user actually tested):\n");
            for (int i = 0; i < sessionTestingSteps.size(); i++) {
                ChatSession.TestingStep step = sessionTestingSteps.get(i);
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
                
                %s
                
                === DEEP REQUEST ANALYSIS (Session's Original Request) ===
                %s
                
                === DEEP RESPONSE ANALYSIS (Session's Original Response) ===
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
                
                MANDATORY RESPONSE RULES:
                
                1. DEEP REFLECTION-BASED ANALYSIS (this is your primary job):
                   - Use the REFLECTION ANALYSIS above to identify EXACT reflection points
                   - For EACH reflected parameter, state clearly:
                     • Parameter name and its value
                     • EXACTLY where it appears in the response (HTML body, inside a <script> tag,
                       inside an HTML attribute, in a JSON response, in an HTTP header, etc.)
                     • Whether the reflection is encoded, filtered, or raw
                     • The exact surrounding code context (e.g. "reflected inside: var data='YOUR_INPUT_HERE';")
                   - If attached request/response data is present above, analyze THAT data
                
                2. CONTEXT-SPECIFIC PAYLOADS ONLY (do NOT list multiple contexts):
                   - Based on the EXACT reflection context you found, provide payloads ONLY for that context
                   - If input reflects in JS string → JS string breakout payloads ONLY
                   - If input reflects in HTML body → HTML injection payloads ONLY
                   - If input reflects in HTML attribute → attribute escape payloads ONLY
                   - DO NOT say "For HTML context try X, for JS context try Y" — you KNOW the exact context
                   - Show the EXACT modified request with the payload injected in the right parameter
                   - If a parameter value is encoded (Base64, URL-encoded, JSON), show how to decode,
                     inject the payload, and re-encode it
                
                3. ESCALATION PATH:
                   - If the primary reflection context is not exploitable (encoded, filtered),
                     suggest specific bypass techniques for THAT filter
                   - If no XSS is possible, suggest other vulnerability types specific to this endpoint
                     (e.g., SSRF if URL parameters exist, SQLi if database queries likely, IDOR if IDs present)
                
                4. RESPONSE FORMAT:
                   - Start by identifying the exact reflection points (be surgical, cite line/context)
                   - Give ONE targeted payload with the exact modified request
                   - Explain why this payload works for THIS specific context
                   - Show what to look for in the response (exact string/behavior)
                   - End with next steps based on expected result
                
                CRITICAL: Do NOT list payloads for different contexts as categories.
                You have the reflection data — use it to give ONE precise, targeted recommendation.
                Write conversationally but be specific and actionable.
                """.formatted(userQuery, testingHistory.toString(), deepRequestAnalysis, deepResponseAnalysis,
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
                
                MANDATORY RESPONSE RULES:
                
                1. ANALYZE TEST RESULTS DEEPLY:
                   - Look at the TESTING HISTORY above — the user's previous requests and responses are there
                   - Compare what was sent vs what was returned
                   - Identify: was the payload reflected? Was it encoded/stripped/blocked? Did the response change?
                   - Be specific: "Your payload <script> was HTML-encoded to &lt;script&gt; in the response,
                     meaning the server uses HTML entity encoding on this parameter"
                
                2. ADAPT BASED ON WHAT YOU LEARNED:
                   - If payload was encoded → suggest encoding bypass specific to THAT encoding
                   - If payload was stripped → suggest payloads that avoid the stripped pattern
                   - If payload was blocked (WAF/403) → suggest WAF bypass techniques
                   - If payload reflected cleanly but didn't execute → check context (maybe inside a comment, 
                     inside an attribute that needs event handler, etc.)
                   - If reflection context changed → adapt payload to the NEW context
                
                3. GIVE ONE PRECISE NEXT STEP:
                   - Based on what failed/succeeded, provide the SINGLE best next payload to try
                   - Show the EXACT modified request with the new payload
                   - Explain specifically why this bypasses what blocked the previous attempt
                   - If the current vulnerability type seems not exploitable after multiple attempts,
                     pivot to a DIFFERENT vulnerability type relevant to this endpoint
                
                4. RESPONSE FORMAT:
                   - Briefly acknowledge what the previous test revealed (be specific, not generic)
                   - Explain what defense mechanism you identified from the result
                   - Give ONE targeted next payload with the exact request
                   - Explain why this will bypass the identified defense
                   - Tell them what to look for
                
                NEVER list multiple context categories — you know what context the reflection is in.
                NEVER give generic advice — you have the actual test results, analyze them.
                Write conversationally but be surgical and specific.
                """.formatted(conversationContext.toString(), testingHistory.toString(),
                             deepRequestAnalysis, deepResponseAnalysis,
                             wafInfo, truncate(bypassKnowledge, 1500),
                             payloadLibraryContext);
        }
    }

    private String callAI(String prompt) throws Exception {
        return callAIWithPrompts("You are an expert penetration testing consultant.", prompt, null, null, null);
    }
    
    /**
     * Call AI with separate system and user prompts, with proper logging.
     */
    private String callAIWithPrompts(String systemPrompt, String userPrompt, String templateName,
                                     String httpRequest, String httpResponse) throws Exception {
        AIConfigManager config = AIConfigManager.getInstance();
        
        if ("Azure AI".equalsIgnoreCase(config.getProvider())) {
            AzureAIService.Configuration c = new AzureAIService.Configuration();
            c.setEndpoint(config.getEndpoint());
            c.setDeploymentName(config.getDeployment());
            c.setApiKey(config.getAzureApiKey());
            c.setTemperature(config.getTemperature());
            c.setMaxTokens(config.getMaxTokens());
            return new AzureAIService(c).ask(systemPrompt, userPrompt, templateName, httpRequest, httpResponse);
        } else if ("OpenRouter".equalsIgnoreCase(config.getProvider())) {
            com.vista.security.service.OpenRouterService.Configuration c = 
                new com.vista.security.service.OpenRouterService.Configuration();
            c.setApiKey(config.getOpenRouterApiKey());
            c.setModel(config.getOpenRouterModel());
            c.setTemperature(config.getTemperature());
            c.setMaxTokens(config.getMaxTokens());
            return new com.vista.security.service.OpenRouterService(c).ask(systemPrompt, userPrompt, templateName, httpRequest, httpResponse);
        } else {
            OpenAIService.Configuration c = new OpenAIService.Configuration();
            c.setApiKey(config.getOpenAIApiKey());
            c.setModel(config.getModel());
            c.setTemperature(config.getTemperature());
            c.setMaxTokens(config.getMaxTokens());
            return new OpenAIService(c).ask(systemPrompt, userPrompt, templateName, httpRequest, httpResponse);
        }
    }
    
    /**
     * Call AI with full conversation history (token efficient!).
     * System prompt is sent only once, not repeated with every message.
     */
    private String callAIWithHistory(java.util.List<ChatMessage> messages) throws Exception {
        AIConfigManager config = AIConfigManager.getInstance();
        
        if ("Azure AI".equalsIgnoreCase(config.getProvider())) {
            AzureAIService.Configuration c = new AzureAIService.Configuration();
            c.setEndpoint(config.getEndpoint());
            c.setDeploymentName(config.getDeployment());
            c.setApiKey(config.getAzureApiKey());
            c.setTemperature(config.getTemperature());
            c.setMaxTokens(config.getMaxTokens());
            return new AzureAIService(c).askWithHistory(messages);
        } else if ("OpenRouter".equalsIgnoreCase(config.getProvider())) {
            com.vista.security.service.OpenRouterService.Configuration c = 
                new com.vista.security.service.OpenRouterService.Configuration();
            c.setApiKey(config.getOpenRouterApiKey());
            c.setModel(config.getOpenRouterModel());
            c.setTemperature(config.getTemperature());
            c.setMaxTokens(config.getMaxTokens());
            return new com.vista.security.service.OpenRouterService(c).askWithHistory(messages);
        } else {
            OpenAIService.Configuration c = new OpenAIService.Configuration();
            c.setApiKey(config.getOpenAIApiKey());
            c.setModel(config.getModel());
            c.setTemperature(config.getTemperature());
            c.setMaxTokens(config.getMaxTokens());
            return new OpenAIService(c).askWithHistory(messages);
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
        
        // Get session-specific testing steps
        ChatSession activeSession = chatSessionManager.getActiveSession();
        List<ChatSession.TestingStep> sessionTestingSteps = activeSession != null ? 
            activeSession.getTestingSteps() : new ArrayList<>();
        
        // Create context with all required parameters
        VariableContext context = new VariableContext(
            helpers,
            currentRequest,
            reqAnalysis,
            respAnalysis,
            reflectionAnalysis,
            wafList,
            sessionTestingSteps,
            conversationHistory
        );
        
        // Set attached requests count from active session
        context.setAttachedRequestsCount(activeSession != null ? activeSession.getAttachedRequestCount() : 0);
        
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
        
        // Clear session-specific data
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession != null) {
            activeSession.clearTestingSteps();
            activeSession.clearAttachedRequests();
        }
        
        attachedRequests.clear();
        conversationPane.clear();
        currentTestingPlan = null;
        currentStep = 0;
        statusLabel.setText("Ready");
        
        updateMultiRequestLabel();
        
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
        
        // Clear session-specific data
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession != null) {
            activeSession.clearTestingSteps();
            activeSession.clearAttachedRequests();
        }
        
        attachedRequests.clear();
        conversationPane.clear();
        currentTestingPlan = null;
        currentStep = 0;
        
        updateMultiRequestLabel();
        
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
            switch (sender) {
                case "YOU" -> conversationPane.appendUserMessage(message);
                case "VISTA" -> conversationPane.appendAIMessage(message);
                case "SYSTEM" -> conversationPane.appendSystemMessage(message);
                default -> conversationPane.appendSystemMessage(sender + ": " + message);
            }
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
    }
    
    /**
     * Shows the testing history in a dialog
     */
    private void showTestingHistory() {
        ChatSession activeSession = chatSessionManager.getActiveSession();
        List<ChatSession.TestingStep> sessionTestingSteps = activeSession != null ? 
            activeSession.getTestingSteps() : new ArrayList<>();
        
        if (sessionTestingSteps.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "No testing history yet.\n\nAttach requests from Repeater and send them to build history.",
                "Testing History",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        StringBuilder history = new StringBuilder();
        history.append("TESTING HISTORY\n");
        history.append("=".repeat(80)).append("\n\n");
        
        for (int i = 0; i < sessionTestingSteps.size(); i++) {
            ChatSession.TestingStep step = sessionTestingSteps.get(i);
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
            "Testing History (" + sessionTestingSteps.size() + " tests)",
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
        callbacks.printOutput("[VISTA] attachFromRepeaterHistory called with index: " + index);
        
        // Get active session
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession == null) {
            callbacks.printOutput("[VISTA] No active session - cannot attach request from dropdown");
            statusLabel.setText("⚠️ No active session. Send a request from Repeater first.");
            return;
        }
        
        com.vista.security.core.RepeaterRequestTracker.RepeaterRequest req = 
            com.vista.security.core.RepeaterRequestTracker.getInstance().getRequest(index);
        
        if (req != null) {
            IHttpRequestResponse requestResponse = req.getRequestResponse();
            
            // Check if this request is already attached (avoid duplicates)
            if (isRequestAlreadyAttachedToSession(activeSession, requestResponse)) {
                callbacks.printOutput("[VISTA] Request already attached to active session, skipping duplicate");
                statusLabel.setText("⚠️ This request is already attached to this session");
                JOptionPane.showMessageDialog(this,
                    "This request is already attached to the active session.\n\nDuplicate attachments are not allowed.",
                    "Duplicate Request",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // Add to ACTIVE SESSION ONLY (not global list!)
            activeSession.addAttachedRequest(requestResponse);
            callbacks.printOutput("[VISTA] Request added to active session from dropdown: " + activeSession.getSessionId());
            callbacks.printOutput("[VISTA] Total attached requests in session: " + activeSession.getAttachedRequestCount());
            
            updateMultiRequestLabel();
            
            appendSuggestion("SYSTEM", "✓ Request attached from history: " + req.getMethod() + " " + 
                truncate(req.getUrl(), 60) + " [" + req.getStatusCode() + "]");
            
            statusLabel.setText("✓ Request attached - Type your observation and click Send");
        } else {
            callbacks.printOutput("[VISTA] Request not found at index: " + index);
        }
    }
    
    /**
     * Public method to attach a request from Repeater (called from context menu)
     */
    public void attachRepeaterRequest(IHttpRequestResponse requestResponse) {
        callbacks.printOutput("[VISTA] attachRepeaterRequest called");
        
        // Get active session
        ChatSession activeSession = chatSessionManager.getActiveSession();
        if (activeSession == null) {
            callbacks.printOutput("[VISTA] No active session - cannot attach request");
            statusLabel.setText("⚠️ No active session. Send a request from Repeater first.");
            return;
        }
        
        // Check if this request is already attached (avoid duplicates)
        if (isRequestAlreadyAttachedToSession(activeSession, requestResponse)) {
            callbacks.printOutput("[VISTA] Request already attached to active session, skipping duplicate");
            statusLabel.setText("⚠️ This request is already attached to this session");
            return;
        }
        
        // Make sure interactive chat panel is visible
        if (interactiveChatPanel != null) {
            interactiveChatPanel.setVisible(true);
            callbacks.printOutput("[VISTA] Interactive chat panel set to visible");
        }
        
        // Add the request to the ACTIVE SESSION ONLY
        activeSession.addAttachedRequest(requestResponse);
        callbacks.printOutput("[VISTA] Request added to active session: " + activeSession.getSessionId());
        callbacks.printOutput("[VISTA] Total attached requests in session: " + activeSession.getAttachedRequestCount());
        
        // Update multi-request label
        updateMultiRequestLabel();
        
        // Update dropdown
        if (repeaterRequestDropdown != null) {
            updateRepeaterDropdown(repeaterRequestDropdown);
            callbacks.printOutput("[VISTA] Dropdown updated");
        }
        
        // Show success message
        statusLabel.setText("✓ Request attached to active session - Type your observation and click Send");
        
        // Add a helpful message to the conversation if it's empty
        if (conversationHistory.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                conversationPane.appendSystemMessage(
                    "📎 Request attached to this session!\n\n" +
                    "💡 Quick Start:\n" +
                    "1. Type what you observed (e.g., 'I see HTML encoding' or 'WAF blocked my payload')\n" +
                    "2. Click Send\n" +
                    "3. AI will analyze and provide bypass suggestions\n\n" +
                    "Or ask a question like:\n" +
                    "• 'How can I bypass this WAF?'\n" +
                    "• 'Test for XSS'\n" +
                    "• 'Suggest SQLi bypass payloads'\n\n" +
                    "💡 TIP: You can attach multiple requests for comparison!"
                );
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
     * Check if a request is already attached to a specific session (to avoid duplicates).
     */
    private boolean isRequestAlreadyAttachedToSession(ChatSession session, IHttpRequestResponse newRequest) {
        if (newRequest == null || newRequest.getRequest() == null) return false;
        
        String newFirstLine = extractFirstLine(newRequest.getRequest());
        
        for (IHttpRequestResponse attached : session.getAttachedRequests()) {
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
    
    // ═══════════════════════════════════════════════════════════════
    // Chat Session Helper Methods
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Get current system prompt from selected template.
     */
    private String getCurrentSystemPrompt() {
        if (templateSelector != null) {
            String selectedTemplate = (String) templateSelector.getSelectedItem();
            // Check for actual default placeholder text, not just "Default"
            if (selectedTemplate != null && !selectedTemplate.startsWith("--") && !selectedTemplate.equals("Default")) {
                PromptTemplate template = templateManager.getTemplateByName(selectedTemplate);
                if (template != null) {
                    return template.getSystemPrompt();
                }
            }
        }
        
        // Default system prompt - rich enough for security testing context
        return """
            You are an expert penetration testing mentor in a Burp Suite extension called VISTA.
            You help security testers find and exploit vulnerabilities in web applications.
            
            YOUR CAPABILITIES:
            - Users can ATTACH HTTP request/response pairs to their messages for you to analyze
            - When a user's message contains "=== ATTACHED REQUEST/RESPONSE FOR ANALYSIS ===" section,
              that is REAL HTTP traffic they captured — you MUST analyze it thoroughly
            - You have access to deep automated analysis of the target
            - Provide specific, actionable testing guidance with real payloads
            
            RULES:
            - Be conversational and educational, not generic
            - Provide specific payloads, not just theory
            - Explain WHY each test/payload is relevant to their specific context
            - If the user attaches request/response data, ALWAYS analyze it in detail
            - NEVER say "I cannot see the request" or "please paste the request"
            - Build on previous conversation context naturally
            - Keep responses focused and practical
            """;
    }
    
    /**
     * Extract request URL from request text.
     */
    private String extractRequestUrl(String reqText) {
        String[] lines = reqText.split("\r?\n");
        if (lines.length > 0) {
            String firstLine = lines[0];
            String[] parts = firstLine.split(" ");
            if (parts.length >= 2) {
                return parts[0] + " " + parts[1]; // Method + URL
            }
            return firstLine;
        }
        return "Unknown Request";
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Session Switcher UI Methods (DISABLED - UI removed for simplicity)
    // ═══════════════════════════════════════════════════════════════
    
    /*
    // These methods are commented out since session switcher UI was removed
    
    private void updateSessionSelector() {
        // Session selector UI removed for simplicity
    }
    
    private String buildSessionDisplayText(ChatSession session) {
        // Session selector UI removed for simplicity
        return "";
    }
    
    private void switchToSelectedSession() {
        // Session selector UI removed for simplicity
    }
    */
    
    /**
     * Load a session's conversation into the UI.
     */
    private void loadSessionIntoUI(ChatSession session) {
        // Clear current UI
        conversationPane.clear();
        conversationHistory.clear();
        
        // NOTE: We DON'T clear testingSteps here anymore - they're stored per-session!
        // Each session maintains its own testingSteps, so switching sessions preserves them.
        
        // Load the request/response for this session
        IHttpRequestResponse sessionRequest = session.getRequestResponse();
        if (sessionRequest != null) {
            this.currentRequest = sessionRequest;
            httpMessageViewer.setHttpMessage(sessionRequest.getRequest(), sessionRequest.getResponse());
        }
        
        // Load session messages into UI
        for (ChatMessage msg : session.getMessages()) {
            if (msg.getRole() == ChatMessage.Role.USER) {
                appendSuggestion("YOU", msg.getContent());
                conversationHistory.add(new ConversationMessage("user", msg.getContent()));
            } else if (msg.getRole() == ChatMessage.Role.ASSISTANT) {
                appendSuggestion("VISTA", msg.getContent());
                conversationHistory.add(new ConversationMessage("assistant", msg.getContent()));
            }
            // Skip SYSTEM messages (they're not shown in UI)
        }
        
        // Update multi-request label to show session's attached requests
        updateMultiRequestLabel();
        
        // Update status
        statusLabel.setText("Loaded session: " + session.getSessionTitle());
        
        callbacks.printOutput("[VISTA] Loaded session: " + session.getSessionId());
        callbacks.printOutput("[VISTA] Session has " + session.getAttachedRequestCount() + " attached requests");
        callbacks.printOutput("[VISTA] Session has " + session.getTestingStepCount() + " testing steps");
    }
    
    /*
    // Session management dialog - commented out since UI was simplified
    private void showAllSessions() {
        // Session switcher UI removed for simplicity
    }
    */
    
    /**
     * Build a summary string for a session in the list.
     */
    private String getSessionSummary(ChatSession session, int index) {
        String activeMarker = session.isActive() ? "🟢" : "⚪";
        String title = session.getSessionTitle();
        if (title.length() > 60) {
            title = title.substring(0, 57) + "...";
        }
        return String.format("%s #%d: %s (%d messages)", 
            activeMarker, index, title, session.getMessages().size());
    }
    
    /**
     * Build a detailed summary for session list.
     */
    private String buildSessionSummary(ChatSession session, int index) {
        String activeMarker = session.isActive() ? "🟢 ACTIVE" : "⚪ Inactive";
        String title = session.getSessionTitle();
        int messageCount = session.getMessages().size();
        int exchangeCount = session.getExchangeCount();
        
        return String.format("#%d [%s] %s - %d messages (%d exchanges)", 
            index, activeMarker, title, messageCount, exchangeCount);
    }
    
    /**
     * Build a preview of session conversation.
     */
    private String buildSessionPreview(ChatSession session) {
        StringBuilder preview = new StringBuilder();
        
        preview.append("SESSION DETAILS\n");
        preview.append("═".repeat(80)).append("\n\n");
        preview.append("Session ID: ").append(session.getSessionId()).append("\n");
        preview.append("Created: ").append(session.getCreatedAt()).append("\n");
        preview.append("Last Activity: ").append(session.getLastActivityAt()).append("\n");
        preview.append("Request: ").append(session.getInitialRequestUrl()).append("\n");
        preview.append("Status: ").append(session.isActive() ? "Active" : "Inactive").append("\n");
        preview.append("Messages: ").append(session.getMessages().size()).append("\n");
        preview.append("Exchanges: ").append(session.getExchangeCount()).append("\n\n");
        
        preview.append("CONVERSATION\n");
        preview.append("═".repeat(80)).append("\n\n");
        
        List<ChatMessage> messages = session.getMessages();
        for (int i = 0; i < messages.size(); i++) {
            ChatMessage msg = messages.get(i);
            
            if (msg.getRole() == ChatMessage.Role.SYSTEM) {
                continue; // Skip system messages in preview
            }
            
            String roleLabel = msg.getRole() == ChatMessage.Role.USER ? "👤 YOU" : "🤖 VISTA";
            preview.append(roleLabel).append(":\n");
            
            String content = msg.getContent();
            if (content.length() > 500) {
                content = content.substring(0, 497) + "...";
            }
            preview.append(content).append("\n\n");
            preview.append("─".repeat(80)).append("\n\n");
        }
        
        return preview.toString();
    }
}
