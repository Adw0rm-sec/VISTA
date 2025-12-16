package com.vista.security.ui;

import burp.*;
import com.vista.security.core.*;
import com.vista.security.model.RequestGroup;
import com.vista.security.service.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main UI panel for the VISTA extension.
 * Provides the primary interface for security analysis.
 */
public class MainPanel {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JPanel rootPanel;

    // Request management
    private final DefaultListModel<String> requestListModel = new DefaultListModel<>();
    private final JList<String> requestList = new JList<>(requestListModel);
    private final List<IHttpRequestResponse> requests = new ArrayList<>();
    private final Map<IHttpRequestResponse, StringBuilder> analysisHistory = new HashMap<>();
    private final Map<IHttpRequestResponse, List<String>> findings = new HashMap<>();
    private final StringBuilder globalChat = new StringBuilder();

    // Display areas
    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();
    private final JTextArea parametersArea = new JTextArea();
    private final JTextPane chatPane = new JTextPane();
    private final JTextField questionField = new JTextField();

    // Settings controls
    private final JComboBox<String> providerCombo = new JComboBox<>(new String[]{"Azure AI", "OpenAI"});
    private final JTextField endpointField = new JTextField();
    private final JTextField deploymentField = new JTextField();
    private final JTextField apiVersionField = new JTextField("2024-12-01-preview");
    private final JPasswordField apiKeyField = new JPasswordField();
    private final JTextField openAiModelField = new JTextField();
    private final JTextField openAiBaseUrlField = new JTextField("https://api.openai.com/v1");
    private final JCheckBox stripHeadersCheckbox = new JCheckBox("Strip sensitive headers", true);
    private final JSpinner maxCharsSpinner = new JSpinner(new SpinnerNumberModel(32000, 1000, 200000, 1000));
    private final JSlider temperatureSlider = new JSlider(0, 100, 70);

    // Templates
    private final JTextField templatesDirField = new JTextField();
    private final DefaultListModel<String> templatesModel = new DefaultListModel<>();
    private final JList<String> templatesList = new JList<>(templatesModel);
    private final Map<String, String> customTemplates = new LinkedHashMap<>();

    // Payload library
    private final DefaultListModel<String> payloadListModel = new DefaultListModel<>();
    private final JList<String> payloadList = new JList<>(payloadListModel);
    private final Map<String, String> savedPayloads = new LinkedHashMap<>();

    // Findings
    private final DefaultListModel<String> findingsListModel = new DefaultListModel<>();
    private final JList<String> findingsList = new JList<>(findingsListModel);

    // Request Groups
    private final List<RequestGroup> requestGroups = new ArrayList<>();
    private final Map<IHttpRequestResponse, RequestGroup> requestToGroup = new HashMap<>();
    private final DefaultComboBoxModel<String> groupComboModel = new DefaultComboBoxModel<>();
    private final JComboBox<String> groupCombo = new JComboBox<>(groupComboModel);

    // Session and Reflection display
    private final JTextArea sessionArea = new JTextArea();
    private final JTextArea reflectionArea = new JTextArea();

    // Status
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progressBar = new JProgressBar();
    private final javax.swing.Timer animationTimer;
    private final AtomicBoolean isProcessing = new AtomicBoolean(false);

    // Preset selector
    private final JComboBox<String> presetCombo = new JComboBox<>(new String[]{
            "Auto-detect", "CSRF", "IDOR", "SQL Injection", "SSRF", "XSS",
            "Authentication", "Authorization", "File Upload", "XXE", "Command Injection"
    });

    private IHttpRequestResponse currentRequest;
    private int animationDotCount = 0;

    public MainPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.animationTimer = new javax.swing.Timer(400, e -> animateStatus());
        this.rootPanel = buildUI();
        loadDefaultPayloads();
        loadPersistedState();
    }

    public JComponent getComponent() {
        return rootPanel;
    }

    public void addMessages(IHttpRequestResponse[] messages) {
        if (messages == null || messages.length == 0) return;
        
        for (IHttpRequestResponse msg : messages) {
            requests.add(msg);
            requestListModel.addElement(summarizeRequest(msg));
            analysisHistory.putIfAbsent(msg, new StringBuilder());
            findings.putIfAbsent(msg, new ArrayList<>());
        }
        
        if (currentRequest == null && !requests.isEmpty()) {
            requestList.setSelectedIndex(requests.size() - 1);
            loadSelectedRequest();
        }
        
        persistState();
    }

    // ==================== UI Construction ====================

    private JPanel buildUI() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        Font monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        requestArea.setEditable(false);
        responseArea.setEditable(false);
        parametersArea.setEditable(false);
        sessionArea.setEditable(false);
        reflectionArea.setEditable(false);
        requestArea.setFont(monoFont);
        responseArea.setFont(monoFont);
        parametersArea.setFont(monoFont);
        sessionArea.setFont(monoFont);
        reflectionArea.setFont(monoFont);
        chatPane.setEditable(false);
        chatPane.setFont(monoFont);

        // Left: Request list with groups
        JPanel leftPanel = buildRequestListPanel();

        // Center: Request/Response/Parameters/Session/Reflections tabs
        JTabbedPane contentTabs = new JTabbedPane();
        contentTabs.addTab("Request", new JScrollPane(requestArea));
        contentTabs.addTab("Response", new JScrollPane(responseArea));
        contentTabs.addTab("Parameters", new JScrollPane(parametersArea));
        contentTabs.addTab("Session", new JScrollPane(sessionArea));
        contentTabs.addTab("Reflections", new JScrollPane(reflectionArea));

        JSplitPane leftCenterSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, contentTabs);
        leftCenterSplit.setResizeWeight(0.25);

        // Bottom: Chat panel
        JPanel chatPanel = buildChatPanel();

        // Right: Sidebar
        JPanel rightSidebar = buildSidebar();

        // Main layout
        JSplitPane centerChatSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, leftCenterSplit, chatPanel);
        centerChatSplit.setResizeWeight(0.45);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, centerChatSplit, rightSidebar);
        mainSplit.setResizeWeight(0.75);

        // Toolbar
        JPanel toolbar = buildToolbar();

        // Settings (collapsible)
        JPanel settingsPanel = buildSettingsPanel();
        settingsPanel.setVisible(false);
        panel.putClientProperty("settingsPanel", settingsPanel);

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(mainSplit, BorderLayout.CENTER);
        panel.add(settingsPanel, BorderLayout.SOUTH);

        setupKeyboardShortcuts(panel);

        return panel;
    }

    private JPanel buildRequestListPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(BorderFactory.createTitledBorder("Requests"));

        // Custom cell renderer for colored groups
        requestList.setCellRenderer(new RequestListCellRenderer());
        requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) loadSelectedRequest();
        });
        requestList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) sendToRepeater();
            }
        });

        JScrollPane scrollPane = new JScrollPane(requestList);
        scrollPane.setPreferredSize(new Dimension(280, 200));

        // Group controls
        JPanel groupPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        groupComboModel.addElement("No Group");
        groupCombo.setPreferredSize(new Dimension(120, 25));
        JButton newGroupBtn = new JButton("+");
        newGroupBtn.setToolTipText("Create new group");
        JButton assignGroupBtn = new JButton("Assign");
        assignGroupBtn.setToolTipText("Assign selected request to group");
        
        newGroupBtn.addActionListener(e -> createNewGroup());
        assignGroupBtn.addActionListener(e -> assignToGroup());
        
        groupPanel.add(new JLabel("Group:"));
        groupPanel.add(groupCombo);
        groupPanel.add(newGroupBtn);
        groupPanel.add(assignGroupBtn);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton removeBtn = new JButton("Remove");
        JButton clearBtn = new JButton("Clear All");
        JButton repeaterBtn = new JButton("→ Repeater");
        JButton intruderBtn = new JButton("→ Intruder");

        removeBtn.addActionListener(e -> removeSelectedRequest());
        clearBtn.addActionListener(e -> clearAllRequests());
        repeaterBtn.addActionListener(e -> sendToRepeater());
        intruderBtn.addActionListener(e -> sendToIntruder());

        buttonPanel.add(removeBtn);
        buttonPanel.add(clearBtn);
        buttonPanel.add(repeaterBtn);
        buttonPanel.add(intruderBtn);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(groupPanel, BorderLayout.NORTH);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Custom cell renderer for request list with group colors.
     */
    private class RequestListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index, 
                                                      boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (index >= 0 && index < requests.size()) {
                IHttpRequestResponse req = requests.get(index);
                RequestGroup group = requestToGroup.get(req);
                
                if (group != null && !isSelected) {
                    label.setBackground(group.getLightColor());
                    label.setOpaque(true);
                    // Add group indicator
                    label.setText("● " + value.toString());
                    label.setForeground(group.getColor().darker());
                }
            }
            
            return label;
        }
    }

    private JPanel buildChatPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createTitledBorder("VISTA Analysis"));

        JScrollPane chatScroll = new JScrollPane(chatPane);

        // Quick question buttons
        JPanel quickButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        String[] quickQuestions = {"Suggest Tests", "Find Vulnerabilities", "Generate Payloads", "Explain Response", "Bypass Ideas"};
        for (String label : quickQuestions) {
            JButton btn = new JButton(label);
            btn.setFont(btn.getFont().deriveFont(10f));
            btn.addActionListener(e -> {
                questionField.setText(getQuickQuestionPrompt(label));
                submitQuestion();
            });
            quickButtons.add(btn);
        }

        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout(6, 6));
        installPlaceholder(questionField, "Ask about this request, or press Enter for suggestions...");
        
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton askBtn = new JButton("Ask VISTA");
        JButton clearChatBtn = new JButton("Clear");
        JButton copyBtn = new JButton("Copy");
        
        askBtn.addActionListener(e -> submitQuestion());
        clearChatBtn.addActionListener(e -> clearCurrentChat());
        copyBtn.addActionListener(e -> copyChat());
        
        buttonRow.add(clearChatBtn);
        buttonRow.add(copyBtn);
        buttonRow.add(askBtn);
        
        inputPanel.add(questionField, BorderLayout.CENTER);
        inputPanel.add(buttonRow, BorderLayout.EAST);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(quickButtons, BorderLayout.NORTH);
        bottomPanel.add(inputPanel, BorderLayout.SOUTH);

        panel.add(chatScroll, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel buildSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setPreferredSize(new Dimension(220, 400));

        // Quick Actions
        JPanel actionsPanel = new JPanel(new GridLayout(0, 1, 4, 4));
        actionsPanel.setBorder(BorderFactory.createTitledBorder("Quick Actions"));
        
        JButton analyzeBtn = new JButton("🔍 Auto-Analyze");
        JButton extractBtn = new JButton("📋 Extract Parameters");
        JButton sessionBtn = new JButton("🔐 Analyze Session");
        JButton reflectionBtn = new JButton("🔄 Find Reflections");
        JButton reportBtn = new JButton("📄 Export Report");
        JButton findingBtn = new JButton("⚠️ Add Finding");
        
        analyzeBtn.addActionListener(e -> autoAnalyze());
        extractBtn.addActionListener(e -> extractParameters());
        sessionBtn.addActionListener(e -> analyzeSessionDetails());
        reflectionBtn.addActionListener(e -> analyzeReflectionDetails());
        reportBtn.addActionListener(e -> exportReport());
        findingBtn.addActionListener(e -> addFinding());
        
        actionsPanel.add(analyzeBtn);
        actionsPanel.add(extractBtn);
        actionsPanel.add(sessionBtn);
        actionsPanel.add(reflectionBtn);
        actionsPanel.add(reportBtn);
        actionsPanel.add(findingBtn);

        // Payload Library
        JPanel payloadPanel = new JPanel(new BorderLayout(4, 4));
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload Library"));
        payloadList.setVisibleRowCount(6);
        payloadList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        payloadList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) copySelectedPayload();
            }
        });
        
        JPanel payloadButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 2));
        JButton copyPayloadBtn = new JButton("Copy");
        JButton addPayloadBtn = new JButton("+");
        copyPayloadBtn.addActionListener(e -> copySelectedPayload());
        addPayloadBtn.addActionListener(e -> addCustomPayload());
        payloadButtons.add(copyPayloadBtn);
        payloadButtons.add(addPayloadBtn);
        
        payloadPanel.add(new JScrollPane(payloadList), BorderLayout.CENTER);
        payloadPanel.add(payloadButtons, BorderLayout.SOUTH);

        // Findings
        JPanel findingsPanel = new JPanel(new BorderLayout(4, 4));
        findingsPanel.setBorder(BorderFactory.createTitledBorder("Findings"));
        findingsList.setVisibleRowCount(5);
        findingsList.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        
        JPanel findingsButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 2));
        JButton viewBtn = new JButton("View");
        JButton removeBtn = new JButton("Remove");
        viewBtn.addActionListener(e -> viewSelectedFinding());
        removeBtn.addActionListener(e -> removeSelectedFinding());
        findingsButtons.add(viewBtn);
        findingsButtons.add(removeBtn);
        
        findingsPanel.add(new JScrollPane(findingsList), BorderLayout.CENTER);
        findingsPanel.add(findingsButtons, BorderLayout.SOUTH);

        sidebar.add(actionsPanel);
        sidebar.add(Box.createVerticalStrut(8));
        sidebar.add(payloadPanel);
        sidebar.add(Box.createVerticalStrut(8));
        sidebar.add(findingsPanel);

        return sidebar;
    }

    private JPanel buildToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JToggleButton settingsToggle = new JToggleButton("⚙ Settings");
        settingsToggle.addActionListener(e -> {
            JPanel settings = (JPanel) rootPanel.getClientProperty("settingsPanel");
            if (settings != null) {
                settings.setVisible(settingsToggle.isSelected());
                rootPanel.revalidate();
                rootPanel.repaint();
            }
        });

        toolbar.add(settingsToggle);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(new JLabel("Focus:"));
        toolbar.add(presetCombo);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        
        progressBar.setPreferredSize(new Dimension(100, 20));
        progressBar.setVisible(false);
        toolbar.add(progressBar);
        toolbar.add(statusLabel);

        return toolbar;
    }

    private JPanel buildSettingsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Settings & Configuration"));

        // Provider row
        JPanel providerRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        providerRow.add(new JLabel("AI Provider:"));
        providerRow.add(providerCombo);
        providerRow.add(Box.createHorizontalStrut(20));
        providerRow.add(new JLabel("Temperature:"));
        temperatureSlider.setPreferredSize(new Dimension(100, 20));
        providerRow.add(temperatureSlider);
        JLabel tempLabel = new JLabel("0.7");
        temperatureSlider.addChangeListener(e -> tempLabel.setText(String.format("%.1f", temperatureSlider.getValue() / 100.0)));
        providerRow.add(tempLabel);

        // Azure settings
        JPanel azurePanel = new JPanel(new GridLayout(0, 4, 8, 4));
        azurePanel.setBorder(BorderFactory.createTitledBorder("Azure AI"));
        azurePanel.add(new JLabel("Endpoint:"));
        azurePanel.add(endpointField);
        azurePanel.add(new JLabel("Deployment:"));
        azurePanel.add(deploymentField);
        azurePanel.add(new JLabel("API Version:"));
        azurePanel.add(apiVersionField);
        azurePanel.add(new JLabel(""));
        azurePanel.add(new JLabel(""));

        // OpenAI settings
        JPanel openaiPanel = new JPanel(new GridLayout(0, 4, 8, 4));
        openaiPanel.setBorder(BorderFactory.createTitledBorder("OpenAI"));
        openaiPanel.add(new JLabel("Model:"));
        openaiPanel.add(openAiModelField);
        openaiPanel.add(new JLabel("Base URL:"));
        openaiPanel.add(openAiBaseUrlField);

        // Common settings
        JPanel commonPanel = new JPanel(new GridLayout(0, 4, 8, 4));
        commonPanel.setBorder(BorderFactory.createTitledBorder("Common"));
        commonPanel.add(new JLabel("API Key:"));
        commonPanel.add(apiKeyField);
        commonPanel.add(new JLabel("Max Chars:"));
        commonPanel.add(maxCharsSpinner);
        commonPanel.add(stripHeadersCheckbox);
        commonPanel.add(new JLabel(""));
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> testConnection());
        commonPanel.add(testBtn);
        commonPanel.add(new JLabel(""));

        // Templates
        JPanel templatesPanel = new JPanel(new BorderLayout(8, 4));
        templatesPanel.setBorder(BorderFactory.createTitledBorder("Custom Templates"));
        JPanel tplRow = new JPanel(new BorderLayout(4, 0));
        tplRow.add(new JLabel("Directory: "), BorderLayout.WEST);
        tplRow.add(templatesDirField, BorderLayout.CENTER);
        JButton loadBtn = new JButton("Load");
        loadBtn.addActionListener(e -> loadCustomTemplates());
        tplRow.add(loadBtn, BorderLayout.EAST);
        templatesList.setVisibleRowCount(3);
        templatesPanel.add(tplRow, BorderLayout.NORTH);
        templatesPanel.add(new JScrollPane(templatesList), BorderLayout.CENTER);

        // Placeholders
        installPlaceholder(endpointField, "https://your-resource.openai.azure.com");
        installPlaceholder(deploymentField, "gpt-4o-mini");
        installPlaceholder(apiKeyField, "<paste-your-api-key>");
        installPlaceholder(openAiModelField, "gpt-4o-mini");
        installPlaceholder(openAiBaseUrlField, "https://api.openai.com/v1");

        providerCombo.addActionListener(e -> updateProviderVisibility());
        updateProviderVisibility();

        panel.add(providerRow);
        panel.add(azurePanel);
        panel.add(openaiPanel);
        panel.add(commonPanel);
        panel.add(templatesPanel);

        return panel;
    }

    private void setupKeyboardShortcuts(JPanel panel) {
        questionField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    if (e.isControlDown() || e.isMetaDown() || questionField.getText().trim().isEmpty()) {
                        submitQuestion();
                    }
                }
            }
        });

        requestList.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_DELETE || e.getKeyCode() == KeyEvent.VK_BACK_SPACE) {
                    removeSelectedRequest();
                }
            }
        });

        panel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancel");
        panel.getActionMap().put("cancel", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (isProcessing.get()) {
                    isProcessing.set(false);
                    setStatus(false, "Cancelled");
                }
            }
        });
    }

    // ==================== Request Management ====================

    private void loadSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0 || idx >= requests.size()) return;

        currentRequest = requests.get(idx);
        requestArea.setText(HttpMessageParser.requestToText(helpers, currentRequest.getRequest()));
        responseArea.setText(HttpMessageParser.responseToText(helpers, currentRequest.getResponse()));
        requestArea.setCaretPosition(0);
        responseArea.setCaretPosition(0);

        String params = ParameterAnalyzer.extractSummary(helpers, currentRequest);
        parametersArea.setText(params);
        parametersArea.setCaretPosition(0);

        // Analyze session information
        SessionAnalyzer.SessionInfo sessionInfo = SessionAnalyzer.analyze(helpers, currentRequest);
        sessionArea.setText(sessionInfo.summary);
        sessionArea.setCaretPosition(0);

        // Analyze reflections
        ReflectionAnalyzer.ReflectionResult reflections = ReflectionAnalyzer.analyze(helpers, currentRequest);
        reflectionArea.setText(reflections.summary);
        reflectionArea.setCaretPosition(0);

        // Update group combo selection
        RequestGroup group = requestToGroup.get(currentRequest);
        if (group != null) {
            groupCombo.setSelectedItem(group.getName());
        } else {
            groupCombo.setSelectedIndex(0); // "No Group"
        }

        StringBuilder history = analysisHistory.get(currentRequest);
        renderChat(history == null ? "" : history.toString());

        updateFindingsList();
        autoDetectPreset();
    }

    private void autoDetectPreset() {
        if (currentRequest == null) return;
        String detected = ParameterAnalyzer.detectLikelyVulnerability(helpers, currentRequest);
        if (detected != null && "Auto-detect".equals(presetCombo.getSelectedItem())) {
            statusLabel.setText("Detected: " + detected);
        }
    }

    private String summarizeRequest(IHttpRequestResponse msg) {
        try {
            String reqText = HttpMessageParser.requestToText(helpers, msg.getRequest());
            String[] lines = reqText.split("\\r?\\n");
            String firstLine = lines.length > 0 ? lines[0] : "(request)";
            String host = HttpMessageParser.extractHeader(reqText, "Host");
            host = host != null ? host : "";
            String shortPath = firstLine.length() > 80 ? firstLine.substring(0, 80) + "…" : firstLine;
            return (host.isEmpty() ? "" : host + " ") + shortPath;
        } catch (Exception e) {
            return "Request " + (requests.size() + 1);
        }
    }

    private void removeSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0 || idx >= requests.size()) return;

        IHttpRequestResponse removed = requests.remove(idx);
        requestListModel.remove(idx);
        analysisHistory.remove(removed);
        findings.remove(removed);

        if (requests.isEmpty()) {
            currentRequest = null;
            requestArea.setText("");
            responseArea.setText("");
            parametersArea.setText("");
            renderChat(globalChat.toString());
            findingsListModel.clear();
        } else {
            int newIdx = Math.min(idx, requests.size() - 1);
            requestList.setSelectedIndex(newIdx);
            loadSelectedRequest();
        }
        persistState();
    }

    private void clearAllRequests() {
        int confirm = JOptionPane.showConfirmDialog(rootPanel,
            "Clear all requests and analysis history?", "Confirm", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        requests.clear();
        requestListModel.clear();
        analysisHistory.clear();
        findings.clear();
        currentRequest = null;
        requestArea.setText("");
        responseArea.setText("");
        parametersArea.setText("");
        renderChat(globalChat.toString());
        findingsListModel.clear();
        persistState();
    }

    private IHttpRequestResponse getSelectedRequest() {
        int idx = requestList.getSelectedIndex();
        return (idx >= 0 && idx < requests.size()) ? requests.get(idx) : null;
    }

    // ==================== Request Groups ====================

    private void createNewGroup() {
        String name = JOptionPane.showInputDialog(rootPanel, "Group name:", "Create Group", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.isBlank()) return;

        // Color selection dialog
        JPanel colorPanel = new JPanel(new GridLayout(2, 5, 4, 4));
        ButtonGroup colorGroup = new ButtonGroup();
        JRadioButton[] colorButtons = new JRadioButton[RequestGroup.PRESET_COLORS.length];
        
        for (int i = 0; i < RequestGroup.PRESET_COLORS.length; i++) {
            final int colorIndex = i;
            colorButtons[i] = new JRadioButton(RequestGroup.COLOR_NAMES[i]);
            colorButtons[i].setBackground(RequestGroup.PRESET_COLORS[i]);
            colorButtons[i].setOpaque(true);
            colorGroup.add(colorButtons[i]);
            colorPanel.add(colorButtons[i]);
        }
        colorButtons[0].setSelected(true);

        int result = JOptionPane.showConfirmDialog(rootPanel, colorPanel, "Select Color", 
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        int selectedColor = 0;
        for (int i = 0; i < colorButtons.length; i++) {
            if (colorButtons[i].isSelected()) {
                selectedColor = i;
                break;
            }
        }

        RequestGroup group = new RequestGroup(name, selectedColor);
        requestGroups.add(group);
        groupComboModel.addElement(name);
        
        appendChat("INFO", "Created group: " + name + " (" + RequestGroup.COLOR_NAMES[selectedColor] + ")");
        persistState();
    }

    private void assignToGroup() {
        if (currentRequest == null) {
            appendChat("VISTA", "Select a request first.");
            return;
        }

        String selectedGroupName = (String) groupCombo.getSelectedItem();
        if (selectedGroupName == null || "No Group".equals(selectedGroupName)) {
            // Remove from current group
            RequestGroup currentGroup = requestToGroup.remove(currentRequest);
            if (currentGroup != null) {
                currentGroup.removeRequest(currentRequest);
                appendChat("INFO", "Removed request from group: " + currentGroup.getName());
            }
        } else {
            // Find the group and assign
            for (RequestGroup group : requestGroups) {
                if (group.getName().equals(selectedGroupName)) {
                    // Remove from previous group if any
                    RequestGroup prevGroup = requestToGroup.get(currentRequest);
                    if (prevGroup != null) {
                        prevGroup.removeRequest(currentRequest);
                    }
                    
                    // Assign to new group
                    group.addRequest(currentRequest);
                    requestToGroup.put(currentRequest, group);
                    appendChat("INFO", "Assigned request to group: " + group.getName());
                    break;
                }
            }
        }
        
        // Refresh the list to show updated colors
        requestList.repaint();
        persistState();
    }

    // ==================== Burp Integration ====================

    private void sendToRepeater() {
        IHttpRequestResponse selected = getSelectedRequest();
        if (selected == null) {
            appendChat("VISTA", "No request selected.");
            return;
        }
        try {
            String[] hostInfo = extractHostInfo(selected);
            callbacks.sendToRepeater(hostInfo[0], Integer.parseInt(hostInfo[1]), 
                Boolean.parseBoolean(hostInfo[2]), selected.getRequest(), "VISTA");
            appendChat("INFO", "Sent to Repeater: " + hostInfo[0] + ":" + hostInfo[1]);
        } catch (Exception ex) {
            appendChat("ERROR", "Failed: " + ex.getMessage());
        }
    }

    private void sendToIntruder() {
        IHttpRequestResponse selected = getSelectedRequest();
        if (selected == null) {
            appendChat("VISTA", "No request selected.");
            return;
        }
        try {
            String[] hostInfo = extractHostInfo(selected);
            // Try reflection for Intruder (may not be available in all versions)
            try {
                java.lang.reflect.Method method = callbacks.getClass().getMethod(
                    "sendToIntruder", String.class, int.class, boolean.class, byte[].class);
                method.invoke(callbacks, hostInfo[0], Integer.parseInt(hostInfo[1]), 
                    Boolean.parseBoolean(hostInfo[2]), selected.getRequest());
                appendChat("INFO", "Sent to Intruder: " + hostInfo[0] + ":" + hostInfo[1]);
            } catch (NoSuchMethodException e) {
                callbacks.sendToRepeater(hostInfo[0], Integer.parseInt(hostInfo[1]), 
                    Boolean.parseBoolean(hostInfo[2]), selected.getRequest(), "VISTA-Intruder");
                appendChat("INFO", "Sent to Repeater (Intruder unavailable): " + hostInfo[0]);
            }
        } catch (Exception ex) {
            appendChat("ERROR", "Failed: " + ex.getMessage());
        }
    }

    private String[] extractHostInfo(IHttpRequestResponse msg) {
        String host = null;
        int port = 0;
        boolean https = false;

        try { host = msg.getHost(); } catch (Throwable ignored) {}
        try { port = msg.getPort(); } catch (Throwable ignored) {}
        try { https = msg.isHttps(); } catch (Throwable ignored) {}

        if (host == null || host.isBlank() || port == 0) {
            String reqText = HttpMessageParser.requestToText(helpers, msg.getRequest());
            String hostHeader = HttpMessageParser.extractHeader(reqText, "Host");
            if (hostHeader != null) {
                if (hostHeader.contains(":")) {
                    String[] parts = hostHeader.split(":", 2);
                    host = parts[0].trim();
                    try { port = Integer.parseInt(parts[1].trim()); } catch (NumberFormatException ignored) {}
                } else {
                    host = hostHeader.trim();
                }
            }
            String firstLine = reqText.split("\\r?\\n")[0].toLowerCase();
            if (firstLine.contains("https://")) https = true;
            if (port == 0) port = https ? 443 : 80;
        }

        if (host == null || host.isBlank()) {
            throw new RuntimeException("Could not determine host");
        }

        return new String[]{host, String.valueOf(port), String.valueOf(https)};
    }

    // ==================== AI Interaction ====================

    private void submitQuestion() {
        if (isProcessing.get()) {
            appendChat("VISTA", "Already processing. Please wait or press Escape to cancel.");
            return;
        }

        String question = questionField.getText().trim();
        if (question.isEmpty() || question.equals("Ask about this request, or press Enter for suggestions...")) {
            question = "Analyze this request and provide the top 5 most likely security tests with specific payloads, rationale, and verification steps.";
        }

        if (getSelectedRequest() == null) {
            appendChat("VISTA", "Send a request to VISTA first (right-click → Send to VISTA).");
            return;
        }

        questionField.setText("");
        appendChat("You", question);

        final String finalQuestion = question;
        final IHttpRequestResponse boundRequest = getSelectedRequest();

        String reqText = HttpMessageParser.requestToText(helpers, boundRequest.getRequest());
        String rspText = HttpMessageParser.responseToText(helpers, boundRequest.getResponse());

        boolean stripHeaders = stripHeadersCheckbox.isSelected();
        int maxChars = (Integer) maxCharsSpinner.getValue();

        String reqForAI = HttpMessageParser.prepareForAI(reqText, stripHeaders, maxChars);
        String rspForAI = HttpMessageParser.prepareForAI(rspText, stripHeaders, maxChars / 2);

        String systemPrompt = buildSystemPrompt();
        String userPrompt = "HTTP Request:\n" + reqForAI + "\n\nHTTP Response:\n" + rspForAI + "\n\nQuestion: " + finalQuestion;

        isProcessing.set(true);
        setStatus(true, "Analyzing");

        new Thread(() -> {
            try {
                String answer = callAIService(systemPrompt, userPrompt);
                if (!isProcessing.get()) return;

                SwingUtilities.invokeLater(() -> {
                    IHttpRequestResponse current = getSelectedRequest();
                    if (current != boundRequest) {
                        StringBuilder sb = analysisHistory.computeIfAbsent(boundRequest, k -> new StringBuilder());
                        sb.append("[VISTA] ").append(answer).append("\n\n");
                        appendChat("INFO", "(Response saved to original request's history)");
                    } else {
                        appendChat("VISTA", answer);
                    }
                });
            } catch (Exception ex) {
                if (isProcessing.get()) {
                    callbacks.printError("AI error: " + ex);
                    SwingUtilities.invokeLater(() -> appendChat("ERROR", "AI Error: " + ex.getMessage()));
                }
            } finally {
                isProcessing.set(false);
                SwingUtilities.invokeLater(() -> setStatus(false, "Ready"));
            }
        }, "VISTA-AI").start();
    }

    private String buildSystemPrompt() {
        String base = """
            You are VISTA (Vulnerability Insight & Strategic Test Assistant), an expert security testing assistant for Burp Suite.
            
            ROLE: Help authorized penetration testers identify and exploit vulnerabilities.
            
            GUIDELINES:
            - Be concise and actionable
            - Provide specific payloads adapted to the request context
            - Include verification steps (what to look for in response)
            - Suggest Burp tools (Repeater, Intruder, Collaborator) when relevant
            - Prioritize high-impact, likely vulnerabilities first
            - Include safe/non-destructive test variants when possible
            
            FORMAT your responses with:
            - Clear headers for each test/finding
            - Specific payloads in code blocks
            - Expected behavior/indicators
            - Risk level (Critical/High/Medium/Low)
            """;

        String preset = (String) presetCombo.getSelectedItem();
        if (preset != null && !preset.equals("Auto-detect")) {
            String template = VulnerabilityTemplates.getTemplate(preset);
            if (template != null) {
                base += "\n\nFOCUS AREA: " + preset + "\n" + template;
            }
        }

        return augmentWithCustomTemplates(base);
    }

    private String augmentWithCustomTemplates(String systemPrompt) {
        List<String> selected = templatesList.getSelectedValuesList();
        if (selected == null || selected.isEmpty()) return systemPrompt;

        StringBuilder sb = new StringBuilder(systemPrompt);
        sb.append("\n\nCUSTOM PLAYBOOKS:\n");
        int budget = 4000;

        for (String name : selected) {
            String content = customTemplates.get(name);
            if (content == null) continue;
            String trimmed = content.length() > 1200 ? content.substring(0, 1200) + "\n...[truncated]" : content;
            if (budget - trimmed.length() < 0) break;
            budget -= trimmed.length();
            sb.append("\n--- ").append(name).append(" ---\n").append(trimmed).append("\n");
        }

        return sb.toString();
    }

    private String callAIService(String systemPrompt, String userPrompt) throws Exception {
        String provider = (String) providerCombo.getSelectedItem();
        double temperature = temperatureSlider.getValue() / 100.0;

        if ("OpenAI".equals(provider)) {
            OpenAIService.Configuration config = new OpenAIService.Configuration();
            config.setModel(getText(openAiModelField));
            config.setApiKey(new String(apiKeyField.getPassword()));
            config.setBaseUrl(getText(openAiBaseUrlField));
            config.setTemperature(temperature);

            if (!config.isValid()) {
                throw new RuntimeException("OpenAI configuration incomplete. Check model and API key.");
            }

            return new OpenAIService(config).ask(systemPrompt, userPrompt);
        } else {
            AzureAIService.Configuration config = new AzureAIService.Configuration();
            config.setEndpoint(getText(endpointField));
            config.setDeploymentName(getText(deploymentField));
            config.setApiVersion(getText(apiVersionField));
            config.setApiKey(new String(apiKeyField.getPassword()));
            config.setTemperature(temperature);

            String validationError = config.getValidationError();
            if (validationError != null) {
                throw new RuntimeException(validationError);
            }

            return new AzureAIService(config).ask(systemPrompt, userPrompt);
        }
    }

    private void testConnection() {
        setStatus(true, "Testing");

        new Thread(() -> {
            try {
                String provider = (String) providerCombo.getSelectedItem();
                String result;

                if ("OpenAI".equals(provider)) {
                    OpenAIService.Configuration config = new OpenAIService.Configuration();
                    config.setModel(getText(openAiModelField));
                    config.setApiKey(new String(apiKeyField.getPassword()));
                    config.setBaseUrl(getText(openAiBaseUrlField));
                    result = new OpenAIService(config).testConnection();
                } else {
                    AzureAIService.Configuration config = new AzureAIService.Configuration();
                    config.setEndpoint(getText(endpointField));
                    config.setDeploymentName(getText(deploymentField));
                    config.setApiVersion(getText(apiVersionField));
                    config.setApiKey(new String(apiKeyField.getPassword()));
                    result = new AzureAIService(config).testConnection();
                }

                SwingUtilities.invokeLater(() -> appendChat("VISTA", "Connection test: " + result));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> appendChat("ERROR", "Test failed: " + ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> setStatus(false, "Ready"));
            }
        }, "VISTA-Test").start();
    }

    // ==================== Quick Actions ====================

    private void autoAnalyze() {
        if (getSelectedRequest() == null) {
            appendChat("VISTA", "Select a request first.");
            return;
        }
        questionField.setText("Perform a comprehensive security analysis. Identify input vectors, potential vulnerabilities (ranked by likelihood), specific test payloads, and verification steps.");
        submitQuestion();
    }

    private void extractParameters() {
        if (currentRequest == null) {
            appendChat("VISTA", "Select a request first.");
            return;
        }
        String params = ParameterAnalyzer.extractDetailed(helpers, currentRequest);
        parametersArea.setText(params);
        appendChat("INFO", "Parameters extracted. See Parameters tab.");
    }

    private void analyzeSessionDetails() {
        if (currentRequest == null) {
            appendChat("VISTA", "Select a request first.");
            return;
        }
        
        SessionAnalyzer.SessionInfo info = SessionAnalyzer.analyze(helpers, currentRequest);
        sessionArea.setText(info.summary);
        sessionArea.setCaretPosition(0);
        
        // Also add to chat for visibility
        StringBuilder chatMsg = new StringBuilder("Session Analysis Complete:\n");
        chatMsg.append("• ").append(info.cookies.size()).append(" session cookie(s) detected\n");
        chatMsg.append("• ").append(info.authHeaders.size()).append(" auth header(s) detected\n");
        if (!info.securityIssues.isEmpty()) {
            chatMsg.append("• ⚠️ ").append(info.securityIssues.size()).append(" security issue(s) found\n");
        }
        chatMsg.append("\nSee Session tab for details.");
        appendChat("INFO", chatMsg.toString());
    }

    private void analyzeReflectionDetails() {
        if (currentRequest == null) {
            appendChat("VISTA", "Select a request first.");
            return;
        }
        
        ReflectionAnalyzer.ReflectionResult result = ReflectionAnalyzer.analyze(helpers, currentRequest);
        reflectionArea.setText(result.summary);
        reflectionArea.setCaretPosition(0);
        
        // Also add to chat for visibility
        StringBuilder chatMsg = new StringBuilder("Reflection Analysis Complete:\n");
        if (result.hasReflections()) {
            chatMsg.append("• ").append(result.totalReflections).append(" reflection(s) found in ");
            chatMsg.append(result.reflections.size()).append(" parameter(s)\n");
            
            // Count by risk level
            int critical = 0, high = 0, medium = 0;
            for (ReflectionAnalyzer.ReflectedParameter rp : result.reflections) {
                switch (rp.risk) {
                    case CRITICAL -> critical++;
                    case HIGH -> high++;
                    case MEDIUM -> medium++;
                }
            }
            if (critical > 0) chatMsg.append("• 🔴 ").append(critical).append(" CRITICAL risk\n");
            if (high > 0) chatMsg.append("• 🟠 ").append(high).append(" HIGH risk\n");
            if (medium > 0) chatMsg.append("• 🟡 ").append(medium).append(" MEDIUM risk\n");
        } else {
            chatMsg.append("• No parameter reflections detected");
        }
        chatMsg.append("\nSee Reflections tab for details.");
        appendChat("INFO", chatMsg.toString());
    }

    private void addFinding() {
        if (currentRequest == null) {
            appendChat("VISTA", "Select a request first.");
            return;
        }

        String title = JOptionPane.showInputDialog(rootPanel, "Finding title:", "Add Finding", JOptionPane.PLAIN_MESSAGE);
        if (title == null || title.isBlank()) return;

        String severity = (String) JOptionPane.showInputDialog(rootPanel, "Severity:", "Add Finding",
            JOptionPane.PLAIN_MESSAGE, null, new String[]{"Critical", "High", "Medium", "Low", "Info"}, "Medium");
        if (severity == null) return;

        String description = JOptionPane.showInputDialog(rootPanel, "Description (optional):", "Add Finding", JOptionPane.PLAIN_MESSAGE);

        String finding = "[" + severity + "] " + title + (description != null && !description.isBlank() ? " - " + description : "");

        List<String> requestFindings = findings.computeIfAbsent(currentRequest, k -> new ArrayList<>());
        requestFindings.add(finding);
        updateFindingsList();

        appendChat("INFO", "Finding added: " + finding);
        persistState();
    }

    private void updateFindingsList() {
        findingsListModel.clear();
        if (currentRequest != null) {
            List<String> requestFindings = findings.get(currentRequest);
            if (requestFindings != null) {
                for (String f : requestFindings) {
                    findingsListModel.addElement(f);
                }
            }
        }
    }

    private void viewSelectedFinding() {
        String selected = findingsList.getSelectedValue();
        if (selected != null) {
            JOptionPane.showMessageDialog(rootPanel, selected, "Finding Details", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void removeSelectedFinding() {
        int idx = findingsList.getSelectedIndex();
        if (idx < 0 || currentRequest == null) return;

        List<String> requestFindings = findings.get(currentRequest);
        if (requestFindings != null && idx < requestFindings.size()) {
            requestFindings.remove(idx);
            updateFindingsList();
            persistState();
        }
    }

    private void exportReport() {
        if (requests.isEmpty()) {
            appendChat("VISTA", "No requests to export.");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("vista-report.md"));
        if (chooser.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        try {
            String report = ReportGenerator.generateMarkdownReport(helpers, requests, analysisHistory, findings);
            java.nio.file.Files.writeString(file.toPath(), report);
            appendChat("INFO", "Report exported to: " + file.getAbsolutePath());
        } catch (Exception ex) {
            appendChat("ERROR", "Export failed: " + ex.getMessage());
        }
    }

    // ==================== Payload Library ====================

    private void loadDefaultPayloads() {
        Map<String, List<String>> allPayloads = PayloadLibrary.getAllPayloads();
        for (Map.Entry<String, List<String>> entry : allPayloads.entrySet()) {
            String category = entry.getKey();
            for (int i = 0; i < Math.min(2, entry.getValue().size()); i++) {
                String payload = entry.getValue().get(i);
                String key = category + " " + (i + 1);
                savedPayloads.put(key, payload);
                String display = key + ": " + (payload.length() > 25 ? payload.substring(0, 25) + "..." : payload);
                payloadListModel.addElement(display);
            }
        }
    }

    private void copySelectedPayload() {
        int idx = payloadList.getSelectedIndex();
        if (idx < 0) return;

        String display = payloadListModel.get(idx);
        String key = display.split(":")[0].trim();
        String payload = savedPayloads.get(key);
        if (payload != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(payload), null);
            statusLabel.setText("Copied: " + key);
        }
    }

    private void addCustomPayload() {
        String name = JOptionPane.showInputDialog(rootPanel, "Payload name:", "Add Payload", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.isBlank()) return;

        String payload = JOptionPane.showInputDialog(rootPanel, "Payload value:", "Add Payload", JOptionPane.PLAIN_MESSAGE);
        if (payload == null || payload.isBlank()) return;

        savedPayloads.put(name, payload);
        String display = name + ": " + (payload.length() > 25 ? payload.substring(0, 25) + "..." : payload);
        payloadListModel.addElement(display);
        persistState();
    }

    // ==================== Chat Management ====================

    private void appendChat(String speaker, String text) {
        if (speaker == null) speaker = "?";
        if (text == null) text = "";

        String line = "[" + speaker + "] " + text + "\n\n";

        if (currentRequest != null) {
            StringBuilder sb = analysisHistory.computeIfAbsent(currentRequest, k -> new StringBuilder());
            sb.append(line);
            renderChat(sb.toString());
        } else {
            globalChat.append(line);
            renderChat(globalChat.toString());
        }
        persistState();
    }

    private void renderChat(String content) {
        StyledDocument doc = chatPane.getStyledDocument();
        try { doc.remove(0, doc.getLength()); } catch (BadLocationException ignored) {}

        SimpleAttributeSet bodyStyle = new SimpleAttributeSet();
        StyleConstants.setForeground(bodyStyle, chatPane.getForeground());

        String[] blocks = content.split("\n\n");
        try {
            for (String block : blocks) {
                if (block == null || block.isBlank()) continue;

                int bracketIdx = block.indexOf(']');
                if (block.startsWith("[") && bracketIdx > 1) {
                    String tag = block.substring(0, bracketIdx + 1);
                    String speaker = tag.substring(1, tag.length() - 1);
                    String rest = block.substring(bracketIdx + 1).trim();

                    SimpleAttributeSet speakerStyle = getSpeakerStyle(speaker);
                    doc.insertString(doc.getLength(), tag + " ", speakerStyle);
                    renderFormattedText(doc, rest, bodyStyle);
                    doc.insertString(doc.getLength(), "\n\n", bodyStyle);
                } else {
                    doc.insertString(doc.getLength(), block + "\n\n", bodyStyle);
                }
            }
        } catch (BadLocationException ignored) {}

        chatPane.setCaretPosition(chatPane.getDocument().getLength());
    }

    private void renderFormattedText(StyledDocument doc, String text, SimpleAttributeSet bodyStyle) throws BadLocationException {
        SimpleAttributeSet codeStyle = new SimpleAttributeSet();
        StyleConstants.setFontFamily(codeStyle, Font.MONOSPACED);
        StyleConstants.setBackground(codeStyle, new Color(240, 240, 240));
        StyleConstants.setForeground(codeStyle, new Color(50, 50, 50));

        String[] parts = text.split("```");
        boolean inCode = false;
        for (String part : parts) {
            if (inCode) {
                String code = part;
                int newline = code.indexOf('\n');
                if (newline > 0 && newline < 20) {
                    code = code.substring(newline + 1);
                }
                doc.insertString(doc.getLength(), code, codeStyle);
            } else {
                doc.insertString(doc.getLength(), part, bodyStyle);
            }
            inCode = !inCode;
        }
    }

    private SimpleAttributeSet getSpeakerStyle(String speaker) {
        String key = speaker == null ? "" : speaker.trim().toUpperCase();
        Color color = switch (key) {
            case "VISTA" -> new Color(180, 0, 0);
            case "YOU" -> new Color(0, 70, 170);
            case "INFO" -> new Color(0, 120, 0);
            case "ERROR" -> new Color(200, 0, 0);
            case "SYSTEM" -> Color.DARK_GRAY;
            default -> new Color(100, 0, 100);
        };

        SimpleAttributeSet style = new SimpleAttributeSet();
        StyleConstants.setBold(style, true);
        StyleConstants.setForeground(style, color);
        return style;
    }

    private void clearCurrentChat() {
        if (currentRequest != null) {
            analysisHistory.put(currentRequest, new StringBuilder());
            renderChat("");
        } else {
            globalChat.setLength(0);
            renderChat("");
        }
        persistState();
    }

    private void copyChat() {
        String text = currentRequest != null 
            ? analysisHistory.getOrDefault(currentRequest, new StringBuilder()).toString() 
            : globalChat.toString();
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        statusLabel.setText("Chat copied to clipboard");
    }

    private String getQuickQuestionPrompt(String label) {
        return switch (label) {
            case "Suggest Tests" -> "Analyze this request and suggest the top 5 most likely security tests with specific payloads.";
            case "Find Vulnerabilities" -> "Identify potential vulnerabilities in this request/response. Focus on high-impact issues.";
            case "Generate Payloads" -> "Generate specific attack payloads for each parameter in this request.";
            case "Explain Response" -> "Explain what this response reveals about the application's behavior and potential weaknesses.";
            case "Bypass Ideas" -> "Suggest bypass techniques for any security controls visible in this request/response.";
            default -> label;
        };
    }

    // ==================== UI Helpers ====================

    private void setStatus(boolean busy, String status) {
        progressBar.setVisible(busy);
        progressBar.setIndeterminate(busy);
        statusLabel.setText(status + (busy ? "..." : ""));

        if (busy && !animationTimer.isRunning()) {
            animationTimer.start();
        } else if (!busy && animationTimer.isRunning()) {
            animationTimer.stop();
        }
    }

    private void animateStatus() {
        animationDotCount = (animationDotCount + 1) % 4;
        String base = statusLabel.getText();
        int removed = 0;
        while (base.endsWith(".") && removed < 3) {
            base = base.substring(0, base.length() - 1);
            removed++;
        }
        statusLabel.setText(base + ".".repeat(animationDotCount));
    }

    private void updateProviderVisibility() {
        boolean isAzure = !"OpenAI".equals(providerCombo.getSelectedItem());
        endpointField.setEnabled(isAzure);
        deploymentField.setEnabled(isAzure);
        apiVersionField.setEnabled(isAzure);
        openAiModelField.setEnabled(!isAzure);
        openAiBaseUrlField.setEnabled(!isAzure);
    }

    private void loadCustomTemplates() {
        String dir = templatesDirField.getText().trim();
        if (dir.isEmpty()) {
            appendChat("VISTA", "Enter a templates directory path.");
            return;
        }

        File folder = new File(dir);
        if (!folder.exists() || !folder.isDirectory()) {
            appendChat("ERROR", "Directory not found: " + dir);
            return;
        }

        File[] files = folder.listFiles((d, name) ->
            name.toLowerCase().endsWith(".jinja") ||
            name.toLowerCase().endsWith(".txt") ||
            name.toLowerCase().endsWith(".md"));

        if (files == null || files.length == 0) {
            appendChat("VISTA", "No template files found in: " + dir);
            return;
        }

        customTemplates.clear();
        templatesModel.clear();

        for (File f : files) {
            try {
                String content = java.nio.file.Files.readString(f.toPath());
                customTemplates.put(f.getName(), content);
                templatesModel.addElement(f.getName());
            } catch (Exception ex) {
                callbacks.printError("Failed to read: " + f + " - " + ex);
            }
        }

        appendChat("INFO", "Loaded " + customTemplates.size() + " template(s)");
        persistState();
    }

    private static String getText(JTextField field) {
        return field.getText().trim();
    }

    // ==================== Persistence ====================

    private File getStateFile() {
        return new File(System.getProperty("user.home", "."), ".vista-config.json");
    }

    private void persistState() {
        new Thread(() -> {
            try (FileWriter fw = new FileWriter(getStateFile())) {
                StringBuilder sb = new StringBuilder();
                sb.append("{\n");
                sb.append("  \"provider\": \"").append(escape((String) providerCombo.getSelectedItem())).append("\",\n");
                sb.append("  \"endpoint\": \"").append(escape(getText(endpointField))).append("\",\n");
                sb.append("  \"deployment\": \"").append(escape(getText(deploymentField))).append("\",\n");
                sb.append("  \"apiVersion\": \"").append(escape(getText(apiVersionField))).append("\",\n");
                sb.append("  \"openAiModel\": \"").append(escape(getText(openAiModelField))).append("\",\n");
                sb.append("  \"openAiBaseUrl\": \"").append(escape(getText(openAiBaseUrlField))).append("\",\n");
                sb.append("  \"stripHeaders\": ").append(stripHeadersCheckbox.isSelected()).append(",\n");
                sb.append("  \"maxChars\": ").append((Integer) maxCharsSpinner.getValue()).append(",\n");
                sb.append("  \"temperature\": ").append(temperatureSlider.getValue()).append(",\n");
                sb.append("  \"preset\": \"").append(escape((String) presetCombo.getSelectedItem())).append("\",\n");
                sb.append("  \"templatesDir\": \"").append(escape(getText(templatesDirField))).append("\",\n");
                sb.append("  \"globalChat\": \"").append(escape(globalChat.toString())).append("\"\n");
                sb.append("}");
                fw.write(sb.toString());
            } catch (Exception ex) {
                callbacks.printError("Failed to save state: " + ex);
            }
        }, "VISTA-Persist").start();
    }

    private void loadPersistedState() {
        File stateFile = getStateFile();
        
        // Migrate from old file name
        File oldFile = new File(System.getProperty("user.home", "."), ".vista.json");
        if (!stateFile.exists() && oldFile.exists()) {
            oldFile.renameTo(stateFile);
        }
        
        if (!stateFile.exists()) return;

        try {
            String json = java.nio.file.Files.readString(stateFile.toPath());

            String provider = extractJsonValue(json, "provider");
            if (provider != null) providerCombo.setSelectedItem(provider);

            String endpoint = extractJsonValue(json, "endpoint");
            if (endpoint != null && !endpoint.isBlank()) endpointField.setText(endpoint);

            String deployment = extractJsonValue(json, "deployment");
            if (deployment != null && !deployment.isBlank()) deploymentField.setText(deployment);

            String apiVersion = extractJsonValue(json, "apiVersion");
            if (apiVersion != null && !apiVersion.isBlank()) apiVersionField.setText(apiVersion);

            String openAiModel = extractJsonValue(json, "openAiModel");
            if (openAiModel != null && !openAiModel.isBlank()) openAiModelField.setText(openAiModel);

            String openAiBaseUrl = extractJsonValue(json, "openAiBaseUrl");
            if (openAiBaseUrl != null && !openAiBaseUrl.isBlank()) openAiBaseUrlField.setText(openAiBaseUrl);

            String stripHeaders = extractJsonValue(json, "stripHeaders");
            if ("true".equals(stripHeaders) || "false".equals(stripHeaders)) {
                stripHeadersCheckbox.setSelected(Boolean.parseBoolean(stripHeaders));
            }

            String maxChars = extractJsonValue(json, "maxChars");
            if (maxChars != null) {
                try { maxCharsSpinner.setValue(Integer.parseInt(maxChars)); } catch (NumberFormatException ignored) {}
            }

            String temp = extractJsonValue(json, "temperature");
            if (temp != null) {
                try { temperatureSlider.setValue(Integer.parseInt(temp)); } catch (NumberFormatException ignored) {}
            }

            String preset = extractJsonValue(json, "preset");
            if (preset != null) presetCombo.setSelectedItem(preset);

            String templatesDir = extractJsonValue(json, "templatesDir");
            if (templatesDir != null && !templatesDir.isBlank()) templatesDirField.setText(templatesDir);

            String chat = extractJsonValue(json, "globalChat");
            if (chat != null) {
                globalChat.setLength(0);
                globalChat.append(unescape(chat));
                renderChat(globalChat.toString());
            }
        } catch (Exception ex) {
            callbacks.printError("Failed to load state: " + ex);
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String unescape(String s) {
        return s.replace("\\n", "\n").replace("\\r", "\r").replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;

        int start = idx + pattern.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length()) return null;

        if (json.charAt(start) == '"') {
            start++;
            StringBuilder sb = new StringBuilder();
            boolean escaped = false;
            for (int i = start; i < json.length(); i++) {
                char c = json.charAt(i);
                if (escaped) {
                    sb.append(c);
                    escaped = false;
                } else if (c == '\\') {
                    sb.append(c);
                    escaped = true;
                } else if (c == '"') {
                    break;
                } else {
                    sb.append(c);
                }
            }
            return unescape(sb.toString());
        } else {
            int end = start;
            while (end < json.length() && ",}\n\r".indexOf(json.charAt(end)) == -1) end++;
            return json.substring(start, end).trim();
        }
    }

    // ==================== Placeholder Support ====================

    private static void installPlaceholder(JTextField field, String placeholder) {
        Color hintColor = new Color(150, 150, 150);
        Color normalColor = field.getForeground();

        if (field.getText() == null || field.getText().isBlank()) {
            field.setForeground(hintColor);
            field.setText(placeholder);
        }

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

    private static void installPlaceholder(JPasswordField field, String placeholder) {
        Color hintColor = new Color(150, 150, 150);
        Color normalColor = field.getForeground();
        char echoChar = field.getEchoChar();

        if (field.getPassword().length == 0) {
            field.setForeground(hintColor);
            field.setEchoChar((char) 0);
            field.setText(placeholder);
        }

        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (field.getForeground().equals(hintColor)) {
                    field.setText("");
                    field.setEchoChar(echoChar);
                    field.setForeground(normalColor);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (new String(field.getPassword()).isBlank()) {
                    field.setForeground(hintColor);
                    field.setEchoChar((char) 0);
                    field.setText(placeholder);
                }
            }
        });
    }
}
