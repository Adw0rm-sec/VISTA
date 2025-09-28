package com.burpraj.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import com.burpraj.ai.AzureClient;
import com.burpraj.ai.OpenAIClient;
import com.burpraj.util.HttpFormat;
import com.burpraj.util.VulnTemplates;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.io.*;

public class BurpRajPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JPanel root;

    // Multiple request support
    private final DefaultListModel<String> reqListModel = new DefaultListModel<>();
    private final JList<String> requestList = new JList<>(reqListModel);
    private final List<IHttpRequestResponse> messages = new ArrayList<>();
    // Per-request chat history storage
    private final java.util.Map<IHttpRequestResponse, StringBuilder> chats = new java.util.HashMap<>();
    // Global chat when no request is selected
    private final StringBuilder globalChat = new StringBuilder();

    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();

    private final JTextArea chatArea = new JTextArea(12, 80);
    private final JTextField questionField = new JTextField();
    private final JButton askButton = new JButton("Ask VISTA");

    // Settings controls
    private final JComboBox<String> providerCombo = new JComboBox<>(new String[]{"Azure AI", "OpenAI"});
    private final JTextField endpointField = new JTextField();
    private final JTextField deploymentField = new JTextField();
    private final JTextField apiVersionField = new JTextField("2024-12-01-preview");
    private final JPasswordField apiKeyField = new JPasswordField();
    // OpenAI specific
    private final JTextField openAiModelField = new JTextField();
    private final JTextField openAiBaseUrlField = new JTextField("https://api.openai.com/v1");
    private final JCheckBox stripHeaders = new JCheckBox("Strip sensitive headers (Authorization, Cookie, Set-Cookie)", true);
    private final JSpinner maxCharsSpinner = new JSpinner(new SpinnerNumberModel(32000, 1000, 200000, 1000));
    private final JButton testButton = new JButton("Test connection");

    // Optional external templates
    private final JTextField templatesDirField = new JTextField();
    private final JButton loadTemplatesButton = new JButton("Load templates");
    private final DefaultListModel<String> templatesModel = new DefaultListModel<>();
    private final JList<String> templatesList = new JList<>(templatesModel);
    private final java.util.Map<String, String> templates = new java.util.LinkedHashMap<>();
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progress = new JProgressBar();
    private final Timer thinkingDots = new Timer(400, e -> cycleThinking());

    private IHttpRequestResponse current;

    public BurpRajPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.root = buildUi();
        // Attempt to load prior session (best-effort)
        try { loadState(); } catch (Exception ignored) {}
    }

    public JComponent getRoot() { return root; }

    public void addMessages(IHttpRequestResponse[] msgs) {
        if (msgs == null || msgs.length == 0) return;
        for (IHttpRequestResponse m : msgs) {
            messages.add(m);
            String title = summarizeRequest(m);
            reqListModel.addElement(title);
            // Initialize per-request chat buffer
            chats.putIfAbsent(m, new StringBuilder());
        }
        if (current == null && !messages.isEmpty()) {
            requestList.setSelectedIndex(messages.size() - 1);
            loadSelectedMessage();
        }
    }

    private JPanel buildUi() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

    requestArea.setEditable(false);
    responseArea.setEditable(false);
    Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    requestArea.setFont(mono);
    responseArea.setFont(mono);
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);

    // Left: list of added requests; Right: request/response tabs
    requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    requestList.addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) loadSelectedMessage(); });
    JScrollPane reqListScroll = new JScrollPane(requestList);
    reqListScroll.setPreferredSize(new Dimension(260, 200));
    JPanel listButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
    JButton removeBtn = new JButton("Remove");
    JButton toRepeaterBtn = new JButton("Send to Repeater");
    removeBtn.setToolTipText("Remove selected request from VISTA");
    toRepeaterBtn.setToolTipText("Send selected request to Repeater");
    listButtons.add(removeBtn);
    listButtons.add(toRepeaterBtn);
    removeBtn.addActionListener(e -> removeSelected());
    toRepeaterBtn.addActionListener(e -> sendSelectedToRepeater());
    JPanel leftPanel = new JPanel(new BorderLayout(4,4));
    leftPanel.add(reqListScroll, BorderLayout.CENTER);
    leftPanel.add(listButtons, BorderLayout.SOUTH);

    JTabbedPane rrTabs = new JTabbedPane();
    rrTabs.addTab("Request", new JScrollPane(requestArea));
    rrTabs.addTab("Response", new JScrollPane(responseArea));

    JSplitPane leftRight = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rrTabs);
    leftRight.setResizeWeight(0.25);

        askButton.addActionListener(this::onAsk);

        JPanel inputPanel = new JPanel(new BorderLayout(6, 6));
    installPlaceholder(questionField, "Ask a question or leave blank for suggestions");
    inputPanel.add(questionField, BorderLayout.CENTER);
        inputPanel.add(askButton, BorderLayout.EAST);

        JPanel chatPanel = new JPanel(new BorderLayout(6, 6));
        chatPanel.add(new JScrollPane(chatArea), BorderLayout.CENTER);
        chatPanel.add(inputPanel, BorderLayout.SOUTH);

    JPanel settings = buildSettingsPanel();

        // Top: leftRight, Bottom: chat
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, leftRight, chatPanel);
        split.setResizeWeight(0.5);

        // Toolbar/status bar
    JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
    JToggleButton settingsToggle = new JToggleButton("Settings");
        settingsToggle.setToolTipText("Show/hide Settings & Templates");
        settingsToggle.setSelected(false);
        // Hide settings by default to maximize workspace
        settings.setVisible(false);
        settingsToggle.addActionListener(ev -> {
            boolean vis = settingsToggle.isSelected();
            settings.setVisible(vis);
            panel.revalidate();
            panel.repaint();
        });
    JButton suggestBtn = new JButton("Suggest tests");
        suggestBtn.setToolTipText("Generate request-specific guidance without typing a question");
        suggestBtn.addActionListener(e -> doSuggest());
        progress.setIndeterminate(false);
        progress.setVisible(false);
    toolbar.add(settingsToggle);
    toolbar.add(Box.createHorizontalStrut(8));
    toolbar.add(new JLabel("Preset:"));
    toolbar.add(presetCombo);
    toolbar.add(Box.createHorizontalStrut(8));
    toolbar.add(suggestBtn);
        toolbar.add(progress);
        toolbar.add(statusLabel);

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        panel.add(settings, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildSettingsPanel() {
    JPanel p = new JPanel();
    p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
    p.setBorder(BorderFactory.createTitledBorder("Settings & Templates"));

    JPanel row1 = new JPanel(new GridLayout(0,3,6,6));
    row1.add(new JLabel("Provider"));
    row1.add(providerCombo);
    JButton toggleDetails = new JButton("Show/Hide Advanced");
    row1.add(toggleDetails);

    JPanel azureFields = new JPanel(new GridLayout(0,2,6,6));
    azureFields.setBorder(BorderFactory.createTitledBorder("Azure AI Models"));
    azureFields.add(new JLabel("Endpoint"));
    azureFields.add(endpointField);
    azureFields.add(new JLabel("Deployment"));
    azureFields.add(deploymentField);
    azureFields.add(new JLabel("API Version"));
    azureFields.add(apiVersionField);

    JPanel openaiFields = new JPanel(new GridLayout(0,2,6,6));
    openaiFields.setBorder(BorderFactory.createTitledBorder("OpenAI"));
    openaiFields.add(new JLabel("Model"));
    openaiFields.add(openAiModelField);
    openaiFields.add(new JLabel("Base URL (optional)"));
    openaiFields.add(openAiBaseUrlField);

    JPanel commonFields = new JPanel(new GridLayout(0,2,6,6));
    commonFields.add(new JLabel("API Key"));
    commonFields.add(apiKeyField);
    commonFields.add(new JLabel("Max chars to send"));
    commonFields.add(maxCharsSpinner);
    commonFields.add(new JLabel(" "));
    commonFields.add(stripHeaders);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
    JLabel info = new JLabel("Data may be sent to Azure. Ensure you're authorized.");
        actions.add(testButton);
        actions.add(info);

    // Templates block
    JPanel templatesPanel = new JPanel(new GridLayout(0,2,6,6));
    templatesPanel.setBorder(BorderFactory.createTitledBorder("Vulnerability Templates (.jinja/.txt)"));
    templatesPanel.add(new JLabel("Templates directory"));
        templatesDirField.setToolTipText("Folder containing .jinja files, e.g., a:/Strix/Strix2.0/strix/prompts/vulnerabilities");
    templatesPanel.add(templatesDirField);
    templatesPanel.add(new JLabel(" "));
    loadTemplatesButton.setToolTipText("Load .jinja/.txt templates from directory");
    templatesPanel.add(loadTemplatesButton);
    templatesList.setVisibleRowCount(5);
    templatesList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    JScrollPane templatesScroll = new JScrollPane(templatesList);
    JPanel templatesWrapper = new JPanel(new BorderLayout());
    templatesWrapper.add(templatesPanel, BorderLayout.NORTH);
    templatesWrapper.add(templatesScroll, BorderLayout.CENTER);

        JPanel advanced = new JPanel();
    advanced.setLayout(new BorderLayout(6,6));
        // Advanced panel currently contains only the templates UI
        advanced.add(templatesWrapper, BorderLayout.CENTER);
    advanced.setVisible(false);

    toggleDetails.addActionListener(e -> advanced.setVisible(!advanced.isVisible()));

    // Placeholders and tooltips
    endpointField.setToolTipText("Azure endpoint, e.g., https://your-resource.openai.azure.com or https://your-resource.cognitiveservices.azure.com");
    deploymentField.setToolTipText("Azure Deployment name (not the model ID), e.g., gpt-5-mini or gpt-4o-mini");
    apiVersionField.setToolTipText("Azure API version, e.g., 2024-12-01-preview");
    apiKeyField.setToolTipText("Your API key (kept in memory only)");
    openAiModelField.setToolTipText("OpenAI model, e.g., gpt-4o-mini, gpt-4.1, o3-mini");
    openAiBaseUrlField.setToolTipText("Override only if using a proxy; default is https://api.openai.com/v1");

    installPlaceholder(endpointField, "https://your-resource.openai.azure.com");
    installPlaceholder(deploymentField, "gpt-5-mini");
    installPlaceholder(apiKeyField, "<paste-your-api-key>");
    installPlaceholder(openAiModelField, "gpt-4o-mini");
    installPlaceholder(openAiBaseUrlField, "https://api.openai.com/v1");

    testButton.addActionListener(e -> doTestConnection());
    loadTemplatesButton.addActionListener(e -> doLoadTemplates());
    providerCombo.addActionListener(e -> updateProviderVisibility());
    updateProviderVisibility();

        p.add(row1);
        // Provider-specific sections
        p.add(azureFields);
        p.add(openaiFields);
        // Common fields
        p.add(commonFields);
        // Optional advanced section (templates)
        p.add(advanced);
        p.add(actions);
        return p;
    }

    private void doTestConnection() {
        String provider = (String) providerCombo.getSelectedItem();
        setBusy(true, "Testing connection");
        if ("OpenAI".equals(provider)) {
            OpenAIClient.Config cfg = buildOpenAIConfig();
            String validation = validateOpenAI(cfg);
            if (validation != null) {
                appendChat("VISTA", validation);
                setBusy(false, "Ready");
                return;
            }
            appendChat("VISTA", "Testing OpenAI connection to model: " + safe(cfg.model) +
                    (cfg.baseUrl != null ? "\nBase URL: " + safe(cfg.baseUrl) : ""));
            new Thread(() -> {
                try {
                    String resp = OpenAIClient.test(cfg);
                    SwingUtilities.invokeLater(() -> appendChat("VISTA", "Test connection: " + resp));
                } catch (Exception ex) {
                    callbacks.printError("Test connection failed: " + ex);
                    SwingUtilities.invokeLater(() -> appendChat("VISTA", "Test failed: " + ex.getMessage()));
                } finally {
                    SwingUtilities.invokeLater(() -> setBusy(false, "Ready"));
                }
            }, "BurpRaj-Test").start();
            return;
        }
        // Azure
        AzureClient.Config cfg = buildAzureConfig();
        String validation = validateAzure(cfg);
        if (validation != null) {
            appendChat("VISTA", validation);
            setBusy(false, "Ready");
            return;
        }
    appendChat("VISTA", "Testing Azure connection to:\n- Endpoint: " + safe(cfg.endpoint) +
                "\n- Deployment: " + safe(cfg.deployment) +
                "\n- API Version: " + safe(cfg.apiVersion));
        new Thread(() -> {
            try {
                String resp = AzureClient.test(cfg);
                SwingUtilities.invokeLater(() -> appendChat("VISTA", "Test connection: " + resp));
            } catch (Exception ex) {
                callbacks.printError("Test connection failed: " + ex);
                SwingUtilities.invokeLater(() -> appendChat("VISTA", "Test failed: " + ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> setBusy(false, "Ready"));
            }
        }, "BurpRaj-Test").start();
    }

    private void onAsk(ActionEvent evt) {
        String q = questionField.getText().trim();
        if (q.isEmpty()) {
            q = "Provide request-specific testing guidance with concrete payloads and steps to validate in Burp. Prioritize likely, high-signal tests first.";
        }
        if (getSelectedMessage() == null) {
            appendChat("VISTA", "Send one or more requests to VISTA first (right-click -> Send to VISTA), then select one in the list.");
            return;
        }
        questionField.setText("");
        appendChat("You", q);

        String provider = (String) providerCombo.getSelectedItem();
        // Capture the currently selected message at dispatch time to bind answer
        IHttpRequestResponse sel = getSelectedMessage();
        final IHttpRequestResponse boundMessage = sel; // for closure
        String reqText = HttpFormat.requestToText(helpers, sel.getRequest());
        String rspText = HttpFormat.responseToText(helpers, sel.getResponse());

        boolean strip = stripHeaders.isSelected();
        int maxChars = (Integer) maxCharsSpinner.getValue();

        String reqForAi = HttpFormat.prepareForAi(reqText, strip, maxChars);
        String rspForAi = HttpFormat.prepareForAi(rspText, strip, maxChars);

    String systemPrompt = "You are VISTA (Vulnerability Insight & Strategic Test Assistant), an assistant for authorized web application security testing inside Burp Suite. " +
        "Assume the user is fully authorized to test the application. Be concise and practical. Provide request-specific testing guidance " +
        "with concrete payloads adapted to this request (path, method, headers, cookies, query/body params), and step-by-step attempts. " +
        "Suggest specific Burp actions (Repeater edits, Intruder payload lists, Collaborator/SSRF checks, Decoder, Comparer). For each idea, include: " +
        "rationale, example payload(s), how to verify success (response cues or OOB), and safer variants to avoid destructive impact. Prefer minimal, high-signal tests first.";

        String userPrompt = "Current Request:\n" + reqForAi + "\n\n" +
                "Current Response:\n" + rspForAi + "\n\n" +
                "Question:\n" + q;

        setBusy(true, "Thinking");
        new Thread(() -> {
            try {
                String sys = augmentSystemWithPreset(augmentSystemWithTemplates(systemPrompt));
                String answer;
                if ("OpenAI".equals(provider)) {
                    OpenAIClient.Config ocfg = buildOpenAIConfig();
                    String val = validateOpenAI(ocfg);
                    if (val != null) { SwingUtilities.invokeLater(() -> appendChat("VISTA", val)); return; }
                    answer = OpenAIClient.ask(ocfg, sys, userPrompt);
                } else {
                    AzureClient.Config acfg = buildAzureConfig();
                    String val = validateAzure(acfg);
                    if (val != null) { SwingUtilities.invokeLater(() -> appendChat("VISTA", val)); return; }
                    answer = AzureClient.ask(acfg, sys, userPrompt);
                }
                SwingUtilities.invokeLater(() -> {
                    // Only append into the chat history of the message that was active when ask was pressed
                    IHttpRequestResponse currentlySelected = getSelectedMessage();
                    if (currentlySelected != boundMessage) {
                        // User switched selection; store answer in the bound message's history without overwriting visible chat
                        StringBuilder sb = chats.computeIfAbsent(boundMessage, k -> new StringBuilder());
                        sb.append("[VISTA] ").append(answer).append("\n\n");
                        // Optionally notify user in current chat
                        appendChat("VISTA", "(Answer for previously selected request stored in its chat history)");
                    } else {
                        appendChat("VISTA", answer);
                    }
                });
            } catch (Exception ex) {
                callbacks.printError("AI error: " + ex);
                SwingUtilities.invokeLater(() -> appendChat("VISTA", "Error calling provider: " + ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> setBusy(false, "Ready"));
            }
    }, "VISTA-AI").start();
    }

    private void doSuggest() {
        // acts like onAsk with empty prompt
        onAsk(null);
    }

    private AzureClient.Config buildAzureConfig() {
        AzureClient.Config cfg = new AzureClient.Config();
        cfg.endpoint = text(endpointField);
        cfg.deployment = text(deploymentField);
        cfg.apiVersion = text(apiVersionField);
        cfg.apiKey = new String(apiKeyField.getPassword());
        return cfg;
    }

    private OpenAIClient.Config buildOpenAIConfig() {
        OpenAIClient.Config cfg = new OpenAIClient.Config();
        cfg.model = text(openAiModelField);
        cfg.apiKey = new String(apiKeyField.getPassword());
        String base = text(openAiBaseUrlField);
        if (base != null && !base.isBlank()) cfg.baseUrl = base;
        return cfg;
    }

    private static String orDefault(String s, String d) { return (s == null || s.isBlank()) ? d : s; }
    private static String text(JTextField f) { return f.getText().trim(); }

    // Validation per provider
    private String validateAzure(AzureClient.Config cfg) {
        if (cfg == null) return "Invalid configuration.";
        if (cfg.endpoint == null || cfg.endpoint.isBlank()) return "Endpoint is empty.";
        if (cfg.deployment == null || cfg.deployment.isBlank()) return "Deployment name is empty.";
        if (cfg.apiKey == null || cfg.apiKey.isBlank()) return "API key is empty.";
        // Users sometimes paste a model ID or prefixed name like "azure/gpt-4o-mini"; Azure expects the deployment name only
        if (cfg.deployment.contains("/") || cfg.deployment.contains(" ")) {
            return "Deployment looks invalid ('" + cfg.deployment + "'). Use the Deployment name you created in Azure (e.g., 'gpt-4o-mini'), not a model ID like 'azure/gpt-4o-mini'.";
        }
        // Endpoint domain hint: allow both Azure OpenAI and Azure AI Foundry (Cognitive Services) endpoints.
        String lc = cfg.endpoint.toLowerCase();
        boolean isOpenAI = lc.contains(".openai.azure.com");
        boolean isCognitive = lc.contains(".cognitiveservices.azure.com");
        if (!(isOpenAI || isCognitive)) {
            return "Endpoint host doesn't look like Azure OpenAI (*.openai.azure.com) or Azure AI Foundry (*.cognitiveservices.azure.com): '" + cfg.endpoint + "'.";
        }
        return null;
    }

    private String validateOpenAI(OpenAIClient.Config cfg) {
        if (cfg == null) return "Invalid configuration.";
        if (cfg.model == null || cfg.model.isBlank()) return "OpenAI model is empty.";
        if (cfg.apiKey == null || cfg.apiKey.isBlank()) return "API key is empty.";
        // baseUrl optional
        return null;
    }

    private static String safe(String s) { return s == null ? "(null)" : s; }

    private void setBusy(boolean busy, String status) {
        askButton.setEnabled(!busy);
        testButton.setEnabled(!busy);
        progress.setVisible(busy);
        progress.setIndeterminate(busy);
    statusLabel.setText(status + (busy ? "..." : ""));
    if (busy && !thinkingDots.isRunning()) thinkingDots.start();
    }

    private int dotCount = 0;
    private void cycleThinking() {
        dotCount = (dotCount + 1) % 4; // 0..3
        String base = statusLabel.getText();
        // remove up to 3 trailing dots without regex to avoid escaping issues
        int removed = 0;
        while (base.endsWith(".") && removed < 3) {
            base = base.substring(0, base.length() - 1);
            removed++;
        }
        statusLabel.setText(base + ".".repeat(dotCount));
    }

    // Simple placeholder support for Swing fields
    private static void installPlaceholder(JTextField field, String placeholder) {
        final java.awt.Color hint = new java.awt.Color(150, 150, 150);
        final java.awt.Color normal = field.getForeground();
        if (field.getText() == null || field.getText().isBlank()) {
            field.setForeground(hint);
            field.setText(placeholder);
        }
        field.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusGained(java.awt.event.FocusEvent e) {
                if (field.getForeground().equals(hint)) {
                    field.setText("");
                    field.setForeground(normal);
                }
            }
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                if (field.getText().isBlank()) {
                    field.setForeground(hint);
                    field.setText(placeholder);
                }
            }
        });
    }

    private static void installPlaceholder(JPasswordField field, String placeholder) {
        final java.awt.Color hint = new java.awt.Color(150, 150, 150);
        final java.awt.Color normal = field.getForeground();
        final char echo = field.getEchoChar();
        if (field.getPassword().length == 0) {
            field.setForeground(hint);
            field.setEchoChar((char)0);
            field.setText(placeholder);
        }
        field.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusGained(java.awt.event.FocusEvent e) {
                if (field.getForeground().equals(hint)) {
                    field.setText("");
                    field.setEchoChar(echo);
                    field.setForeground(normal);
                }
            }
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                if (new String(field.getPassword()).isBlank()) {
                    field.setForeground(hint);
                    field.setEchoChar((char)0);
                    field.setText(placeholder);
                }
            }
        });
    }

    private void appendChat(String who, String text) {
        String line = "[" + who + "] " + text + "\n\n";
        if (current != null) {
            StringBuilder sb = chats.computeIfAbsent(current, k -> new StringBuilder());
            sb.append(line);
            chatArea.setText(sb.toString());
        } else {
            globalChat.append(line);
            chatArea.setText(globalChat.toString());
        }
        chatArea.setCaretPosition(chatArea.getDocument().getLength());
    }

    private void updateProviderVisibility() {
        String provider = (String) providerCombo.getSelectedItem();
        boolean azure = !"OpenAI".equals(provider);
        // Find the titled panels by walking up the component hierarchy under settings panel
        // Since we added them in order, we can simply toggle by label visibility of fields
        endpointField.setEnabled(azure);
        deploymentField.setEnabled(azure);
        apiVersionField.setEnabled(azure);
        openAiModelField.setEnabled(!azure);
        openAiBaseUrlField.setEnabled(!azure);
    }

    // Built-in preset guidance from bundled templates
    private final JComboBox<String> presetCombo = new JComboBox<>(new String[]{
        "None (auto)", "CSRF", "IDOR", "SQL Injection", "SSRF", "XSS"
    });

    private String augmentSystemWithPreset(String systemPrompt) {
        String sel = (String) presetCombo.getSelectedItem();
        if (sel == null || sel.startsWith("None")) return systemPrompt;
        String add = switch (sel) {
            case "CSRF" -> VulnTemplates.CSRF;
            case "IDOR" -> VulnTemplates.IDOR;
            case "SQL Injection" -> VulnTemplates.SQLI;
            case "SSRF" -> VulnTemplates.SSRF;
            case "XSS" -> VulnTemplates.XSS;
            default -> null;
        };
        if (add == null) return systemPrompt;
        return systemPrompt + "\n\nFocus area preset:\n" + add + "\n(Adapt payloads to the specific request parameters and context.)";
    }


    private String augmentSystemWithTemplates(String systemPrompt) {
        java.util.List<String> selected = templatesList.getSelectedValuesList();
        if (selected == null || selected.isEmpty()) return systemPrompt;
        StringBuilder sb = new StringBuilder(systemPrompt);
        sb.append("\n\nUse the following vulnerability playbooks when crafting guidance and payloads (adapt to this specific request):\n");
        int budget = 6000; // keep template content bounded
        for (String name : selected) {
            String content = templates.get(name);
            if (content == null) continue;
            String trimmed = content.length() > 1400 ? content.substring(0, 1400) + "\n...[truncated]..." : content;
            if (budget - trimmed.length() < 0) break;
            budget -= trimmed.length();
            sb.append("\n--- Template: ").append(name).append(" ---\n").append(trimmed).append("\n");
        }
        return sb.toString();
    }

    private void doLoadTemplates() {
        String dir = templatesDirField.getText().trim();
        if (dir.isEmpty()) {
            appendChat("VISTA", "Enter a templates directory path and click Load templates.");
            return;
        }
        java.io.File folder = new java.io.File(dir);
        if (!folder.exists() || !folder.isDirectory()) {
            appendChat("VISTA", "Templates directory not found: " + dir);
            return;
        }
        java.io.File[] files = folder.listFiles((d, name) -> name.toLowerCase().endsWith(".jinja") || name.toLowerCase().endsWith(".txt"));
        if (files == null || files.length == 0) {
            appendChat("VISTA", "No .jinja or .txt files found in: " + dir);
            return;
        }
        templates.clear();
        templatesModel.clear();
        for (java.io.File f : files) {
            try {
                String content = java.nio.file.Files.readString(f.toPath());
                String name = f.getName();
                templates.put(name, content);
                templatesModel.addElement(name);
            } catch (Exception ex) {
                callbacks.printError("Failed to read template: " + f + " -> " + ex);
            }
        }
    appendChat("VISTA", "Loaded " + templates.size() + " template(s) from: " + dir);
    }

    private IHttpRequestResponse getSelectedMessage() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0 || idx >= messages.size()) return null;
        return messages.get(idx);
    }

    private void loadSelectedMessage() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0 || idx >= messages.size()) return;
        current = messages.get(idx);
        requestArea.setText(HttpFormat.requestToText(helpers, current.getRequest()));
        responseArea.setText(HttpFormat.responseToText(helpers, current.getResponse()));
        requestArea.setCaretPosition(0);
        responseArea.setCaretPosition(0);
        // Load chat history for this request
        StringBuilder history = chats.get(current);
        chatArea.setText(history == null ? "" : history.toString());
        chatArea.setCaretPosition(chatArea.getDocument().getLength());
    }

    private String summarizeRequest(IHttpRequestResponse msg) {
        try {
            String req = HttpFormat.requestToText(helpers, msg.getRequest());
            String[] lines = req.split("\\r?\\n");
            String start = lines.length > 0 ? lines[0] : "(request)"; // e.g., GET /path HTTP/1.1
            String host = "";
            for (String l : lines) {
                if (l.toLowerCase().startsWith("host:")) { host = l.substring(5).trim(); break; }
            }
            String shortPath = start.length() > 100 ? start.substring(0, 100) + "…" : start;
            return (host.isEmpty() ? "" : host + " ") + shortPath;
        } catch (Exception e) {
            return "Request " + (messages.size() + 1);
        }
    }

    // Remove selected request and its chat history
    private void removeSelected() {
        int idx = requestList.getSelectedIndex();
        if (idx < 0 || idx >= messages.size()) return;
        IHttpRequestResponse removed = messages.remove(idx);
        reqListModel.remove(idx);
        chats.remove(removed);
        if (messages.isEmpty()) {
            current = null;
            requestArea.setText("");
            responseArea.setText("");
            chatArea.setText(globalChat.toString());
        } else {
            int newIdx = Math.min(idx, messages.size() - 1);
            requestList.setSelectedIndex(newIdx);
            loadSelectedMessage();
        }
        saveStateAsync();
    }

    // Send selected request to Burp Repeater
    private void sendSelectedToRepeater() {
        IHttpRequestResponse sel = getSelectedMessage();
        if (sel == null) {
            appendChat("VISTA", "No request selected to send to Repeater.");
            return;
        }
        try {
            String host = null;
            int port = 0;
            boolean https = false;

            try { host = sel.getHost(); } catch (Throwable ignored) {}
            try { port = sel.getPort(); } catch (Throwable ignored) {}
            try { https = sel.isHttps(); } catch (Throwable ignored) {}

            if (host == null || host.isBlank() || port == 0) {
                String reqText = HttpFormat.requestToText(helpers, sel.getRequest());
                String[] lines = reqText.split("\\r?\\n");
                String first = lines.length > 0 ? lines[0] : "";
                for (String l : lines) {
                    if (l.toLowerCase().startsWith("host:")) {
                        String hv = l.substring(5).trim();
                        if (hv.contains(":")) {
                            String[] hp = hv.split(":", 2);
                            host = hp[0].trim();
                            try { port = Integer.parseInt(hp[1].trim()); } catch (NumberFormatException ignored) {}
                        } else {
                            host = hv.trim();
                        }
                        break;
                    }
                }
                String lower = first.toLowerCase();
                if (lower.contains("http://")) https = false;
                else if (lower.contains("https://")) https = true;
                if (port == 0) port = https ? 443 : 80;
            }

            if (host == null || host.isBlank()) {
                appendChat("VISTA", "Could not determine host for Repeater.");
                return;
            }

            callbacks.sendToRepeater(host, port, https, sel.getRequest(), "VISTA");
            appendChat("VISTA", "Sent to Repeater: " + host + ":" + port + (https ? " (https)" : " (http)"));
            saveStateAsync();
        } catch (Exception ex) {
            callbacks.printError("Send to Repeater failed: " + ex);
            appendChat("VISTA", "Failed to send to Repeater: " + ex.getMessage());
        }
    }

    // ---------------- Persistence (best-effort JSON without external libs) ----------------
    private File stateFile() {
        String home = System.getProperty("user.home", ".");
        return new File(home, ".burpraj.json");
    }

    private synchronized void saveStateAsync() {
        new Thread(this::saveState, "BurpRaj-Save").start();
    }

    private synchronized void saveState() {
        try (FileWriter fw = new FileWriter(stateFile())) {
            // Only store settings + per-request chats by index (request raw data not persisted)
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            // settings
            sb.append("\"provider\":\"").append(escape((String)providerCombo.getSelectedItem())).append("\",");
            sb.append("\"endpoint\":\"").append(escape(text(endpointField))).append("\",");
            sb.append("\"deployment\":\"").append(escape(text(deploymentField))).append("\",");
            sb.append("\"apiVersion\":\"").append(escape(text(apiVersionField))).append("\",");
            sb.append("\"openAiModel\":\"").append(escape(text(openAiModelField))).append("\",");
            sb.append("\"openAiBaseUrl\":\"").append(escape(text(openAiBaseUrlField))).append("\",");
            sb.append("\"strip\":").append(stripHeaders.isSelected()).append(',');
            sb.append("\"maxChars\":").append((Integer)maxCharsSpinner.getValue()).append(',');
            sb.append("\"preset\":\"").append(escape((String)presetCombo.getSelectedItem())).append("\",");
            // chats
            sb.append("\"globalChat\":\"").append(escape(globalChat.toString())).append("\",");
            sb.append("\"chats\":[");
            boolean first = true;
            for (Map.Entry<IHttpRequestResponse,StringBuilder> e : chats.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('{');
                sb.append("\"hash\":").append(e.getKey().hashCode()).append(',');
                sb.append("\"text\":\"").append(escape(e.getValue().toString())).append("\"}");
            }
            sb.append(']');
            sb.append('}');
            fw.write(sb.toString());
        } catch (Exception ex) {
            callbacks.printError("Failed to save state: " + ex);
        }
    }

    private synchronized void loadState() {
        File f = stateFile();
        if (!f.exists()) return;
        try {
            String json = java.nio.file.Files.readString(f.toPath());
            // Extremely naive parsing (no nested objects aside from chats array)
            providerCombo.setSelectedItem(extract(json, "provider"));
            endpointField.setText(extract(json, "endpoint"));
            deploymentField.setText(extract(json, "deployment"));
            apiVersionField.setText(extract(json, "apiVersion"));
            openAiModelField.setText(extract(json, "openAiModel"));
            openAiBaseUrlField.setText(extract(json, "openAiBaseUrl"));
            String strip = extract(json, "strip");
            if (strip != null && (strip.equals("true") || strip.equals("false"))) stripHeaders.setSelected(Boolean.parseBoolean(strip));
            String maxChars = extract(json, "maxChars");
            try { if (maxChars != null) maxCharsSpinner.setValue(Integer.parseInt(maxChars)); } catch (NumberFormatException ignored) {}
            String preset = extract(json, "preset");
            if (preset != null) presetCombo.setSelectedItem(preset);
            String g = extract(json, "globalChat");
            if (g != null) { globalChat.setLength(0); globalChat.append(unescape(g)); }
            // chats array not re-bound to requests since requests are session-scoped; they will repopulate as new requests are added.
        } catch (Exception ex) {
            callbacks.printError("Failed to load state: " + ex);
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
    private static String unescape(String s) { return s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\"); }

    private static String extract(String json, String key) {
        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;
        int start = idx + pattern.length();
        // bool/number vs string
        if (start < json.length() && json.charAt(start) == '"') {
            start++;
            int end = json.indexOf('"', start);
            if (end < 0) return null;
            return unescape(json.substring(start, end));
        } else {
            int end = start;
            while (end < json.length() && ",}\n".indexOf(json.charAt(end)) == -1) end++;
            return json.substring(start, end).trim();
        }
    }
}
