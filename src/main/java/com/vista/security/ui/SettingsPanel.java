package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import com.vista.security.core.AIConfigManager;
import com.vista.security.core.VistaPersistenceManager;
import com.vista.security.service.AzureAIService;
import com.vista.security.service.OpenAIService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.util.List;

import static com.vista.security.ui.VistaTheme.*;

/**
 * Centralized Settings Panel for VISTA.
 * All AI configuration is done here and shared across all tabs.
 */
public class SettingsPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final AIConfigManager config;

    // AI Provider
    private final JComboBox<String> providerCombo = new JComboBox<>(new String[]{"OpenAI", "Azure AI", "OpenRouter"});
    private final JPasswordField apiKeyField = new JPasswordField(35);
    private final JPasswordField azureApiKeyField = new JPasswordField(35);
    private final JTextField modelField = new JTextField("gpt-4o-mini", 20);
    private final JTextField endpointField = new JTextField(35);
    private final JTextField deploymentField = new JTextField(20);
    private final JTextField azureApiVersionField = new JTextField("2025-01-01-preview", 20);
    private final JComboBox<String> azureAuthModeCombo = new JComboBox<>(new String[]{"API Key", "Azure Identity"});
    private final JPasswordField openRouterApiKeyField = new JPasswordField(35);
    private final JComboBox<String> openRouterModelCombo = new JComboBox<>();
    private final JSlider temperatureSlider = new JSlider(0, 100, 30);
    private final JLabel tempValueLabel = new JLabel("0.30");
    private final JLabel statusLabel = new JLabel();

    // Panel references
    private JPanel openaiPanel;
    private JPanel azurePanel;
    private JPanel openRouterPanel;

    // Action buttons (promoted to fields for enable/disable logic)
    private JButton saveBtn;
    private JButton testBtn;
    private boolean testPassed = false;

    public SettingsPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.config = AIConfigManager.getInstance();
        
        setLayout(new BorderLayout());
        setBackground(VistaTheme.BG_PANEL);
        setBorder(new EmptyBorder(0, 0, 0, 0));
        
        buildUI();
        loadConfig();
        updateStatus();
    }

    private void buildUI() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBackground(VistaTheme.BG_PANEL);
        mainPanel.setMaximumSize(new Dimension(650, Integer.MAX_VALUE));

        // Header
        JLabel headerLabel = new JLabel("AI Configuration");
        headerLabel.setFont(VistaTheme.FONT_TITLE);
        headerLabel.setForeground(VistaTheme.TEXT_PRIMARY);
        headerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        
        JLabel subLabel = new JLabel("Configure your AI provider. Settings are shared across all VISTA features.");
        subLabel.setFont(VistaTheme.FONT_SUBTITLE);
        subLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        subLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Provider selection
        JPanel providerPanel = createSection("Select AI Provider");
        JPanel providerRow = createRow("Provider:", providerCombo);
        providerPanel.add(providerRow);
        providerCombo.addActionListener(e -> {
            updateProviderVisibility();
            saveConfig();
        });

        // OpenAI Settings
        openaiPanel = createSection("OpenAI Configuration");
        
        JPanel openaiKeyRow = createRow("API Key:", apiKeyField);
        JButton showKeyBtn = VistaTheme.compactButton("Show");
        showKeyBtn.addActionListener(e -> {
            if (apiKeyField.getEchoChar() == '•') {
                apiKeyField.setEchoChar((char) 0);
                showKeyBtn.setText("Hide");
            } else {
                apiKeyField.setEchoChar('•');
                showKeyBtn.setText("Show");
            }
        });
        openaiKeyRow.add(showKeyBtn);
        openaiPanel.add(openaiKeyRow);
        apiKeyField.addActionListener(e -> saveConfig());
        
        openaiPanel.add(createRow("Model:", modelField));
        modelField.setToolTipText("e.g., gpt-4o-mini, gpt-4o, gpt-3.5-turbo");
        
        JLabel openaiInfo = new JLabel("Get API key at platform.openai.com/api-keys");
        openaiInfo.setFont(VistaTheme.FONT_SMALL);
        openaiInfo.setForeground(VistaTheme.TEXT_MUTED);
        JPanel openaiInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        openaiInfoPanel.add(openaiInfo);
        openaiPanel.add(openaiInfoPanel);

        // Azure Settings
        azurePanel = createSection("Azure AI Configuration");

        // Auth mode selector — show/hide API key field accordingly
        JPanel authModeRow = createRow("Auth Mode:", azureAuthModeCombo);
        azureAuthModeCombo.setToolTipText("API Key: use azure key  |  Azure Identity: DefaultAzureCredential (env vars or az CLI)");
        azurePanel.add(authModeRow);
        azureAuthModeCombo.addActionListener(e -> {
            boolean needKey = "API Key".equals(azureAuthModeCombo.getSelectedItem());
            azureApiKeyField.setEnabled(needKey);
            saveConfig();
            onFieldsChanged();
        });

        JPanel azureKeyRow = createRow("API Key:", azureApiKeyField);
        JButton showAzureKeyBtn = VistaTheme.compactButton("Show");
        showAzureKeyBtn.addActionListener(e -> {
            if (azureApiKeyField.getEchoChar() == '•') {
                azureApiKeyField.setEchoChar((char) 0);
                showAzureKeyBtn.setText("Hide");
            } else {
                azureApiKeyField.setEchoChar('•');
                showAzureKeyBtn.setText("Show");
            }
        });
        azureKeyRow.add(showAzureKeyBtn);
        azurePanel.add(azureKeyRow);
        azureApiKeyField.addActionListener(e -> saveConfig());
        
        JLabel identityHint = new JLabel("Azure Identity: set AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET env vars, or run 'az login'");
        identityHint.setFont(VistaTheme.FONT_SMALL);
        identityHint.setForeground(VistaTheme.TEXT_MUTED);
        JPanel identityHintRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        identityHintRow.setOpaque(false);
        identityHintRow.add(identityHint);
        azurePanel.add(identityHintRow);

        azurePanel.add(createRow("Endpoint:", endpointField));
        azurePanel.add(createRow("Deployment:", deploymentField));
        azurePanel.add(createRow("API Version:", azureApiVersionField));
        endpointField.setToolTipText("e.g., https://your-resource.services.ai.azure.com/openai/v1  or  https://your-resource.openai.azure.com");
        deploymentField.setToolTipText("Your Azure deployment name (e.g., gpt-5.2)");
        azureApiVersionField.setToolTipText("Only used for classic Azure OpenAI endpoints (ignored for Foundry)");

        JLabel azureInfo = new JLabel("Foundry: *.services.ai.azure.com/openai/v1   |   Classic: *.openai.azure.com");
        azureInfo.setFont(VistaTheme.FONT_SMALL);
        azureInfo.setForeground(VistaTheme.TEXT_MUTED);
        JPanel azureInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        azureInfoPanel.add(azureInfo);
        azurePanel.add(azureInfoPanel);

        // OpenRouter Settings
        openRouterPanel = createSection("OpenRouter Configuration");
        
        JPanel openRouterKeyRow = createRow("API Key:", openRouterApiKeyField);
        JButton showOpenRouterKeyBtn = VistaTheme.compactButton("Show");
        showOpenRouterKeyBtn.addActionListener(e -> {
            if (openRouterApiKeyField.getEchoChar() == '•') {
                openRouterApiKeyField.setEchoChar((char) 0);
                showOpenRouterKeyBtn.setText("Hide");
            } else {
                openRouterApiKeyField.setEchoChar('•');
                showOpenRouterKeyBtn.setText("Show");
            }
        });
        openRouterKeyRow.add(showOpenRouterKeyBtn);
        openRouterPanel.add(openRouterKeyRow);
        
        // Populate OpenRouter models - TOP 5 FREE MODELS (updated Feb 2026)
        // These models are verified available on OpenRouter's free tier
        openRouterModelCombo.addItem("deepseek/deepseek-r1-0528:free");          // 671B, 164K ctx — Best reasoning
        openRouterModelCombo.addItem("openai/gpt-oss-120b:free");                // 117B MoE, 131K ctx — High-reasoning, agentic
        openRouterModelCombo.addItem("arcee-ai/trinity-large-preview:free");     // 400B MoE, 131K ctx — Agentic, long prompts
        openRouterModelCombo.addItem("stepfun/step-3.5-flash:free");             // 196B MoE, 256K ctx — Fast reasoning
        openRouterModelCombo.addItem("z-ai/glm-4.5-air:free");                  // MoE, 131K ctx — Thinking mode
        openRouterModelCombo.setEditable(true);
        
        JPanel modelRow = createRow("Model:", openRouterModelCombo);
        openRouterPanel.add(modelRow);
        
        JLabel openRouterInfo1 = new JLabel("5 top free models — DeepSeek R1 (recommended), GPT-OSS-120B, Trinity, Step Flash, GLM 4.5");
        openRouterInfo1.setFont(VistaTheme.FONT_SMALL);
        openRouterInfo1.setForeground(VistaTheme.TEXT_MUTED);
        JPanel infoPanel1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        infoPanel1.setOpaque(false);
        infoPanel1.add(openRouterInfo1);
        openRouterPanel.add(infoPanel1);
        
        JLabel openRouterInfo2 = new JLabel("Get free API key at openrouter.ai/keys (no credit card needed) — Free models rotate regularly");
        openRouterInfo2.setFont(VistaTheme.FONT_SMALL);
        openRouterInfo2.setForeground(VistaTheme.TEXT_MUTED);
        JPanel infoPanel2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        infoPanel2.setOpaque(false);
        infoPanel2.add(openRouterInfo2);
        openRouterPanel.add(infoPanel2);

        // Advanced Settings
        JPanel advancedPanel = createSection("Advanced");
        JPanel tempRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        tempRow.add(new JLabel("Temperature:"));
        temperatureSlider.setPreferredSize(new Dimension(150, 25));
        temperatureSlider.addChangeListener(e -> {
            double temp = temperatureSlider.getValue() / 100.0;
            tempValueLabel.setText(String.format("%.2f", temp));
        });
        tempRow.add(temperatureSlider);
        tempRow.add(tempValueLabel);
        tempRow.add(new JLabel("(Lower = more focused, Higher = more creative)"));
        advancedPanel.add(tempRow);

        // ── Data Backup & Restore ──
        JPanel backupPanel = createSection("Data Backup & Restore");
        backupPanel.setMaximumSize(new Dimension(600, 280));
        
        JLabel backupInfo = new JLabel("Export all VISTA data (traffic, findings, templates, payloads, sessions, AI config) to a backup folder, or restore from a previous backup.");
        backupInfo.setFont(VistaTheme.FONT_SMALL);
        backupInfo.setForeground(VistaTheme.TEXT_SECONDARY);
        JPanel backupInfoRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        backupInfoRow.setOpaque(false);
        backupInfoRow.add(backupInfo);
        backupPanel.add(backupInfoRow);
        
        JPanel backupBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 8));
        backupBtnRow.setOpaque(false);
        
        JButton exportBtn = VistaTheme.primaryButton("📦 Export Backup");
        exportBtn.setToolTipText("Save all VISTA data to a folder of your choice");
        exportBtn.addActionListener(e -> exportBackup());
        
        JButton importBtn = VistaTheme.secondaryButton("📥 Import Backup");
        importBtn.setToolTipText("Restore VISTA data from a previous backup");
        importBtn.addActionListener(e -> importBackup());
        
        backupBtnRow.add(exportBtn);
        backupBtnRow.add(Box.createHorizontalStrut(8));
        backupBtnRow.add(importBtn);
        backupPanel.add(backupBtnRow);
        
        JLabel backupNote = new JLabel("💡 Backups include: traffic logs, exploit findings, custom templates, payload libraries, chat sessions, and AI configuration.");
        backupNote.setFont(VistaTheme.FONT_SMALL);
        backupNote.setForeground(VistaTheme.TEXT_MUTED);
        JPanel backupNoteRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        backupNoteRow.setOpaque(false);
        backupNoteRow.add(backupNote);
        backupPanel.add(backupNoteRow);

        // Buttons - centered alignment
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 0));
        buttonPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        buttonPanel.setOpaque(false);
        
        testBtn = VistaTheme.primaryButton("Test Connection");
        testBtn.setEnabled(false);
        testBtn.addActionListener(e -> testConnection());
        
        saveBtn = VistaTheme.secondaryButton("Save Configuration");
        saveBtn.setEnabled(false);
        saveBtn.addActionListener(e -> {
            saveConfig();
            JOptionPane.showMessageDialog(this, "Configuration saved!", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        
        buttonPanel.add(testBtn);
        buttonPanel.add(saveBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(statusLabel);
        
        // Add listeners to enable Test Connection when API key + model are provided
        javax.swing.event.DocumentListener fieldChangeListener = new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { onFieldsChanged(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { onFieldsChanged(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { onFieldsChanged(); }
        };
        apiKeyField.getDocument().addDocumentListener(fieldChangeListener);
        modelField.getDocument().addDocumentListener(fieldChangeListener);
        azureApiKeyField.getDocument().addDocumentListener(fieldChangeListener);
        endpointField.getDocument().addDocumentListener(fieldChangeListener);
        deploymentField.getDocument().addDocumentListener(fieldChangeListener);
        azureApiVersionField.getDocument().addDocumentListener(fieldChangeListener);
        azureAuthModeCombo.addActionListener(e -> onFieldsChanged());
        openRouterApiKeyField.getDocument().addDocumentListener(fieldChangeListener);
        providerCombo.addActionListener(e -> onFieldsChanged());
        openRouterModelCombo.addActionListener(e -> onFieldsChanged());

        // Add all sections
        mainPanel.add(headerLabel);
        mainPanel.add(Box.createVerticalStrut(4));
        mainPanel.add(subLabel);
        mainPanel.add(Box.createVerticalStrut(20));
        mainPanel.add(providerPanel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(openaiPanel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(azurePanel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(openRouterPanel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(advancedPanel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(backupPanel);
        mainPanel.add(Box.createVerticalStrut(20));
        mainPanel.add(buttonPanel);

        // Create a centered wrapper panel to center content horizontally
        JPanel centeredWrapper = new JPanel(new GridBagLayout());
        centeredWrapper.setBackground(VistaTheme.BG_PANEL);
        centeredWrapper.add(mainPanel);

        // Wrap in scroll pane
        JScrollPane scrollPane = new JScrollPane(centeredWrapper);
        scrollPane.setBorder(null);
        scrollPane.setBackground(VistaTheme.BG_PANEL);
        scrollPane.getViewport().setBackground(VistaTheme.BG_PANEL);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        add(scrollPane, BorderLayout.CENTER);
        
        updateProviderVisibility();
    }

    private JPanel createSection(String title) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(VistaTheme.BG_CARD);
        panel.setBorder(VistaTheme.sectionBorder(title));
        panel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.setMaximumSize(new Dimension(600, 200));
        return panel;
    }

    private JPanel createRow(String label, JComponent field) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row.setOpaque(false);
        JLabel lbl = new JLabel(label);
        lbl.setFont(VistaTheme.FONT_LABEL);
        lbl.setForeground(VistaTheme.TEXT_SECONDARY);
        lbl.setPreferredSize(new Dimension(100, 25));
        row.add(lbl);
        row.add(field);
        return row;
    }

    private void updateProviderVisibility() {
        String provider = (String) providerCombo.getSelectedItem();
        boolean isOpenAI = "OpenAI".equals(provider);
        boolean isAzure = "Azure AI".equals(provider);
        boolean isOpenRouter = "OpenRouter".equals(provider);
        
        // Show only the relevant panel for selected provider
        openaiPanel.setVisible(isOpenAI);
        azurePanel.setVisible(isAzure);
        openRouterPanel.setVisible(isOpenRouter);
        
        revalidate();
        repaint();
    }

    /**
     * Called whenever a configuration field changes.
     * Enables Test Connection if required fields are filled for the current provider.
     * Resets test passed state and disables Save until re-tested.
     */
    private void onFieldsChanged() {
        testPassed = false;
        saveBtn.setEnabled(false);
        
        String provider = (String) providerCombo.getSelectedItem();
        boolean hasRequiredFields = false;
        
        if ("OpenAI".equals(provider)) {
            String key = new String(apiKeyField.getPassword()).trim();
            String model = modelField.getText().trim();
            hasRequiredFields = !key.isEmpty() && !model.isEmpty();
        } else if ("Azure AI".equals(provider)) {
            String endpoint    = endpointField.getText().trim();
            String deployment  = deploymentField.getText().trim();
            boolean isIdentity = "Azure Identity".equals(azureAuthModeCombo.getSelectedItem());
            if (isIdentity) {
                hasRequiredFields = !endpoint.isEmpty() && !deployment.isEmpty();
            } else {
                String key = new String(azureApiKeyField.getPassword()).trim();
                hasRequiredFields = !key.isEmpty() && !endpoint.isEmpty() && !deployment.isEmpty();
            }
        } else if ("OpenRouter".equals(provider)) {
            String key = new String(openRouterApiKeyField.getPassword()).trim();
            Object model = openRouterModelCombo.getSelectedItem();
            hasRequiredFields = !key.isEmpty() && model != null && !model.toString().trim().isEmpty();
        }
        
        testBtn.setEnabled(hasRequiredFields);
    }

    private void loadConfig() {
        providerCombo.setSelectedItem(config.getProvider());
        apiKeyField.setText(config.getOpenAIApiKey());
        azureApiKeyField.setText(config.getAzureApiKey());
        modelField.setText(config.getModel());
        endpointField.setText(config.getEndpoint());
        deploymentField.setText(config.getDeployment());
        azureApiVersionField.setText(config.getAzureApiVersion());
        azureAuthModeCombo.setSelectedItem(
            "azure-identity".equalsIgnoreCase(config.getAzureAuthMode()) ? "Azure Identity" : "API Key");
        azureApiKeyField.setEnabled(!"azure-identity".equalsIgnoreCase(config.getAzureAuthMode()));
        openRouterApiKeyField.setText(config.getOpenRouterApiKey());
        
        // Set OpenRouter model (add if not in list)
        String openRouterModel = config.getOpenRouterModel();
        boolean found = false;
        for (int i = 0; i < openRouterModelCombo.getItemCount(); i++) {
            if (openRouterModelCombo.getItemAt(i).equals(openRouterModel)) {
                found = true;
                break;
            }
        }
        if (!found && openRouterModel != null && !openRouterModel.isBlank()) {
            openRouterModelCombo.addItem(openRouterModel);
        }
        openRouterModelCombo.setSelectedItem(openRouterModel);
        
        temperatureSlider.setValue((int) (config.getTemperature() * 100));
        tempValueLabel.setText(String.format("%.2f", config.getTemperature()));
        updateProviderVisibility();
        
        // Update button states based on loaded config
        onFieldsChanged();
    }

    private void saveConfig() {
        String provider = (String) providerCombo.getSelectedItem();
        
        String authModeValue = "Azure Identity".equals(azureAuthModeCombo.getSelectedItem())
            ? "azure-identity" : "api-key";
        config.updateConfig(
            provider,
            new String(apiKeyField.getPassword()),
            new String(azureApiKeyField.getPassword()),
            modelField.getText().trim(),
            endpointField.getText().trim(),
            deploymentField.getText().trim(),
            azureApiVersionField.getText().trim(),
            authModeValue,
            new String(openRouterApiKeyField.getPassword()),
            (String) openRouterModelCombo.getSelectedItem(),
            temperatureSlider.getValue() / 100.0
        );
        // Clear cached credential tokens when config changes
        com.vista.security.service.AzureCredentialProvider.getInstance().clearCache();
        updateStatus();
    }

    private void updateStatus() {
        if (config.isConfigured()) {
            statusLabel.setText("● " + config.getProvider() + " configured");
            statusLabel.setForeground(VistaTheme.STATUS_SUCCESS);
            statusLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        } else {
            statusLabel.setText("● " + config.getStatusMessage());
            statusLabel.setForeground(VistaTheme.STATUS_WARNING);
            statusLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        }
    }

    private void testConnection() {
        saveConfig();
        
        if (!config.isConfigured()) {
            JOptionPane.showMessageDialog(this, 
                "Please complete the configuration first.\n\n" + config.getStatusMessage(),
                "Configuration Incomplete", JOptionPane.WARNING_MESSAGE);
            return;
        }

        statusLabel.setText("Testing connection...");
        statusLabel.setForeground(VistaTheme.PRIMARY);
        testBtn.setEnabled(false);

        new Thread(() -> {
            try {
                String response;
                String provider = config.getProvider();
                
                if ("Azure AI".equals(provider)) {
                    AzureAIService.Configuration azureConfig = new AzureAIService.Configuration();
                    azureConfig.setEndpoint(config.getEndpoint());
                    azureConfig.setDeploymentName(config.getDeployment());
                    azureConfig.setApiKey(config.getAzureApiKey());
                    azureConfig.setApiVersion(config.getAzureApiVersion());
                    azureConfig.setAuthMode(config.getAzureAuthMode());
                    azureConfig.setTemperature(0.1);
                    response = new AzureAIService(azureConfig).testConnection();
                } else if ("OpenRouter".equals(provider)) {
                    com.vista.security.service.OpenRouterService.Configuration openRouterConfig = 
                        new com.vista.security.service.OpenRouterService.Configuration();
                    openRouterConfig.setApiKey(config.getOpenRouterApiKey());
                    openRouterConfig.setModel(config.getOpenRouterModel());
                    openRouterConfig.setTemperature(0.1);
                    response = new com.vista.security.service.OpenRouterService(openRouterConfig).testConnection();
                } else {
                    OpenAIService.Configuration openaiConfig = new OpenAIService.Configuration();
                    openaiConfig.setApiKey(config.getOpenAIApiKey());
                    openaiConfig.setModel(config.getModel());
                    openaiConfig.setTemperature(0.1);
                    response = new OpenAIService(openaiConfig).testConnection();
                }

                SwingUtilities.invokeLater(() -> {
                    testPassed = true;
                    saveBtn.setEnabled(true);
                    testBtn.setEnabled(true);
                    statusLabel.setText("● Connection successful!");
                    statusLabel.setForeground(VistaTheme.STATUS_SUCCESS);
                    JOptionPane.showMessageDialog(this, 
                        "Connection successful!\n\nAI Response: " + truncate(response, 100),
                        "Success", JOptionPane.INFORMATION_MESSAGE);
                });

            } catch (Exception e) {
                final String errorMessage = e.getMessage();
                SwingUtilities.invokeLater(() -> {
                    testPassed = false;
                    saveBtn.setEnabled(false);
                    testBtn.setEnabled(true);
                    statusLabel.setText("● Connection failed");
                    statusLabel.setForeground(VistaTheme.STATUS_ERROR);
                    
                    // Create a detailed error panel with scrollable text
                    String errorDetails = parseConnectionError(errorMessage, config.getProvider());
                    
                    JTextArea errorArea = new JTextArea(errorDetails);
                    errorArea.setEditable(false);
                    errorArea.setFont(VistaTheme.FONT_BODY);
                    errorArea.setLineWrap(true);
                    errorArea.setWrapStyleWord(true);
                    errorArea.setBackground(VistaTheme.SEVERITY_CRITICAL_BG);
                    errorArea.setForeground(VistaTheme.TEXT_PRIMARY);
                    errorArea.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
                    
                    JScrollPane scrollPane = new JScrollPane(errorArea);
                    scrollPane.setPreferredSize(new Dimension(450, 200));
                    scrollPane.setBorder(BorderFactory.createLineBorder(VistaTheme.SEVERITY_CRITICAL));
                    
                    JOptionPane.showMessageDialog(this, 
                        scrollPane,
                        "Connection Failed", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }
    
    /**
     * Parse connection error and provide helpful suggestions.
     */
    private String parseConnectionError(String errorMessage, String provider) {
        StringBuilder details = new StringBuilder();
        details.append("❌ Connection Error\n\n");
        
        if (errorMessage == null) {
            errorMessage = "Unknown error occurred";
        }
        
        // Determine error type and provide helpful message
        if (errorMessage.contains("401") || errorMessage.toLowerCase().contains("unauthorized") || 
            errorMessage.toLowerCase().contains("invalid") && errorMessage.toLowerCase().contains("key")) {
            details.append("🔑 Authentication Failed\n\n");
            details.append("Your API key appears to be invalid or expired.\n\n");
            details.append("Suggestions:\n");
            details.append("• Check if the API key is correctly entered\n");
            details.append("• Verify the API key hasn't expired\n");
            details.append("• Generate a new API key if needed\n\n");
            
            if ("OpenAI".equals(provider)) {
                details.append("Get a new key at: platform.openai.com/api-keys");
            } else if ("Azure AI".equals(provider)) {
                details.append("Check Azure Portal → Azure OpenAI Service → Keys");
            } else if ("OpenRouter".equals(provider)) {
                details.append("Get a new key at: openrouter.ai/keys");
            }
            
        } else if (errorMessage.contains("402") || errorMessage.toLowerCase().contains("payment") ||
                   errorMessage.toLowerCase().contains("insufficient")) {
            details.append("💳 Payment Required / Insufficient Credits\n\n");
            details.append("Your account doesn't have enough credits for this model.\n\n");
            details.append("Suggestions:\n");
            details.append("• Switch to a free model (models ending with :free)\n");
            details.append("• Add credits at openrouter.ai/credits\n");
            details.append("• Check your billing status at openrouter.ai/settings\n");
            
        } else if (errorMessage.contains("429") || errorMessage.toLowerCase().contains("rate limit") ||
                   errorMessage.toLowerCase().contains("quota")) {
            details.append("⏱️ Rate Limit / Quota Exceeded\n\n");
            details.append("You've hit the API rate limit or quota.\n\n");
            details.append("Suggestions:\n");
            details.append("• Wait a few minutes and try again\n");
            details.append("• Free models have lower rate limits — space out your requests\n");
            details.append("• Check your API usage at openrouter.ai/activity\n");
            if ("OpenRouter".equals(provider)) {
                details.append("• Try a different free model (some have higher limits)\n");
            } else {
                details.append("• Consider upgrading your plan\n");
            }
            
        } else if (errorMessage.contains("404") || errorMessage.toLowerCase().contains("not found") ||
                   errorMessage.toLowerCase().contains("no longer available")) {
            details.append("🔍 Model/Endpoint Not Found\n\n");
            details.append("The specified model or endpoint wasn't found.\n\n");
            details.append("Suggestions:\n");
            details.append("• Verify the model name is correct\n");
            
            if ("Azure AI".equals(provider)) {
                details.append("• Check your deployment name in Azure Portal\n");
                details.append("• Verify the endpoint URL is correct\n");
            } else if ("OpenRouter".equals(provider)) {
                details.append("• Free models are rotated regularly on OpenRouter\n");
                details.append("• Select an updated model from the dropdown list\n");
                details.append("• Browse available models at openrouter.ai/models?q=free\n");
            } else {
                details.append("• Try a different model (e.g., gpt-4o-mini)\n");
            }
            
        } else if (errorMessage.toLowerCase().contains("connection") || 
                   errorMessage.toLowerCase().contains("timeout") ||
                   errorMessage.toLowerCase().contains("network")) {
            details.append("🌐 Network Error\n\n");
            details.append("Could not connect to the AI service.\n\n");
            details.append("Suggestions:\n");
            details.append("• Check your internet connection\n");
            details.append("• Verify firewall/proxy settings\n");
            details.append("• Try again in a few moments\n");
            
            if ("Azure AI".equals(provider)) {
                details.append("• Verify the endpoint URL is accessible\n");
            }
            
        } else if (errorMessage.contains("500") || errorMessage.contains("502") || 
                   errorMessage.contains("503")) {
            details.append("🔧 Server Error\n\n");
            details.append("The AI service is experiencing issues.\n\n");
            details.append("Suggestions:\n");
            details.append("• Wait a few minutes and retry\n");
            details.append("• Check the provider's status page\n");
            
        } else {
            details.append("Error Details:\n");
            details.append(errorMessage).append("\n\n");
            details.append("Suggestions:\n");
            details.append("• Verify all configuration fields are correct\n");
            details.append("• Check the API key is valid\n");
            details.append("• Try again in a few moments\n");
        }
        
        return details.toString();
    }

    // ═══════════════════════════════════════════════════════════════
    // Backup Export / Import
    // ═══════════════════════════════════════════════════════════════
    
    private void exportBackup() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose Backup Destination");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setApproveButtonText("Export Here");
        
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        
        File destDir = chooser.getSelectedFile();
        
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        new Thread(() -> {
            try {
                File backupDir = VistaPersistenceManager.getInstance().exportBackup(destDir);
                SwingUtilities.invokeLater(() -> {
                    setCursor(Cursor.getDefaultCursor());
                    JOptionPane.showMessageDialog(this,
                            "✅ Backup exported successfully!\n\n" +
                            "Location:\n" + backupDir.getAbsolutePath() + "\n\n" +
                            "You can restore this backup anytime using 'Import Backup'.",
                            "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    setCursor(Cursor.getDefaultCursor());
                    JOptionPane.showMessageDialog(this,
                            "❌ Export failed:\n" + e.getMessage(),
                            "Export Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }
    
    private void importBackup() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "⚠️ Importing a backup will overwrite your current VISTA data.\n\n" +
                "This includes: traffic logs, findings, templates, payloads,\n" +
                "chat sessions, and AI configuration.\n\n" +
                "Do you want to continue?",
                "Confirm Import", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        
        if (confirm != JOptionPane.YES_OPTION) return;
        
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select VISTA Backup Folder");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setApproveButtonText("Import");
        
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        
        File backupDir = chooser.getSelectedFile();
        
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        new Thread(() -> {
            try {
                int restored = VistaPersistenceManager.getInstance().importBackup(backupDir);
                
                // Reload AI config into the UI
                SwingUtilities.invokeLater(() -> {
                    setCursor(Cursor.getDefaultCursor());
                    loadConfig();
                    JOptionPane.showMessageDialog(this,
                            "✅ Backup imported successfully!\n\n" +
                            restored + " data section(s) restored.\n\n" +
                            "Note: Restart Burp Suite for all changes to take full effect.",
                            "Import Complete", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    setCursor(Cursor.getDefaultCursor());
                    JOptionPane.showMessageDialog(this,
                            "❌ Import failed:\n" + e.getMessage(),
                            "Import Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
