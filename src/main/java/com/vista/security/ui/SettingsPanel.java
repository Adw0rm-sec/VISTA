package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import com.vista.security.core.AIConfigManager;
import com.vista.security.core.HeadlessBrowserVerifier;
import com.vista.security.service.AzureAIService;
import com.vista.security.service.OpenAIService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

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
    private final JPasswordField openRouterApiKeyField = new JPasswordField(35);
    private final JComboBox<String> openRouterModelCombo = new JComboBox<>();
    private final JSlider temperatureSlider = new JSlider(0, 100, 30);
    private final JLabel tempValueLabel = new JLabel("0.30");
    private final JLabel statusLabel = new JLabel();
    private final JLabel browserStatusLabel = new JLabel();

    // Panel references
    private JPanel openaiPanel;
    private JPanel azurePanel;
    private JPanel openRouterPanel;

    public SettingsPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.config = AIConfigManager.getInstance();
        
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(20, 20, 20, 20));
        
        buildUI();
        loadConfig();
        updateStatus();
    }

    private void buildUI() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Header
        JLabel headerLabel = new JLabel("AI Configuration");
        headerLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 18));
        headerLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel subLabel = new JLabel("Configure your AI provider. Settings are shared across all VISTA features.");
        subLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        subLabel.setForeground(Color.GRAY);
        subLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

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
        JButton showKeyBtn = new JButton("Show");
        showKeyBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
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
        openaiInfo.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        openaiInfo.setForeground(Color.GRAY);
        JPanel openaiInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        openaiInfoPanel.add(openaiInfo);
        openaiPanel.add(openaiInfoPanel);

        // Azure Settings
        azurePanel = createSection("Azure AI Configuration");
        
        JPanel azureKeyRow = createRow("API Key:", azureApiKeyField);
        JButton showAzureKeyBtn = new JButton("Show");
        showAzureKeyBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
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
        
        azurePanel.add(createRow("Endpoint:", endpointField));
        azurePanel.add(createRow("Deployment:", deploymentField));
        endpointField.setToolTipText("e.g., https://your-resource.openai.azure.com");
        deploymentField.setToolTipText("Your Azure deployment name");
        
        JLabel azureInfo = new JLabel("Configure in Azure Portal > Azure OpenAI Service");
        azureInfo.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        azureInfo.setForeground(Color.GRAY);
        JPanel azureInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        azureInfoPanel.add(azureInfo);
        azurePanel.add(azureInfoPanel);

        // OpenRouter Settings
        openRouterPanel = createSection("OpenRouter Configuration");
        
        JPanel openRouterKeyRow = createRow("API Key:", openRouterApiKeyField);
        JButton showOpenRouterKeyBtn = new JButton("Show");
        showOpenRouterKeyBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
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
        
        // Populate OpenRouter models - VERIFIED WORKING FREE MODELS
        // These models have been tested and confirmed working with free API keys
        openRouterModelCombo.addItem("meta-llama/llama-3.3-70b-instruct:free");
        openRouterModelCombo.addItem("tngtech/deepseek-r1t2-chimera:free");
        openRouterModelCombo.setEditable(true);
        
        JPanel modelRow = createRow("Model:", openRouterModelCombo);
        openRouterPanel.add(modelRow);
        
        JLabel openRouterInfo1 = new JLabel("2 verified free models: Llama 3.3 70B & DeepSeek R1T2 Chimera");
        openRouterInfo1.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        openRouterInfo1.setForeground(Color.GRAY);
        JPanel infoPanel1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
        infoPanel1.add(openRouterInfo1);
        openRouterPanel.add(infoPanel1);
        
        JLabel openRouterInfo2 = new JLabel("Get free API key at openrouter.ai/keys (no credit card needed)");
        openRouterInfo2.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        openRouterInfo2.setForeground(Color.GRAY);
        JPanel infoPanel2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 108, 0));
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

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        
        JButton saveBtn = new JButton("Save Configuration");
        saveBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        saveBtn.addActionListener(e -> {
            saveConfig();
            JOptionPane.showMessageDialog(this, "Configuration saved!", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> testConnection());
        
        buttonPanel.add(saveBtn);
        buttonPanel.add(testBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(statusLabel);

        // Browser Verification Status
        JPanel browserPanel = createSection("Client-Side Verification");
        JPanel browserRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        browserRow.add(new JLabel("Headless Browser:"));
        browserRow.add(browserStatusLabel);
        browserPanel.add(browserRow);
        
        JLabel browserInfo = new JLabel("<html><small>Uses Chrome/Chromium to verify XSS payloads actually execute in browser.</small></html>");
        browserInfo.setForeground(Color.GRAY);
        browserPanel.add(browserInfo);
        
        // Check browser availability
        updateBrowserStatus();

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
        mainPanel.add(Box.createVerticalStrut(12));
        mainPanel.add(browserPanel);
        mainPanel.add(Box.createVerticalStrut(20));
        mainPanel.add(buttonPanel);

        // Wrap in scroll pane
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        add(scrollPane, BorderLayout.CENTER);
        
        updateProviderVisibility();
    }

    private JPanel createSection(String title) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setMaximumSize(new Dimension(600, 200));
        return panel;
    }

    private JPanel createRow(String label, JComponent field) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel lbl = new JLabel(label);
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

    private void loadConfig() {
        providerCombo.setSelectedItem(config.getProvider());
        apiKeyField.setText(config.getOpenAIApiKey());
        azureApiKeyField.setText(config.getAzureApiKey());
        modelField.setText(config.getModel());
        endpointField.setText(config.getEndpoint());
        deploymentField.setText(config.getDeployment());
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
    }

    private void saveConfig() {
        String provider = (String) providerCombo.getSelectedItem();
        
        config.updateConfig(
            provider,
            new String(apiKeyField.getPassword()),
            new String(azureApiKeyField.getPassword()),
            modelField.getText().trim(),
            endpointField.getText().trim(),
            deploymentField.getText().trim(),
            new String(openRouterApiKeyField.getPassword()),
            (String) openRouterModelCombo.getSelectedItem(),
            temperatureSlider.getValue() / 100.0
        );
        updateStatus();
    }

    private void updateStatus() {
        if (config.isConfigured()) {
            statusLabel.setText("✓ " + config.getProvider() + " configured");
            statusLabel.setForeground(new Color(0, 150, 0));
        } else {
            statusLabel.setText("⚠ " + config.getStatusMessage());
            statusLabel.setForeground(new Color(200, 100, 0));
        }
    }

    private void updateBrowserStatus() {
        try {
            HeadlessBrowserVerifier verifier = new HeadlessBrowserVerifier();
            if (verifier.isAvailable()) {
                browserStatusLabel.setText(verifier.getStatusMessage());
                browserStatusLabel.setForeground(new Color(0, 150, 0));
            } else {
                browserStatusLabel.setText(verifier.getStatusMessage());
                browserStatusLabel.setForeground(new Color(200, 100, 0));
            }
        } catch (Exception e) {
            browserStatusLabel.setText("✗ Error checking browser: " + e.getMessage());
            browserStatusLabel.setForeground(Color.RED);
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
        statusLabel.setForeground(Color.BLUE);

        new Thread(() -> {
            try {
                String response;
                String provider = config.getProvider();
                
                if ("Azure AI".equals(provider)) {
                    AzureAIService.Configuration azureConfig = new AzureAIService.Configuration();
                    azureConfig.setEndpoint(config.getEndpoint());
                    azureConfig.setDeploymentName(config.getDeployment());
                    azureConfig.setApiKey(config.getAzureApiKey());
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
                    statusLabel.setText("✓ Connection successful!");
                    statusLabel.setForeground(new Color(0, 150, 0));
                    JOptionPane.showMessageDialog(this, 
                        "Connection successful!\n\nAI Response: " + truncate(response, 100),
                        "Success", JOptionPane.INFORMATION_MESSAGE);
                });

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("✗ Connection failed");
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(this, 
                        "Connection failed:\n\n" + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
