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
    private final JComboBox<String> providerCombo = new JComboBox<>(new String[]{"OpenAI", "Azure AI"});
    private final JPasswordField apiKeyField = new JPasswordField(35);
    private final JTextField modelField = new JTextField("gpt-4o-mini", 20);
    private final JTextField endpointField = new JTextField(35);
    private final JTextField deploymentField = new JTextField(20);
    private final JSlider temperatureSlider = new JSlider(0, 100, 30);
    private final JLabel tempValueLabel = new JLabel("0.30");
    private final JLabel statusLabel = new JLabel();
    private final JLabel browserStatusLabel = new JLabel();

    // Azure panel reference
    private JPanel azurePanel;

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
        JPanel providerPanel = createSection("AI Provider");
        providerPanel.add(createRow("Provider:", providerCombo));
        providerCombo.addActionListener(e -> {
            updateProviderVisibility();
            saveConfig();
        });

        // API Key
        JPanel apiKeyPanel = createSection("Authentication");
        apiKeyPanel.add(createRow("API Key:", apiKeyField));
        apiKeyField.addActionListener(e -> saveConfig());
        
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
        
        JPanel keyRow = (JPanel) apiKeyPanel.getComponent(0);
        keyRow.add(showKeyBtn);

        // OpenAI Settings
        JPanel openaiPanel = createSection("OpenAI Settings");
        openaiPanel.add(createRow("Model:", modelField));
        modelField.setToolTipText("e.g., gpt-4o-mini, gpt-4o, gpt-3.5-turbo");

        // Azure Settings
        azurePanel = createSection("Azure AI Settings");
        azurePanel.add(createRow("Endpoint:", endpointField));
        azurePanel.add(createRow("Deployment:", deploymentField));
        endpointField.setToolTipText("e.g., https://your-resource.openai.azure.com");
        deploymentField.setToolTipText("Your Azure deployment name");

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
        mainPanel.add(Box.createVerticalStrut(12));
        mainPanel.add(apiKeyPanel);
        mainPanel.add(Box.createVerticalStrut(12));
        mainPanel.add(openaiPanel);
        mainPanel.add(Box.createVerticalStrut(12));
        mainPanel.add(azurePanel);
        mainPanel.add(Box.createVerticalStrut(12));
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
        boolean isAzure = "Azure AI".equals(providerCombo.getSelectedItem());
        azurePanel.setVisible(isAzure);
        modelField.setEnabled(!isAzure);
        revalidate();
        repaint();
    }

    private void loadConfig() {
        providerCombo.setSelectedItem(config.getProvider());
        apiKeyField.setText(config.getApiKey());
        modelField.setText(config.getModel());
        endpointField.setText(config.getEndpoint());
        deploymentField.setText(config.getDeployment());
        temperatureSlider.setValue((int) (config.getTemperature() * 100));
        tempValueLabel.setText(String.format("%.2f", config.getTemperature()));
        updateProviderVisibility();
    }

    private void saveConfig() {
        config.updateConfig(
            (String) providerCombo.getSelectedItem(),
            new String(apiKeyField.getPassword()),
            modelField.getText().trim(),
            endpointField.getText().trim(),
            deploymentField.getText().trim(),
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
                if ("Azure AI".equals(config.getProvider())) {
                    AzureAIService.Configuration azureConfig = new AzureAIService.Configuration();
                    azureConfig.setEndpoint(config.getEndpoint());
                    azureConfig.setDeploymentName(config.getDeployment());
                    azureConfig.setApiKey(config.getApiKey());
                    azureConfig.setTemperature(0.1);
                    response = new AzureAIService(azureConfig).ask("Say OK", "Say OK");
                } else {
                    OpenAIService.Configuration openaiConfig = new OpenAIService.Configuration();
                    openaiConfig.setApiKey(config.getApiKey());
                    openaiConfig.setModel(config.getModel());
                    openaiConfig.setTemperature(0.1);
                    response = new OpenAIService(openaiConfig).ask("Say OK", "Say OK");
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
