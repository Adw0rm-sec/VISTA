package com.vista.security.ui;

import com.vista.security.core.AIConfigManager;
import com.vista.security.core.BypassEngine;
import com.vista.security.core.BypassKnowledgeBase;
import com.vista.security.core.WAFDetector;
import com.vista.security.model.BypassAttempt;
import com.vista.security.model.BypassResult;
import com.vista.security.service.AIService;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * UI Panel for the Bypass Assistant feature
 * Helps pentesters bypass WAFs and validation filters
 */
public class BypassAssistantPanel extends JPanel {
    
    private final IBurpExtenderCallbacks callbacks;
    private IHttpRequestResponse currentRequest;
    
    // UI Components
    private JTextArea requestViewer;
    private JTextArea responseViewer;
    private JTextField payloadField;
    private JComboBox<String> attackTypeCombo;
    private JTextArea resultsArea;
    private JProgressBar progressBar;
    private JButton findBypassButton;
    private JLabel statusLabel;
    
    // Core components
    private BypassEngine bypassEngine;
    private BypassKnowledgeBase knowledgeBase;
    
    public BypassAssistantPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.knowledgeBase = new BypassKnowledgeBase();
        
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));
        
        add(buildHeaderPanel(), BorderLayout.NORTH);
        add(buildMainContent(), BorderLayout.CENTER);
        add(buildStatusPanel(), BorderLayout.SOUTH);
    }
    
    private JPanel buildHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        
        // Title and description
        JPanel titlePanel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel("🔓 Bypass Assistant");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titlePanel.add(titleLabel, BorderLayout.WEST);
        
        JLabel descLabel = new JLabel("AI-powered WAF and validation bypass engine");
        descLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        descLabel.setForeground(Color.GRAY);
        titlePanel.add(descLabel, BorderLayout.SOUTH);
        
        panel.add(titlePanel, BorderLayout.NORTH);
        
        // Configuration panel
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        configPanel.setBorder(BorderFactory.createTitledBorder("Configuration"));
        
        configPanel.add(new JLabel("Original Payload:"));
        payloadField = new JTextField(30);
        payloadField.setToolTipText("Enter the payload that's being blocked");
        configPanel.add(payloadField);
        
        configPanel.add(new JLabel("Attack Type:"));
        attackTypeCombo = new JComboBox<>(new String[]{
            "XSS", "SQL Injection", "SSTI", "Command Injection", 
            "SSRF", "XXE", "LFI", "IDOR", "Auth Bypass"
        });
        configPanel.add(attackTypeCombo);
        
        findBypassButton = new JButton("🚀 Find Bypass");
        findBypassButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        findBypassButton.addActionListener(e -> startBypassSearch());
        configPanel.add(findBypassButton);
        
        panel.add(configPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JComponent buildMainContent() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.4);
        
        // Left side - Request/Response viewer
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        
        JSplitPane requestResponseSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        requestResponseSplit.setResizeWeight(0.5);
        
        // Request viewer
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestViewer = new JTextArea();
        requestViewer.setEditable(false);
        requestViewer.setFont(new Font("Monospaced", Font.PLAIN, 12));
        requestPanel.add(new JScrollPane(requestViewer), BorderLayout.CENTER);
        
        // Response viewer
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responseViewer = new JTextArea();
        responseViewer.setEditable(false);
        responseViewer.setFont(new Font("Monospaced", Font.PLAIN, 12));
        responsePanel.add(new JScrollPane(responseViewer), BorderLayout.CENTER);
        
        requestResponseSplit.setTopComponent(requestPanel);
        requestResponseSplit.setBottomComponent(responsePanel);
        
        leftPanel.add(requestResponseSplit, BorderLayout.CENTER);
        
        // Right side - Results
        JPanel rightPanel = new JPanel(new BorderLayout(5, 5));
        rightPanel.setBorder(BorderFactory.createTitledBorder("Bypass Results"));
        
        resultsArea = new JTextArea();
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        resultsArea.setText("Load a request and click 'Find Bypass' to start...\n\n" +
                           "How it works:\n" +
                           "1. Analyzes why your payload is blocked\n" +
                           "2. Generates AI-powered bypass variations\n" +
                           "3. Tests each variation intelligently\n" +
                           "4. Shows you what works!\n\n" +
                           "Right-click any request → 'Send to VISTA Bypass Assistant'");
        
        rightPanel.add(new JScrollPane(resultsArea), BorderLayout.CENTER);
        
        // Progress bar
        JPanel progressPanel = new JPanel(new BorderLayout(5, 5));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressPanel.add(progressBar, BorderLayout.CENTER);
        rightPanel.add(progressPanel, BorderLayout.SOUTH);
        
        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(rightPanel);
        
        return splitPane;
    }
    
    private JPanel buildStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        
        statusLabel = new JLabel("Ready");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        panel.add(statusLabel, BorderLayout.WEST);
        
        JLabel infoLabel = new JLabel("💡 Tip: This feature uses AI to generate smart bypass variations");
        infoLabel.setFont(new Font("Segoe UI", Font.ITALIC, 10));
        infoLabel.setForeground(Color.GRAY);
        panel.add(infoLabel, BorderLayout.EAST);
        
        return panel;
    }
    
    public void setRequest(IHttpRequestResponse request) {
        this.currentRequest = request;
        
        if (request != null) {
            // Display request
            byte[] req = request.getRequest();
            if (req != null) {
                requestViewer.setText(new String(req, java.nio.charset.StandardCharsets.ISO_8859_1));
            }
            
            // Display response
            byte[] resp = request.getResponse();
            if (resp != null) {
                String respStr = new String(resp, java.nio.charset.StandardCharsets.ISO_8859_1);
                responseViewer.setText(respStr.substring(0, Math.min(5000, respStr.length())));
            }
            
            statusLabel.setText("Request loaded - Configure payload and click 'Find Bypass'");
        }
    }
    
    private void startBypassSearch() {
        if (currentRequest == null) {
            JOptionPane.showMessageDialog(this, 
                "Please load a request first!\n\nRight-click any request → 'Send to VISTA Bypass Assistant'",
                "No Request", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String payload = payloadField.getText().trim();
        if (payload.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "Please enter the payload that's being blocked",
                "No Payload", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Check if AI is configured
        AIConfigManager configManager = AIConfigManager.getInstance();
        if (!configManager.isConfigured()) {
            JOptionPane.showMessageDialog(this,
                "Please configure AI in Settings tab first!",
                "AI Not Configured", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Initialize bypass engine
        try {
            AIService aiService = null;
            
            // Create AI service based on provider
            if ("OpenAI".equals(configManager.getProvider())) {
                com.vista.security.service.OpenAIService.Configuration config = 
                    new com.vista.security.service.OpenAIService.Configuration();
                config.setApiKey(configManager.getApiKey());
                config.setModel(configManager.getModel());
                config.setTemperature(configManager.getTemperature());
                aiService = new com.vista.security.service.OpenAIService(config);
            } else if ("Azure AI".equals(configManager.getProvider())) {
                com.vista.security.service.AzureAIService.Configuration config = 
                    new com.vista.security.service.AzureAIService.Configuration();
                config.setApiKey(configManager.getApiKey());
                config.setEndpoint(configManager.getEndpoint());
                config.setDeploymentName(configManager.getDeployment());
                config.setTemperature(configManager.getTemperature());
                aiService = new com.vista.security.service.AzureAIService(config);
            }
            
            if (aiService == null) {
                throw new Exception("Unsupported AI provider: " + configManager.getProvider());
            }
            
            bypassEngine = new BypassEngine(
                aiService,
                callbacks.getHelpers(),
                callbacks,
                knowledgeBase
            );
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "Failed to initialize AI service: " + e.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Start bypass search in background
        findBypassButton.setEnabled(false);
        resultsArea.setText("Starting bypass search...\n\n");
        
        String attackType = (String) attackTypeCombo.getSelectedItem();
        
        SwingWorker<BypassResult, String> worker = new SwingWorker<>() {
            @Override
            protected BypassResult doInBackground() {
                return bypassEngine.findBypass(
                    currentRequest,
                    payload,
                    attackType,
                    new BypassEngine.BypassCallback() {
                        @Override
                        public void onPhaseComplete(String phase, String message) {
                            publish(String.format("[%s] %s\n", phase, message));
                        }
                        
                        @Override
                        public void onBypassTested(int current, int total, BypassAttempt attempt) {
                            int progress = (int) ((current / (double) total) * 100);
                            SwingUtilities.invokeLater(() -> {
                                progressBar.setValue(progress);
                                progressBar.setString(String.format("Testing %d/%d", current, total));
                            });
                            
                            String status = attempt.isSuccessful() ? "✓" : "✗";
                            publish(String.format("  %s [%d/%d] %s\n", 
                                status, current, total, 
                                attempt.getPayload().substring(0, Math.min(50, attempt.getPayload().length()))));
                        }
                    }
                );
            }
            
            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    resultsArea.append(message);
                }
                resultsArea.setCaretPosition(resultsArea.getDocument().getLength());
            }
            
            @Override
            protected void done() {
                try {
                    BypassResult result = get();
                    displayResults(result);
                } catch (Exception e) {
                    resultsArea.append("\n❌ Error: " + e.getMessage());
                    statusLabel.setText("Error occurred");
                } finally {
                    findBypassButton.setEnabled(true);
                    progressBar.setValue(0);
                    progressBar.setString("Ready");
                }
            }
        };
        
        worker.execute();
    }
    
    private void displayResults(BypassResult result) {
        resultsArea.append("\n" + "=".repeat(60) + "\n");
        resultsArea.append("FINAL RESULTS\n");
        resultsArea.append("=".repeat(60) + "\n\n");
        
        if (result.isSuccessful()) {
            resultsArea.append("✅ BYPASS FOUND!\n\n");
            resultsArea.append("Successful Payload:\n");
            resultsArea.append(result.getSuccessfulPayload() + "\n\n");
            resultsArea.append("Response Preview:\n");
            resultsArea.append(result.getSuccessfulResponse().substring(0, 
                Math.min(500, result.getSuccessfulResponse().length())) + "\n\n");
            resultsArea.append(String.format("Found after %d attempts in %dms\n", 
                result.getAttempts().size(), result.getTotalTime()));
            
            statusLabel.setText("✓ Bypass found!");
            
            // Offer to copy payload
            int choice = JOptionPane.showConfirmDialog(this,
                "Bypass found! Copy payload to clipboard?",
                "Success", JOptionPane.YES_NO_OPTION);
            if (choice == JOptionPane.YES_OPTION) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(
                        result.getSuccessfulPayload()), null);
            }
        } else {
            resultsArea.append("❌ NO BYPASS FOUND\n\n");
            resultsArea.append(String.format("Tested %d variations without success\n", 
                result.getTotalAttempts()));
            resultsArea.append(String.format("Time taken: %dms\n\n", result.getTotalTime()));
            resultsArea.append("Suggestions:\n");
            resultsArea.append("• Try a different attack type\n");
            resultsArea.append("• Modify the original payload\n");
            resultsArea.append("• Check if there are alternative injection points\n");
            resultsArea.append("• Use Interactive Assistant for manual testing\n");
            
            statusLabel.setText("✗ No bypass found");
        }
        
        resultsArea.setCaretPosition(resultsArea.getDocument().getLength());
    }
}
