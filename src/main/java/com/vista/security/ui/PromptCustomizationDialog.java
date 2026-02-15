package com.vista.security.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * Dialog for customizing Traffic Monitor AI analysis prompts.
 * Allows users to customize JavaScript and HTML analysis prompts with template variables.
 */
public class PromptCustomizationDialog extends JDialog {
    
    private JTextArea jsPromptArea;
    private JTextArea htmlPromptArea;
    private JTabbedPane tabbedPane;
    
    private String jsPrompt;
    private String htmlPrompt;
    private boolean saved = false;
    
    // Default prompts (same as in IntelligentTrafficAnalyzer)
    private static final String DEFAULT_JS_PROMPT = 
        "You are a security analyzer. Analyze this JavaScript for security issues.\n\n" +
        "URL: {{URL}}\n" +
        "Content-Type: {{CONTENT_TYPE}}\n" +
        "Size: {{SIZE}} bytes\n\n" +
        "JavaScript Code:\n{{CONTENT}}\n\n" +
        "CRITICAL INSTRUCTIONS:\n" +
        "1. ONLY report ACTUAL findings with CONCRETE evidence\n" +
        "2. DO NOT add summary statements like \"No issues found\" or \"Nothing detected\"\n" +
        "3. DO NOT add concluding paragraphs\n" +
        "4. If no issues found, return EMPTY response (no text at all)\n" +
        "5. Each finding MUST have exact code snippet as evidence\n\n" +
        "WHAT TO FIND:\n\n" +
        "1. EXPOSED API KEYS (Type: API_KEY):\n" +
        "   ✅ Report: const API_KEY = \"AIzaSyC_YU1YQKR4YoafqU...\"\n" +
        "   ✅ Report: apiKey: \"sk_live_51H...\"\n" +
        "   ❌ Skip: const apiUrl = \"https://api.example.com\"\n\n" +
        "2. HARDCODED CREDENTIALS (Type: CREDENTIAL):\n" +
        "   ✅ Report: password: \"admin123\"\n" +
        "   ✅ Report: const dbPassword = \"P@ssw0rd\"\n" +
        "   ❌ Skip: passwordField.value (no actual password)\n\n" +
        "3. PRIVATE IP ADDRESSES (Type: PRIVATE_IP):\n" +
        "   ✅ Report: const server = \"192.168.1.100\"\n" +
        "   ✅ Report: apiUrl: \"http://10.0.0.5:8080\"\n" +
        "   ❌ Skip: const publicIP = \"8.8.8.8\"\n\n" +
        "4. AUTHENTICATION TOKENS (Type: TOKEN):\n" +
        "   ✅ Report: const jwt = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\"\n" +
        "   ✅ Report: Authorization: \"Bearer abc123xyz789\"\n" +
        "   ❌ Skip: getToken() (function call, no actual token)\n\n" +
        "5. DEBUG CODE (Type: DEBUG_CODE):\n" +
        "   ✅ Report: console.log(\"Password:\", userPassword)\n" +
        "   ✅ Report: const DEBUG = true\n" +
        "   ❌ Skip: console.log(\"Loading...\") (no sensitive data)\n\n" +
        "6. SENSITIVE CONFIGURATION (Type: SENSITIVE_DATA):\n" +
        "   ✅ Report: const dbUrl = \"mongodb://admin:pass@localhost\"\n" +
        "   ✅ Report: const secret = \"my-secret-key-123\"\n" +
        "   ❌ Skip: const appName = \"MyApp\"\n\n" +
        "RESPONSE FORMAT (STRICT):\n\n" +
        "For EACH finding, use EXACTLY this format:\n" +
        "- Type: [API_KEY|CREDENTIAL|PRIVATE_IP|TOKEN|DEBUG_CODE|SENSITIVE_DATA]\n" +
        "- Severity: [CRITICAL|HIGH|MEDIUM|LOW]\n" +
        "- Evidence: [exact code snippet from the JavaScript]\n" +
        "- Description: [one sentence explaining the issue]\n\n" +
        "REMEMBER:\n" +
        "- NO summary statements\n" +
        "- NO concluding paragraphs\n" +
        "- ONLY report actual findings\n" +
        "- If nothing found, return EMPTY response";
    
    private static final String DEFAULT_HTML_PROMPT = 
        "You are a security analyzer. Analyze this HTML for security issues.\n\n" +
        "URL: {{URL}}\n" +
        "Content-Type: {{CONTENT_TYPE}}\n" +
        "Size: {{SIZE}} bytes\n\n" +
        "HTML Content:\n{{CONTENT}}\n\n" +
        "CRITICAL INSTRUCTIONS:\n" +
        "1. ONLY report ACTUAL findings with CONCRETE evidence\n" +
        "2. DO NOT add summary statements like \"No issues found\" or \"Nothing detected\"\n" +
        "3. DO NOT add concluding paragraphs\n" +
        "4. If no issues found, return EMPTY response (no text at all)\n" +
        "5. Each finding MUST have exact HTML snippet as evidence\n\n" +
        "WHAT TO FIND:\n\n" +
        "1. EXPOSED API KEYS (Type: API_KEY):\n" +
        "   ✅ Report: <script src=\"...?key=AIzaSyC_YU1YQKR4YoafqU...\"></script>\n" +
        "   ✅ Report: data-api-key=\"sk_live_51H...\"\n" +
        "   ❌ Skip: <a href=\"https://api.example.com\">API</a>\n\n" +
        "2. HARDCODED CREDENTIALS (Type: CREDENTIAL):\n" +
        "   ✅ Report: <input type=\"hidden\" name=\"password\" value=\"admin123\">\n" +
        "   ✅ Report: <!-- username: admin, password: secret -->\n" +
        "   ❌ Skip: <input type=\"password\" name=\"password\"> (no value)\n\n" +
        "3. PRIVATE IP ADDRESSES (Type: PRIVATE_IP):\n" +
        "   ✅ Report: <a href=\"http://192.168.1.100/admin\">Admin</a>\n" +
        "   ✅ Report: <!-- Internal server: 10.0.0.5 -->\n" +
        "   ❌ Skip: <a href=\"http://8.8.8.8\">DNS</a>\n\n" +
        "4. HIDDEN FORM FIELDS (Type: HIDDEN_FIELD):\n" +
        "   ✅ Report: <input type=\"hidden\" name=\"sessionToken\" value=\"abc123xyz789\">\n" +
        "   ✅ Report: <input type=\"hidden\" name=\"isAdmin\" value=\"true\">\n" +
        "   ❌ Skip: <input type=\"hidden\" name=\"formId\" value=\"contact-form\">\n\n" +
        "5. AUTHENTICATION TOKENS (Type: TOKEN):\n" +
        "   ✅ Report: <meta name=\"csrf-token\" content=\"abc123xyz789\">\n" +
        "   ✅ Report: data-jwt=\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\"\n" +
        "   ❌ Skip: <meta name=\"viewport\" content=\"width=device-width\">\n\n" +
        "6. SENSITIVE COMMENTS (Type: DEBUG_CODE):\n" +
        "   ✅ Report: <!-- TODO: Remove before production - API key: abc123 -->\n" +
        "   ✅ Report: <!-- Debug mode enabled -->\n" +
        "   ❌ Skip: <!-- Copyright 2024 -->\n\n" +
        "RESPONSE FORMAT (STRICT):\n\n" +
        "For EACH finding, use EXACTLY this format:\n" +
        "- Type: [API_KEY|CREDENTIAL|PRIVATE_IP|HIDDEN_FIELD|TOKEN|DEBUG_CODE|SENSITIVE_DATA]\n" +
        "- Severity: [CRITICAL|HIGH|MEDIUM|LOW]\n" +
        "- Evidence: [exact HTML snippet]\n" +
        "- Description: [one sentence explaining the issue]\n\n" +
        "REMEMBER:\n" +
        "- NO summary statements\n" +
        "- NO concluding paragraphs\n" +
        "- ONLY report actual findings\n" +
        "- If nothing found, return EMPTY response";
    
    public PromptCustomizationDialog(Frame owner, String currentJsPrompt, String currentHtmlPrompt) {
        super(owner, "Customize Traffic Monitor Prompts", true);
        
        this.jsPrompt = currentJsPrompt != null && !currentJsPrompt.trim().isEmpty() 
            ? currentJsPrompt : DEFAULT_JS_PROMPT;
        this.htmlPrompt = currentHtmlPrompt != null && !currentHtmlPrompt.trim().isEmpty() 
            ? currentHtmlPrompt : DEFAULT_HTML_PROMPT;
        
        initializeUI();
        setSize(900, 700);
        setLocationRelativeTo(owner);
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        
        // Header panel
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);
        
        // Tabbed pane for JS and HTML prompts
        tabbedPane = new JTabbedPane();
        
        // JavaScript tab
        jsPromptArea = new JTextArea(jsPrompt);
        jsPromptArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        jsPromptArea.setLineWrap(true);
        jsPromptArea.setWrapStyleWord(true);
        JScrollPane jsScrollPane = new JScrollPane(jsPromptArea);
        tabbedPane.addTab("JavaScript Template", jsScrollPane);
        
        // HTML tab
        htmlPromptArea = new JTextArea(htmlPrompt);
        htmlPromptArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        htmlPromptArea.setLineWrap(true);
        htmlPromptArea.setWrapStyleWord(true);
        JScrollPane htmlScrollPane = new JScrollPane(htmlPromptArea);
        tabbedPane.addTab("HTML Template", htmlScrollPane);
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = createButtonPanel();
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JLabel titleLabel = new JLabel("Customize AI Analysis Prompts");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        JTextArea infoArea = new JTextArea(
            "Customize the prompts used for Traffic Monitor AI analysis.\n\n" +
            "Template Variables:\n" +
            "  {{URL}} - Request URL\n" +
            "  {{CONTENT_TYPE}} - Content type (e.g., text/html, application/javascript)\n" +
            "  {{SIZE}} - Content size in bytes\n" +
            "  {{CONTENT}} - Actual content to analyze\n\n" +
            "Tips:\n" +
            "  • Be specific about what to find and what to skip\n" +
            "  • Include examples (✅ Report / ❌ Skip)\n" +
            "  • Explicitly forbid summary statements\n" +
            "  • Specify exact response format"
        );
        infoArea.setEditable(false);
        infoArea.setBackground(new Color(255, 255, 220));
        infoArea.setFont(new Font("Arial", Font.PLAIN, 11));
        infoArea.setBorder(new EmptyBorder(5, 5, 5, 5));
        panel.add(infoArea, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        
        JButton resetButton = new JButton("Reset to Default");
        resetButton.addActionListener(this::resetToDefault);
        panel.add(resetButton);
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        panel.add(cancelButton);
        
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(this::savePrompts);
        panel.add(saveButton);
        
        return panel;
    }
    
    private void resetToDefault(ActionEvent e) {
        int result = JOptionPane.showConfirmDialog(
            this,
            "Reset to default prompts? This will discard your changes.",
            "Confirm Reset",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        
        if (result == JOptionPane.YES_OPTION) {
            jsPromptArea.setText(DEFAULT_JS_PROMPT);
            htmlPromptArea.setText(DEFAULT_HTML_PROMPT);
        }
    }
    
    private void savePrompts(ActionEvent e) {
        jsPrompt = jsPromptArea.getText();
        htmlPrompt = htmlPromptArea.getText();
        saved = true;
        
        JOptionPane.showMessageDialog(
            this,
            "Prompts saved successfully!\n\nThey will be used for all future Traffic Monitor analyses.",
            "Success",
            JOptionPane.INFORMATION_MESSAGE
        );
        
        dispose();
    }
    
    public boolean isSaved() {
        return saved;
    }
    
    public String getJsPrompt() {
        return jsPrompt;
    }
    
    public String getHtmlPrompt() {
        return htmlPrompt;
    }
    
    public static String getDefaultJsPrompt() {
        return DEFAULT_JS_PROMPT;
    }
    
    public static String getDefaultHtmlPrompt() {
        return DEFAULT_HTML_PROMPT;
    }
}
