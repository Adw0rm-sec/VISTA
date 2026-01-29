package com.vista.security.ui;

import com.vista.security.model.Payload;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Dialog for bulk importing payloads.
 * Users can paste multiple payloads (one per line) and they'll all be added at once.
 */
public class BulkPayloadImportDialog extends JDialog {
    
    private JTextArea payloadsArea;
    private JComboBox<String> categoryCombo;
    private JComboBox<String> contextCombo;
    private JTextField tagsField;
    private JCheckBox autoDetectCheckbox;
    
    private boolean imported = false;
    private List<Payload> payloads;
    private String selectedCategory;
    
    public BulkPayloadImportDialog(Frame parent, String[] categories) {
        super(parent, "Bulk Import Payloads", true);
        
        setLayout(new BorderLayout(10, 10));
        setSize(700, 550);
        setLocationRelativeTo(parent);
        
        // Instructions panel
        JPanel instructionsPanel = new JPanel(new BorderLayout());
        instructionsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        
        JLabel instructionsLabel = new JLabel("<html><b>📋 Paste your payloads below (one per line)</b><br>" +
            "Example:<br>" +
            "&lt;script&gt;alert(1)&lt;/script&gt;<br>" +
            "&lt;img src=x onerror=alert(1)&gt;<br>" +
            "' OR 1=1--<br>" +
            "{{7*7}}</html>");
        instructionsPanel.add(instructionsLabel, BorderLayout.CENTER);
        
        add(instructionsPanel, BorderLayout.NORTH);
        
        // Main panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        // Payloads text area
        JPanel payloadsPanel = new JPanel(new BorderLayout(5, 5));
        payloadsPanel.add(new JLabel("Payloads (one per line):"), BorderLayout.NORTH);
        
        payloadsArea = new JTextArea(15, 60);
        payloadsArea.setLineWrap(false);
        payloadsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane payloadsScroll = new JScrollPane(payloadsArea);
        payloadsPanel.add(payloadsScroll, BorderLayout.CENTER);
        
        mainPanel.add(payloadsPanel, BorderLayout.CENTER);
        
        // Options panel
        JPanel optionsPanel = new JPanel(new GridBagLayout());
        optionsPanel.setBorder(BorderFactory.createTitledBorder("Import Options"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Category
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.weightx = 0;
        optionsPanel.add(new JLabel("Category:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0;
        gbc.weightx = 1.0;
        categoryCombo = new JComboBox<>(categories);
        categoryCombo.setEditable(true);
        optionsPanel.add(categoryCombo, gbc);
        
        // Context
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0;
        optionsPanel.add(new JLabel("Context:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        gbc.weightx = 1.0;
        contextCombo = new JComboBox<>(new String[]{"any", "html-body", "html-attribute", "javascript", "sql", "command"});
        optionsPanel.add(contextCombo, gbc);
        
        // Tags
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.weightx = 0;
        optionsPanel.add(new JLabel("Tags:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        gbc.weightx = 1.0;
        tagsField = new JTextField();
        tagsField.setToolTipText("Comma-separated tags (e.g., basic, custom, imported)");
        optionsPanel.add(tagsField, gbc);
        
        // Auto-detect option
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.gridwidth = 2;
        autoDetectCheckbox = new JCheckBox("Auto-detect payload types (XSS, SQLi, etc.)");
        autoDetectCheckbox.setSelected(true);
        autoDetectCheckbox.setToolTipText("Automatically add tags based on payload content");
        optionsPanel.add(autoDetectCheckbox, gbc);
        
        mainPanel.add(optionsPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton importButton = new JButton("📥 Import All");
        importButton.setFont(new Font("Arial", Font.BOLD, 12));
        importButton.addActionListener(e -> importPayloads());
        buttonPanel.add(importButton);
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        buttonPanel.add(cancelButton);
        
        add(buttonPanel, BorderLayout.SOUTH);
        
        // Focus on text area
        payloadsArea.requestFocusInWindow();
    }
    
    private void importPayloads() {
        String text = payloadsArea.getText().trim();
        if (text.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Please paste some payloads first", 
                "No Payloads", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        selectedCategory = (String) categoryCombo.getSelectedItem();
        if (selectedCategory == null || selectedCategory.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Please select or enter a category", 
                "No Category", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Parse payloads (one per line)
        String[] lines = text.split("\n");
        payloads = new ArrayList<>();
        int skipped = 0;
        
        for (String line : lines) {
            line = line.trim();
            
            // Skip empty lines and comments
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
                continue;
            }
            
            // Skip lines that are too short (likely not payloads)
            if (line.length() < 2) {
                skipped++;
                continue;
            }
            
            // Create payload
            Payload payload = new Payload(line, "Imported payload");
            payload.setContext((String) contextCombo.getSelectedItem());
            payload.setEncoding("none");
            
            // Add user-specified tags
            String tagsText = tagsField.getText().trim();
            if (!tagsText.isEmpty()) {
                String[] tags = tagsText.split(",");
                for (String tag : tags) {
                    payload.addTag(tag.trim());
                }
            }
            
            // Add category tag
            payload.addTag(selectedCategory.toLowerCase());
            payload.addTag("imported");
            
            // Auto-detect payload type
            if (autoDetectCheckbox.isSelected()) {
                autoDetectAndTag(payload);
            }
            
            payloads.add(payload);
        }
        
        if (payloads.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "No valid payloads found.\n\nMake sure each payload is on a separate line.", 
                "No Valid Payloads", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Show confirmation
        String message = String.format(
            "Ready to import %d payload%s to category '%s'",
            payloads.size(),
            payloads.size() == 1 ? "" : "s",
            selectedCategory
        );
        
        if (skipped > 0) {
            message += String.format("\n\n(%d line%s skipped - empty or too short)", 
                skipped, skipped == 1 ? "" : "s");
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            message,
            "Confirm Import",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.INFORMATION_MESSAGE);
        
        if (confirm == JOptionPane.OK_OPTION) {
            imported = true;
            dispose();
        }
    }
    
    /**
     * Auto-detect payload type and add appropriate tags.
     */
    private void autoDetectAndTag(Payload payload) {
        String value = payload.getValue().toLowerCase();
        
        // XSS detection
        if (value.contains("<script") || value.contains("onerror") || value.contains("onload") ||
            value.contains("alert(") || value.contains("prompt(") || value.contains("confirm(") ||
            value.contains("<svg") || value.contains("<img") || value.contains("<iframe") ||
            value.contains("javascript:")) {
            payload.addTag("xss");
        }
        
        // SQL Injection detection
        if (value.contains("' or") || value.contains("\" or") || value.contains("union select") ||
            value.contains("--") || value.contains("/*") || value.contains("sleep(") ||
            value.contains("waitfor") || value.contains("benchmark(") || value.contains("pg_sleep")) {
            payload.addTag("sqli");
        }
        
        // SSTI detection
        if (value.contains("{{") || value.contains("${") || value.contains("<%") ||
            value.contains("#{") || value.contains("*{")) {
            payload.addTag("ssti");
        }
        
        // Command Injection detection
        if (value.contains(";") || value.contains("|") || value.contains("&") ||
            value.contains("`") || value.contains("$(")) {
            payload.addTag("command-injection");
        }
        
        // SSRF detection
        if (value.contains("http://") || value.contains("https://") || value.contains("file://") ||
            value.contains("gopher://") || value.contains("localhost") || value.contains("127.0.0.1") ||
            value.contains("169.254.169.254")) {
            payload.addTag("ssrf");
        }
        
        // XXE detection
        if (value.contains("<!entity") || value.contains("<!doctype") || value.contains("system \"")) {
            payload.addTag("xxe");
        }
        
        // Path Traversal detection
        if (value.contains("../") || value.contains("..\\") || value.contains("%2e%2e")) {
            payload.addTag("path-traversal");
        }
        
        // LFI/RFI detection
        if (value.contains("/etc/passwd") || value.contains("c:\\windows") || 
            value.contains("php://") || value.contains("data://")) {
            payload.addTag("lfi");
        }
    }
    
    public boolean isImported() {
        return imported;
    }
    
    public List<Payload> getPayloads() {
        return payloads;
    }
    
    public String getSelectedCategory() {
        return selectedCategory;
    }
}
