package com.vista.security.ui;

import com.vista.security.model.Payload;

import javax.swing.*;
import java.awt.*;

/**
 * Simple dialog for adding/editing payloads.
 */
public class PayloadEditorDialog extends JDialog {
    
    private JTextArea payloadValueArea;
    private JTextField descriptionField;
    private JComboBox<String> categoryCombo;
    private JComboBox<String> contextCombo;
    private JTextField tagsField;
    
    private boolean saved = false;
    private Payload result;
    
    public PayloadEditorDialog(Frame parent, String[] categories) {
        super(parent, "Add Payload", true);
        
        setLayout(new BorderLayout(10, 10));
        setSize(600, 450);
        setLocationRelativeTo(parent);
        
        // Main panel
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Payload value
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(new JLabel("Payload:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0;
        gbc.weightx = 1.0; gbc.weighty = 0.4;
        gbc.fill = GridBagConstraints.BOTH;
        payloadValueArea = new JTextArea(5, 40);
        payloadValueArea.setLineWrap(true);
        payloadValueArea.setWrapStyleWord(true);
        payloadValueArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane payloadScroll = new JScrollPane(payloadValueArea);
        mainPanel.add(payloadScroll, gbc);
        
        // Description
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0; gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(new JLabel("Description:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        gbc.weightx = 1.0;
        descriptionField = new JTextField(40);
        mainPanel.add(descriptionField, gbc);
        
        // Category
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.weightx = 0;
        mainPanel.add(new JLabel("Category:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        gbc.weightx = 1.0;
        categoryCombo = new JComboBox<>(categories);
        categoryCombo.setEditable(true);
        mainPanel.add(categoryCombo, gbc);
        
        // Context
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.weightx = 0;
        mainPanel.add(new JLabel("Context:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 3;
        gbc.weightx = 1.0;
        contextCombo = new JComboBox<>(new String[]{"any", "html-body", "html-attribute", "javascript", "sql", "command"});
        mainPanel.add(contextCombo, gbc);
        
        // Tags
        gbc.gridx = 0; gbc.gridy = 4;
        gbc.weightx = 0;
        mainPanel.add(new JLabel("Tags:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 4;
        gbc.weightx = 1.0;
        tagsField = new JTextField(40);
        tagsField.setToolTipText("Comma-separated tags (e.g., basic, waf-bypass, rce)");
        mainPanel.add(tagsField, gbc);
        
        add(mainPanel, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton saveButton = new JButton("💾 Save");
        saveButton.addActionListener(e -> save());
        buttonPanel.add(saveButton);
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        buttonPanel.add(cancelButton);
        
        add(buttonPanel, BorderLayout.SOUTH);
        
        // Focus on payload field
        payloadValueArea.requestFocusInWindow();
    }
    
    private void save() {
        String value = payloadValueArea.getText().trim();
        if (value.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Payload value cannot be empty", "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        String description = descriptionField.getText().trim();
        if (description.isEmpty()) {
            description = "Custom payload";
        }
        
        result = new Payload(value, description);
        result.setContext((String) contextCombo.getSelectedItem());
        result.setEncoding("none");
        
        // Parse tags
        String tagsText = tagsField.getText().trim();
        if (!tagsText.isEmpty()) {
            String[] tags = tagsText.split(",");
            for (String tag : tags) {
                result.addTag(tag.trim());
            }
        }
        
        // Add category tag
        String category = (String) categoryCombo.getSelectedItem();
        if (category != null && !category.trim().isEmpty()) {
            result.addTag(category.toLowerCase());
        }
        
        saved = true;
        dispose();
    }
    
    public boolean isSaved() {
        return saved;
    }
    
    public Payload getPayload() {
        return result;
    }
    
    public String getSelectedCategory() {
        return (String) categoryCombo.getSelectedItem();
    }
}
