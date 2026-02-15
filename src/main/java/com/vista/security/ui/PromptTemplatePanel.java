package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import com.vista.security.core.PromptTemplateManager;
import com.vista.security.model.PromptTemplate;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * UI Panel for managing AI prompt templates.
 * Allows users to create, edit, import/export, and organize templates.
 */
public class PromptTemplatePanel extends JPanel {
    
    private final IBurpExtenderCallbacks callbacks;
    private final PromptTemplateManager templateManager;
    
    // UI Components
    private JTable templateTable;
    private TemplateTableModel tableModel;
    private JTextField searchField;
    private JComboBox<String> categoryFilter;
    private JTextArea systemPromptArea;
    private JTextArea userPromptArea;
    private JTextField nameField;
    private JTextField descriptionField;
    private JComboBox<String> categoryCombo;
    private JTextField tagsField;
    private JCheckBox activeCheckbox;
    private JLabel usageCountLabel;
    private JButton saveButton;
    private JButton deleteButton;
    private JButton newButton;
    private JButton copyButton;
    
    private PromptTemplate currentTemplate = null;
    private boolean isEditing = false;
    
    public PromptTemplatePanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.templateManager = PromptTemplateManager.getInstance();
        
        setLayout(new BorderLayout());
        buildUI();
        refreshTemplateList();
    }

    private void buildUI() {
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout(8, 8));
        headerPanel.setBorder(new EmptyBorder(12, 12, 8, 12));
        
        JLabel titleLabel = new JLabel("AI Prompt Templates");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        
        JLabel subtitleLabel = new JLabel("Create and manage custom AI prompts for different testing scenarios");
        subtitleLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        subtitleLabel.setForeground(new Color(100, 100, 110));
        
        JPanel titleStack = new JPanel();
        titleStack.setLayout(new BoxLayout(titleStack, BoxLayout.Y_AXIS));
        titleStack.add(titleLabel);
        titleStack.add(Box.createVerticalStrut(2));
        titleStack.add(subtitleLabel);
        
        headerPanel.add(titleStack, BorderLayout.WEST);
        
        // Search and filter bar
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        
        filterPanel.add(new JLabel("🔍 Search:"));
        searchField = new JTextField(20);
        searchField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent e) {
                filterTemplates();
            }
        });
        filterPanel.add(searchField);
        
        filterPanel.add(Box.createHorizontalStrut(12));
        filterPanel.add(new JLabel("Category:"));
        categoryFilter = new JComboBox<>();
        categoryFilter.addItem("All Categories");
        categoryFilter.addActionListener(e -> filterTemplates());
        filterPanel.add(categoryFilter);
        
        headerPanel.add(filterPanel, BorderLayout.SOUTH);
        
        // Main split pane
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.35);
        
        // Left: Template list
        mainSplit.setLeftComponent(buildTemplateListPanel());
        
        // Right: Template editor
        mainSplit.setRightComponent(buildEditorPanel());
        
        add(headerPanel, BorderLayout.NORTH);
        add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel buildTemplateListPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(8, 8, 8, 4));
        
        // Table
        tableModel = new TemplateTableModel();
        templateTable = new JTable(tableModel);
        templateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        templateTable.setRowHeight(24);
        templateTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadSelectedTemplate();
            }
        });
        
        // Column widths
        templateTable.getColumnModel().getColumn(0).setPreferredWidth(200); // Name
        templateTable.getColumnModel().getColumn(1).setPreferredWidth(100); // Category
        templateTable.getColumnModel().getColumn(2).setPreferredWidth(50);  // Active
        
        // Center align Active column
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        templateTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        
        JScrollPane tableScroll = new JScrollPane(templateTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Templates"));
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        
        newButton = new JButton("➕ New");
        newButton.setToolTipText("Create new template");
        newButton.addActionListener(e -> createNewTemplate());
        
        copyButton = new JButton("📋 Copy");
        copyButton.setToolTipText("Copy selected template");
        copyButton.addActionListener(e -> copySelectedTemplate());
        copyButton.setEnabled(false);
        
        JButton importBtn = new JButton("📥 Import");
        importBtn.setToolTipText("Import template from file");
        importBtn.addActionListener(e -> importTemplate());
        
        JButton exportBtn = new JButton("📤 Export");
        exportBtn.setToolTipText("Export selected template");
        exportBtn.addActionListener(e -> exportSelectedTemplate());
        exportBtn.setEnabled(false);
        
        buttonPanel.add(newButton);
        buttonPanel.add(copyButton);
        buttonPanel.add(importBtn);
        buttonPanel.add(exportBtn);
        
        // Enable/disable export button based on selection
        templateTable.getSelectionModel().addListSelectionListener(e -> {
            boolean hasSelection = templateTable.getSelectedRow() >= 0;
            exportBtn.setEnabled(hasSelection);
            copyButton.setEnabled(hasSelection);
        });
        
        panel.add(tableScroll, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel buildEditorPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(8, 4, 8, 8));
        
        // Editor form
        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        
        // Basic info section
        JPanel basicInfoPanel = new JPanel();
        basicInfoPanel.setLayout(new BoxLayout(basicInfoPanel, BoxLayout.Y_AXIS));
        basicInfoPanel.setBorder(BorderFactory.createTitledBorder("Template Information"));
        
        nameField = new JTextField(30);
        descriptionField = new JTextField(30);
        categoryCombo = new JComboBox<>(new String[]{"Exploitation", "Reconnaissance", "Bypass", "General"});
        tagsField = new JTextField(30);
        activeCheckbox = new JCheckBox("Active", true);
        usageCountLabel = new JLabel("Usage: 0 times");
        usageCountLabel.setFont(new Font("Segoe UI", Font.ITALIC, 10));
        
        basicInfoPanel.add(createFormRow("Name:", nameField));
        basicInfoPanel.add(createFormRow("Description:", descriptionField));
        basicInfoPanel.add(createFormRow("Category:", categoryCombo));
        basicInfoPanel.add(createFormRow("Tags:", tagsField));
        JPanel activeRow = createFormRow("", activeCheckbox);
        activeRow.add(Box.createHorizontalStrut(20));
        activeRow.add(usageCountLabel);
        basicInfoPanel.add(activeRow);
        
        // System prompt section
        JPanel systemPromptPanel = new JPanel(new BorderLayout(4, 4));
        systemPromptPanel.setBorder(BorderFactory.createTitledBorder("System Prompt"));
        
        systemPromptArea = new JTextArea(6, 50);
        systemPromptArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        JScrollPane systemScroll = new JScrollPane(systemPromptArea);
        
        JPanel systemToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        systemToolbar.add(new JLabel("💡 Define AI's role and expertise"));
        
        systemPromptPanel.add(systemToolbar, BorderLayout.NORTH);
        systemPromptPanel.add(systemScroll, BorderLayout.CENTER);
        
        // User prompt section
        JPanel userPromptPanel = new JPanel(new BorderLayout(4, 4));
        userPromptPanel.setBorder(BorderFactory.createTitledBorder("User Prompt (with Variables)"));
        
        userPromptArea = new JTextArea(12, 50);
        userPromptArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        userPromptArea.setLineWrap(true);
        userPromptArea.setWrapStyleWord(true);
        JScrollPane userScroll = new JScrollPane(userPromptArea);
        
        JPanel userToolbar = buildVariableToolbar();
        
        userPromptPanel.add(userToolbar, BorderLayout.NORTH);
        userPromptPanel.add(userScroll, BorderLayout.CENTER);
        
        formPanel.add(basicInfoPanel);
        formPanel.add(Box.createVerticalStrut(8));
        formPanel.add(systemPromptPanel);
        formPanel.add(Box.createVerticalStrut(8));
        formPanel.add(userPromptPanel);
        
        JScrollPane formScroll = new JScrollPane(formPanel);
        formScroll.setBorder(null);
        formScroll.getVerticalScrollBar().setUnitIncrement(16);
        
        // Action buttons
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        
        saveButton = new JButton("💾 Save Template");
        saveButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        saveButton.addActionListener(e -> saveCurrentTemplate());
        saveButton.setEnabled(false);
        
        deleteButton = new JButton("🗑️ Delete");
        deleteButton.addActionListener(e -> deleteCurrentTemplate());
        deleteButton.setEnabled(false);
        
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> cancelEdit());
        
        actionPanel.add(cancelBtn);
        actionPanel.add(deleteButton);
        actionPanel.add(saveButton);
        
        panel.add(formScroll, BorderLayout.CENTER);
        panel.add(actionPanel, BorderLayout.SOUTH);
        
        return panel;
    }

    private JPanel buildVariableToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        
        toolbar.add(new JLabel("💡 Insert variables:"));
        
        String[] commonVars = {
            "USER_QUERY", "REQUEST", "RESPONSE", "PARAMETERS_LIST", "REFLECTION_ANALYSIS",
            "WAF_DETECTION", "ENDPOINT_TYPE", "RISK_SCORE", "PREDICTED_VULNS"
        };
        
        for (String var : commonVars) {
            JButton varBtn = new JButton("{{" + var + "}}");
            varBtn.setFont(new Font("Segoe UI", Font.PLAIN, 9));
            varBtn.setMargin(new Insets(2, 4, 2, 4));
            varBtn.setToolTipText("Insert " + var + " variable");
            if (var.equals("USER_QUERY")) {
                varBtn.setForeground(new Color(0, 100, 200));
                varBtn.setFont(new Font("Segoe UI", Font.BOLD, 9));
                varBtn.setToolTipText("Insert USER_QUERY - User's actual question (IMPORTANT!)");
            }
            varBtn.addActionListener(e -> insertVariable(var));
            toolbar.add(varBtn);
        }
        
        JButton moreBtn = new JButton("More...");
        moreBtn.setFont(new Font("Segoe UI", Font.PLAIN, 9));
        moreBtn.setMargin(new Insets(2, 6, 2, 6));
        moreBtn.addActionListener(e -> showAllVariables());
        toolbar.add(moreBtn);
        
        return toolbar;
    }
    
    private JPanel createFormRow(String label, JComponent component) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        if (!label.isEmpty()) {
            JLabel lbl = new JLabel(label);
            lbl.setPreferredSize(new Dimension(100, 25));
            row.add(lbl);
        } else {
            row.add(Box.createHorizontalStrut(108));
        }
        row.add(component);
        return row;
    }
    
    private void insertVariable(String varName) {
        String varText = "{{" + varName + "}}";
        int pos = userPromptArea.getCaretPosition();
        try {
            userPromptArea.getDocument().insertString(pos, varText, null);
        } catch (Exception e) {
            userPromptArea.append(varText);
        }
    }
    
    private void showAllVariables() {
        String[] allVars = {
            "USER_QUERY", "REQUEST", "RESPONSE", "PARAMETERS_LIST", "REFLECTION_ANALYSIS",
            "WAF_DETECTION", "ENDPOINT_TYPE", "RISK_SCORE", "PREDICTED_VULNS",
            "DEEP_REQUEST_ANALYSIS", "DEEP_RESPONSE_ANALYSIS", "ERROR_MESSAGES",
            "SENSITIVE_DATA", "RESPONSE_SIZE", "STATUS_CODE", "CONTENT_TYPE",
            "SECURITY_HEADERS", "COOKIES", "AUTH_TYPE", "TECH_STACK",
            "INJECTION_POINTS", "ENCODING_DETECTED", "FILTER_DETECTED",
            "TESTING_HISTORY", "CONVERSATION_CONTEXT"
        };
        
        StringBuilder help = new StringBuilder();
        help.append("Available Variables:\n\n");
        help.append("USER_QUERY - Your actual question/prompt (IMPORTANT!)\n\n");
        for (String var : allVars) {
            if (!var.equals("USER_QUERY")) {
                help.append("{{").append(var).append("}}\n");
            }
        }
        help.append("\nThese variables will be replaced with actual values when the template is used.");
        help.append("\n\nIMPORTANT: Always include {{USER_QUERY}} in your templates so the AI");
        help.append("\nknows what you actually asked and can provide relevant responses!");
        
        JTextArea textArea = new JTextArea(help.toString(), 20, 40);
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        JOptionPane.showMessageDialog(this, scrollPane, "Available Variables", JOptionPane.INFORMATION_MESSAGE);
    }

    // Template management methods
    
    private void refreshTemplateList() {
        List<PromptTemplate> templates = templateManager.getAllTemplates();
        tableModel.setTemplates(templates);
        
        // Update category filter
        categoryFilter.removeAllItems();
        categoryFilter.addItem("All Categories");
        for (String category : templateManager.getCategories()) {
            categoryFilter.addItem(category);
        }
    }
    
    private void filterTemplates() {
        String searchText = searchField.getText().toLowerCase();
        String category = (String) categoryFilter.getSelectedItem();
        
        List<PromptTemplate> allTemplates = templateManager.getAllTemplates();
        List<PromptTemplate> filtered = new ArrayList<>();
        
        for (PromptTemplate template : allTemplates) {
            boolean matchesSearch = searchText.isEmpty() || 
                template.getName().toLowerCase().contains(searchText) ||
                template.getDescription().toLowerCase().contains(searchText);
            
            boolean matchesCategory = "All Categories".equals(category) ||
                template.getCategory().equals(category);
            
            if (matchesSearch && matchesCategory) {
                filtered.add(template);
            }
        }
        
        tableModel.setTemplates(filtered);
    }
    
    private void loadSelectedTemplate() {
        int selectedRow = templateTable.getSelectedRow();
        if (selectedRow < 0) {
            clearEditor();
            return;
        }
        
        PromptTemplate template = tableModel.getTemplateAt(selectedRow);
        if (template == null) return;
        
        currentTemplate = template;
        isEditing = true;
        
        nameField.setText(template.getName());
        descriptionField.setText(template.getDescription());
        categoryCombo.setSelectedItem(template.getCategory());
        tagsField.setText(String.join(", ", template.getTags()));
        activeCheckbox.setSelected(template.isActive());
        usageCountLabel.setText("Usage: " + template.getUsageCount() + " times");
        systemPromptArea.setText(template.getSystemPrompt());
        userPromptArea.setText(template.getUserPrompt());
        
        boolean isBuiltIn = template.isBuiltIn();
        nameField.setEnabled(!isBuiltIn);
        descriptionField.setEnabled(!isBuiltIn);
        categoryCombo.setEnabled(!isBuiltIn);
        tagsField.setEnabled(!isBuiltIn);
        systemPromptArea.setEnabled(!isBuiltIn);
        userPromptArea.setEnabled(!isBuiltIn);
        
        saveButton.setEnabled(!isBuiltIn);
        deleteButton.setEnabled(!isBuiltIn);
        
        if (isBuiltIn) {
            JOptionPane.showMessageDialog(this,
                "This is a built-in template and cannot be edited.\nUse 'Copy' to create an editable version.",
                "Built-in Template",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void clearEditor() {
        currentTemplate = null;
        isEditing = false;
        
        nameField.setText("");
        descriptionField.setText("");
        categoryCombo.setSelectedIndex(0);
        tagsField.setText("");
        activeCheckbox.setSelected(true);
        usageCountLabel.setText("Usage: 0 times");
        systemPromptArea.setText("");
        userPromptArea.setText("");
        
        nameField.setEnabled(true);
        descriptionField.setEnabled(true);
        categoryCombo.setEnabled(true);
        tagsField.setEnabled(true);
        systemPromptArea.setEnabled(true);
        userPromptArea.setEnabled(true);
        
        saveButton.setEnabled(false);
        deleteButton.setEnabled(false);
    }

    private void createNewTemplate() {
        clearEditor();
        isEditing = true;
        
        nameField.setText("New Template");
        descriptionField.setText("Description of this template");
        systemPromptArea.setText("You are an expert penetration tester.");
        userPromptArea.setText("Analyze this request:\n\nREQUEST:\n{{REQUEST}}\n\nRESPONSE:\n{{RESPONSE}}");
        
        saveButton.setEnabled(true);
        deleteButton.setEnabled(false);
        
        nameField.requestFocus();
        nameField.selectAll();
    }
    
    private void copySelectedTemplate() {
        if (currentTemplate == null) return;
        
        PromptTemplate copy = currentTemplate.copy();
        copy.setName(copy.getName() + " (Copy)");
        
        currentTemplate = copy;
        isEditing = true;
        
        nameField.setText(copy.getName());
        saveButton.setEnabled(true);
        deleteButton.setEnabled(false);
        
        nameField.requestFocus();
        nameField.selectAll();
    }
    
    private void saveCurrentTemplate() {
        String name = nameField.getText().trim();
        String description = descriptionField.getText().trim();
        String category = (String) categoryCombo.getSelectedItem();
        String tagsText = tagsField.getText().trim();
        String systemPrompt = systemPromptArea.getText().trim();
        String userPrompt = userPromptArea.getText().trim();
        
        if (name.isEmpty() || systemPrompt.isEmpty() || userPrompt.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "Name, System Prompt, and User Prompt are required.",
                "Validation Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        try {
            PromptTemplate template;
            if (currentTemplate != null && !currentTemplate.isBuiltIn()) {
                // Update existing
                template = currentTemplate;
                template.setName(name);
                template.setDescription(description);
                template.setCategory(category);
                template.setSystemPrompt(systemPrompt);
                template.setUserPrompt(userPrompt);
                template.setActive(activeCheckbox.isSelected());
                
                // Update tags
                template.getTags().clear();
                if (!tagsText.isEmpty()) {
                    for (String tag : tagsText.split(",")) {
                        template.addTag(tag.trim());
                    }
                }
            } else {
                // Create new
                template = new PromptTemplate(name, category, "@user", description, systemPrompt, userPrompt);
                template.setActive(activeCheckbox.isSelected());
                
                if (!tagsText.isEmpty()) {
                    for (String tag : tagsText.split(",")) {
                        template.addTag(tag.trim());
                    }
                }
            }
            
            templateManager.saveTemplate(template);
            refreshTemplateList();
            
            JOptionPane.showMessageDialog(this,
                "Template saved successfully!",
                "Success",
                JOptionPane.INFORMATION_MESSAGE);
            
            clearEditor();
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "Failed to save template:\n" + e.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void deleteCurrentTemplate() {
        if (currentTemplate == null || currentTemplate.isBuiltIn()) return;
        
        int result = JOptionPane.showConfirmDialog(this,
            "Delete template '" + currentTemplate.getName() + "'?",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (result == JOptionPane.YES_OPTION) {
            try {
                templateManager.deleteTemplate(currentTemplate.getId());
                refreshTemplateList();
                clearEditor();
                
                JOptionPane.showMessageDialog(this,
                    "Template deleted successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "Failed to delete template:\n" + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void cancelEdit() {
        if (isEditing) {
            int result = JOptionPane.showConfirmDialog(this,
                "Discard unsaved changes?",
                "Confirm Cancel",
                JOptionPane.YES_NO_OPTION);
            
            if (result == JOptionPane.YES_OPTION) {
                clearEditor();
            }
        } else {
            clearEditor();
        }
    }

    private void importTemplate() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Template");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));
        
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                templateManager.importTemplate(file);
                refreshTemplateList();
                
                JOptionPane.showMessageDialog(this,
                    "Template imported successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "Failed to import template:\n" + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void exportSelectedTemplate() {
        if (currentTemplate == null) return;
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Template");
        fileChooser.setSelectedFile(new File(currentTemplate.getName().replaceAll("[^a-zA-Z0-9-]", "_") + ".json"));
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));
        
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                if (!file.getName().endsWith(".json")) {
                    file = new File(file.getAbsolutePath() + ".json");
                }
                
                templateManager.exportTemplate(currentTemplate.getId(), file);
                
                JOptionPane.showMessageDialog(this,
                    "Template exported successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                    "Failed to export template:\n" + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    // Table model
    
    private static class TemplateTableModel extends AbstractTableModel {
        private final String[] columnNames = {"Name", "Category", "Active"};
        private List<PromptTemplate> templates = new ArrayList<>();
        
        public void setTemplates(List<PromptTemplate> templates) {
            this.templates = new ArrayList<>(templates);
            fireTableDataChanged();
        }
        
        public PromptTemplate getTemplateAt(int row) {
            if (row >= 0 && row < templates.size()) {
                return templates.get(row);
            }
            return null;
        }
        
        @Override
        public int getRowCount() {
            return templates.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int row, int column) {
            PromptTemplate template = templates.get(row);
            return switch (column) {
                case 0 -> template.getName() + (template.isBuiltIn() ? " 🔒" : "");
                case 1 -> template.getCategory();
                case 2 -> template.isActive() ? "✓" : "";
                default -> "";
            };
        }
        
        @Override
        public Class<?> getColumnClass(int column) {
            return String.class;
        }
    }
}
