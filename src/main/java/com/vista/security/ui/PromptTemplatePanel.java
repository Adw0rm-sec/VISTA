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

import static com.vista.security.ui.VistaTheme.*;

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
        headerPanel.setBackground(VistaTheme.BG_CARD);
        headerPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, VistaTheme.BORDER),
            new EmptyBorder(14, 16, 10, 16)
        ));
        
        JLabel titleLabel = new JLabel("AI Prompt Templates");
        titleLabel.setFont(VistaTheme.FONT_TITLE);
        titleLabel.setForeground(VistaTheme.TEXT_PRIMARY);
        
        JLabel subtitleLabel = new JLabel("Create and manage custom AI prompts for different testing scenarios");
        subtitleLabel.setFont(VistaTheme.FONT_SMALL);
        subtitleLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        
        JPanel titleStack = new JPanel();
        titleStack.setLayout(new BoxLayout(titleStack, BoxLayout.Y_AXIS));
        titleStack.add(titleLabel);
        titleStack.add(Box.createVerticalStrut(2));
        titleStack.add(subtitleLabel);
        
        headerPanel.add(titleStack, BorderLayout.WEST);
        
        // Search and filter bar
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterPanel.setBackground(VistaTheme.BG_CARD);
        
        JLabel searchLabel = new JLabel("Search:");
        searchLabel.setFont(VistaTheme.FONT_LABEL);
        searchLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        filterPanel.add(searchLabel);
        searchField = new JTextField(20);
        VistaTheme.styleTextField(searchField);
        searchField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent e) {
                filterTemplates();
            }
        });
        filterPanel.add(searchField);
        
        filterPanel.add(Box.createHorizontalStrut(12));
        JLabel catLabel = new JLabel("Category:");
        catLabel.setFont(VistaTheme.FONT_LABEL);
        catLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        filterPanel.add(catLabel);
        categoryFilter = new JComboBox<>();
        VistaTheme.styleComboBox(categoryFilter);
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
        VistaTheme.styleTable(templateTable);
        templateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
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
        tableScroll.setBorder(VistaTheme.sectionBorder("Templates"));
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        
        newButton = VistaTheme.primaryButton("New");
        newButton.setToolTipText("Create new template");
        newButton.addActionListener(e -> createNewTemplate());
        
        copyButton = VistaTheme.compactButton("Copy");
        copyButton.setToolTipText("Copy selected template");
        copyButton.addActionListener(e -> copySelectedTemplate());
        copyButton.setEnabled(false);
        
        JButton importBtn = VistaTheme.compactButton("Import");
        importBtn.setToolTipText("Import template from file");
        importBtn.addActionListener(e -> importTemplate());
        
        JButton exportBtn = VistaTheme.compactButton("Export");
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
        panel.setBackground(VistaTheme.BG_PANEL);
        panel.setBorder(new EmptyBorder(8, 4, 8, 8));
        
        // Editor form
        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        
        // Basic info section
        JPanel basicInfoPanel = new JPanel();
        basicInfoPanel.setLayout(new BoxLayout(basicInfoPanel, BoxLayout.Y_AXIS));
        basicInfoPanel.setBorder(VistaTheme.sectionBorder("Template Information"));
        
        nameField = new JTextField(30);
        VistaTheme.styleTextField(nameField);
        descriptionField = new JTextField(30);
        VistaTheme.styleTextField(descriptionField);
        categoryCombo = new JComboBox<>(new String[]{"Exploitation", "Reconnaissance", "Bypass", "General"});
        VistaTheme.styleComboBox(categoryCombo);
        tagsField = new JTextField(30);
        VistaTheme.styleTextField(tagsField);
        activeCheckbox = new JCheckBox("Active", true);
        activeCheckbox.setFont(VistaTheme.FONT_BODY);
        activeCheckbox.setForeground(VistaTheme.TEXT_PRIMARY);
        usageCountLabel = new JLabel("Usage: 0 times");
        usageCountLabel.setFont(VistaTheme.FONT_SMALL);
        usageCountLabel.setForeground(VistaTheme.TEXT_MUTED);
        
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
        systemPromptPanel.setBorder(VistaTheme.sectionBorder("System Prompt"));
        
        systemPromptArea = new JTextArea(6, 50);
        VistaTheme.styleCodeArea(systemPromptArea);
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        JScrollPane systemScroll = VistaTheme.styledScrollPane(systemPromptArea);
        
        JPanel systemToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JLabel systemHint = new JLabel("Define AI's role and expertise");
        systemHint.setFont(VistaTheme.FONT_SMALL);
        systemHint.setForeground(VistaTheme.TEXT_MUTED);
        systemToolbar.add(systemHint);
        
        systemPromptPanel.add(systemToolbar, BorderLayout.NORTH);
        systemPromptPanel.add(systemScroll, BorderLayout.CENTER);
        
        // User prompt section
        JPanel userPromptPanel = new JPanel(new BorderLayout(4, 4));
        userPromptPanel.setBorder(VistaTheme.sectionBorder("User Prompt (with Variables)"));
        
        userPromptArea = new JTextArea(12, 50);
        VistaTheme.styleCodeArea(userPromptArea);
        userPromptArea.setLineWrap(true);
        userPromptArea.setWrapStyleWord(true);
        JScrollPane userScroll = VistaTheme.styledScrollPane(userPromptArea);
        
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
        
        saveButton = VistaTheme.primaryButton("Save Template");
        saveButton.addActionListener(e -> saveCurrentTemplate());
        saveButton.setEnabled(false);
        
        deleteButton = VistaTheme.secondaryButton("Delete");
        deleteButton.addActionListener(e -> deleteCurrentTemplate());
        deleteButton.setEnabled(false);
        
        JButton cancelBtn = VistaTheme.compactButton("Cancel");
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
        
        JLabel varHint = new JLabel("Insert variables:");
        varHint.setFont(VistaTheme.FONT_SMALL);
        varHint.setForeground(VistaTheme.TEXT_MUTED);
        toolbar.add(varHint);
        
        String[] commonVars = {
            "USER_QUERY", "REQUEST", "RESPONSE", "PARAMETERS_LIST", "REFLECTION_ANALYSIS",
            "WAF_DETECTION", "ENDPOINT_TYPE", "RISK_SCORE", "PREDICTED_VULNS"
        };
        
        for (String var : commonVars) {
            JButton varBtn = VistaTheme.pillButton("{{" + var + "}}");
            varBtn.setToolTipText("Insert " + var + " variable");
            if (var.equals("USER_QUERY")) {
                varBtn.setForeground(VistaTheme.PRIMARY);
                varBtn.setFont(VistaTheme.FONT_SMALL_BOLD);
                varBtn.setToolTipText("Insert USER_QUERY - User's actual question (IMPORTANT!)");
            }
            varBtn.addActionListener(e -> insertVariable(var));
            toolbar.add(varBtn);
        }
        
        JButton moreBtn = VistaTheme.pillButton("More...");
        moreBtn.addActionListener(e -> showAllVariables());
        toolbar.add(moreBtn);
        
        return toolbar;
    }
    
    private JPanel createFormRow(String label, JComponent component) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        if (!label.isEmpty()) {
            JLabel lbl = new JLabel(label);
            lbl.setFont(VistaTheme.FONT_LABEL);
            lbl.setForeground(VistaTheme.TEXT_SECONDARY);
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
        VistaTheme.styleCodeArea(textArea);
        
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
