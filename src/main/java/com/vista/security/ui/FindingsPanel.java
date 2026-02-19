package com.vista.security.ui;

import burp.*;
import com.vista.security.core.FindingsManager;
import com.vista.security.core.HttpMessageParser;
import com.vista.security.core.ReportExporter;
import com.vista.security.model.ExploitFinding;
import com.vista.security.model.FindingTemplate;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

/**
 * Panel displaying all exploit findings across VISTA.
 */
public class FindingsPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    
    private final DefaultTableModel tableModel;
    private final JTable findingsTable;
    private final JTextArea detailsArea;
    private final HttpMessageViewer httpViewer;
    private final JLabel statsLabel;

    public FindingsPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        String[] columns = {"ID", "Severity", "Host", "Endpoint", "Type", "Parameter", "Payload", "Verified"};
        this.tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        this.findingsTable = new JTable(tableModel);
        this.detailsArea = new JTextArea();
        this.httpViewer = new HttpMessageViewer();
        this.statsLabel = new JLabel("Findings: 0");
        
        setLayout(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(8, 8, 8, 8));
        buildUI();
        
        // Listen for new findings
        FindingsManager.getInstance().addListener(finding -> 
            SwingUtilities.invokeLater(this::refreshTable));
    }

    private void buildUI() {
        // Top: Stats and actions
        JPanel topPanel = new JPanel(new BorderLayout(8, 0));
        topPanel.setBorder(BorderFactory.createTitledBorder("📋 Exploit Findings"));
        
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statsPanel.add(statsLabel);
        
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton refreshBtn = new JButton("🔄 Refresh");
        JButton exportBtn = new JButton("📄 Export All");
        JButton clearBtn = new JButton("🗑 Clear All");
        JButton verifyBtn = new JButton("✓ Mark Verified");
        JButton repeaterBtn = new JButton("→ Repeater");
        
        refreshBtn.addActionListener(e -> refreshTable());
        exportBtn.addActionListener(e -> exportFindings());
        clearBtn.addActionListener(e -> clearFindings());
        verifyBtn.addActionListener(e -> markVerified());
        repeaterBtn.addActionListener(e -> sendToRepeater());
        
        actionsPanel.add(refreshBtn);
        actionsPanel.add(verifyBtn);
        actionsPanel.add(repeaterBtn);
        actionsPanel.add(exportBtn);
        actionsPanel.add(clearBtn);
        
        topPanel.add(statsPanel, BorderLayout.WEST);
        topPanel.add(actionsPanel, BorderLayout.EAST);

        // Center: Table and details
        setupTable();
        JScrollPane tableScroll = new JScrollPane(findingsTable);
        tableScroll.setPreferredSize(new Dimension(800, 200));

        // Details tabs
        JTabbedPane detailsTabs = new JTabbedPane();
        
        Font monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        detailsArea.setFont(monoFont);
        detailsArea.setEditable(false);
        
        detailsTabs.addTab("Details", new JScrollPane(detailsArea));
        detailsTabs.addTab("Request / Response", httpViewer);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailsTabs);
        splitPane.setResizeWeight(0.4);

        add(topPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        
        refreshTable();
    }

    private void setupTable() {
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(60);  // ID
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(70);  // Severity
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(150); // Host
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(200); // Endpoint
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(80);  // Type
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(100); // Parameter
        findingsTable.getColumnModel().getColumn(6).setPreferredWidth(200); // Payload
        findingsTable.getColumnModel().getColumn(7).setPreferredWidth(60);  // Verified

        // Color code by severity
        findingsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    List<ExploitFinding> findings = FindingsManager.getInstance().getFindings();
                    if (row < findings.size()) {
                        String severity = findings.get(row).getSeverity();
                        c.setBackground(getSeverityColor(severity));
                    }
                }
                return c;
            }
        });

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedFinding();
            }
        });
    }

    private Color getSeverityColor(String severity) {
        return switch (severity.toLowerCase()) {
            case "critical" -> new Color(255, 200, 200);
            case "high" -> new Color(255, 220, 200);
            case "medium" -> new Color(255, 255, 200);
            case "low" -> new Color(200, 255, 200);
            default -> Color.WHITE;
        };
    }

    public void refreshTable() {
        tableModel.setRowCount(0);
        List<ExploitFinding> findings = FindingsManager.getInstance().getFindings();
        
        for (ExploitFinding f : findings) {
            tableModel.addRow(new Object[]{
                f.getId(),
                f.getSeverity(),
                f.getHost(),
                f.getMethod() + " " + truncate(f.getEndpoint(), 30),
                f.getExploitType(),
                f.getParameter(),
                truncate(f.getPayload(), 40),
                f.isVerified() ? "✓" : ""
            });
        }
        
        updateStats();
    }

    private void updateStats() {
        FindingsManager fm = FindingsManager.getInstance();
        statsLabel.setText(String.format("Findings: %d (Critical: %d, High: %d, Medium: %d)",
            fm.getTotalCount(),
            fm.getCountBySeverity("Critical"),
            fm.getCountBySeverity("High"),
            fm.getCountBySeverity("Medium")));
    }

    private void showSelectedFinding() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return;
        
        List<ExploitFinding> findings = FindingsManager.getInstance().getFindings();
        if (row >= findings.size()) return;
        
        ExploitFinding finding = findings.get(row);
        
        detailsArea.setText(finding.getDetailedReport());
        detailsArea.setCaretPosition(0);
        
        // Show request/response in professional HttpMessageViewer
        httpViewer.setHttpMessage(finding.getRequest(), finding.getResponse());
    }

    private void markVerified() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return;
        
        List<ExploitFinding> findings = FindingsManager.getInstance().getFindings();
        if (row >= findings.size()) return;
        
        ExploitFinding finding = findings.get(row);
        finding.setVerified(!finding.isVerified());
        refreshTable();
    }

    private void sendToRepeater() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return;
        
        List<ExploitFinding> findings = FindingsManager.getInstance().getFindings();
        if (row >= findings.size()) return;
        
        ExploitFinding finding = findings.get(row);
        if (finding.getRequest() == null) return;
        
        try {
            String host = finding.getHost();
            int port = 443;
            boolean https = true;
            
            if (host.contains(":")) {
                String[] parts = host.split(":");
                host = parts[0];
                port = Integer.parseInt(parts[1]);
                https = port == 443;
            }
            
            callbacks.sendToRepeater(host, port, https, finding.getRequest(), 
                "VISTA-" + finding.getId());
            callbacks.printOutput("[VISTA] Sent finding " + finding.getId() + " to Repeater");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to send to Repeater: " + e.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportFindings() {
        List<ExploitFinding> findings = FindingsManager.getInstance().getFindings();
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        // Show export dialog
        showExportDialog(findings);
    }

    private void clearFindings() {
        int confirm = JOptionPane.showConfirmDialog(this, 
            "Clear all findings? This cannot be undone.", "Confirm", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            FindingsManager.getInstance().clearAll();
            refreshTable();
        }
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Enhanced Export with AI and Templates
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Show export dialog with template selection and AI generation.
     */
    private void showExportDialog(List<ExploitFinding> findings) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), 
            "Export Findings", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(600, 500);
        
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));
        
        // Template selection
        JPanel templatePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        templatePanel.add(new JLabel("Report Template:"));
        JComboBox<FindingTemplate> templateCombo = new JComboBox<>();
        for (FindingTemplate template : FindingsManager.getInstance().getTemplates()) {
            templateCombo.addItem(template);
        }
        templatePanel.add(templateCombo);
        
        // Format selection
        JPanel formatPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        formatPanel.add(new JLabel("Export Format:"));
        JComboBox<String> formatCombo = new JComboBox<>(new String[]{"Markdown (.md)", "HTML (.html)"});
        formatPanel.add(formatCombo);
        
        // AI generation option
        JPanel aiPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JCheckBox aiCheckbox = new JCheckBox("Generate AI descriptions (recommended)", true);
        aiCheckbox.setToolTipText("Use AI to generate professional vulnerability descriptions");
        aiPanel.add(aiCheckbox);
        
        // Progress area
        JTextArea progressArea = new JTextArea(10, 50);
        progressArea.setEditable(false);
        progressArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane progressScroll = new JScrollPane(progressArea);
        progressScroll.setBorder(BorderFactory.createTitledBorder("Progress"));
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton exportBtn = new JButton("Export");
        JButton cancelBtn = new JButton("Cancel");
        
        exportBtn.addActionListener(e -> {
            exportBtn.setEnabled(false);
            FindingTemplate template = (FindingTemplate) templateCombo.getSelectedItem();
            boolean isHtml = formatCombo.getSelectedIndex() == 1;
            boolean useAI = aiCheckbox.isSelected();
            
            new Thread(() -> {
                try {
                    performExport(findings, template, isHtml, useAI, progressArea, dialog);
                } finally {
                    SwingUtilities.invokeLater(() -> exportBtn.setEnabled(true));
                }
            }).start();
        });
        
        cancelBtn.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(exportBtn);
        buttonPanel.add(cancelBtn);
        
        mainPanel.add(templatePanel);
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(formatPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(aiPanel);
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(progressScroll);
        
        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    /**
     * Perform the actual export with AI generation.
     */
    private void performExport(List<ExploitFinding> findings, FindingTemplate template,
                              boolean isHtml, boolean useAI, JTextArea progressArea, JDialog dialog) {
        try {
            progressArea.append("Starting export...\n");
            progressArea.append("Template: " + template.getName() + "\n");
            progressArea.append("Format: " + (isHtml ? "HTML" : "Markdown") + "\n");
            progressArea.append("Findings: " + findings.size() + "\n");
            progressArea.append("AI Generation: " + (useAI ? "Enabled" : "Disabled") + "\n\n");
            
            ReportExporter exporter = new ReportExporter(helpers);
            FindingsManager fm = FindingsManager.getInstance();
            
            // Generate AI content for first finding (as example)
            String aiDescription = "";
            String aiImpact = "";
            String aiRemediation = "";
            
            if (useAI && !findings.isEmpty()) {
                progressArea.append("Generating AI content...\n");
                
                ExploitFinding firstFinding = findings.get(0);
                
                progressArea.append("  - Generating description...\n");
                aiDescription = fm.generateDescription(firstFinding);
                
                progressArea.append("  - Generating impact assessment...\n");
                aiImpact = fm.generateImpact(firstFinding);
                
                progressArea.append("  - Generating remediation...\n");
                aiRemediation = fm.generateRemediation(firstFinding);
                
                progressArea.append("AI content generated successfully!\n\n");
            }
            
            // Generate report
            progressArea.append("Generating report...\n");
            String report;
            if (isHtml) {
                report = exporter.exportToHtml(findings, template, aiDescription, aiImpact, aiRemediation);
            } else {
                report = exporter.exportFindings(findings, template, aiDescription, aiImpact, aiRemediation);
            }
            
            // Save file
            SwingUtilities.invokeLater(() -> {
                JFileChooser chooser = new JFileChooser();
                String extension = isHtml ? ".html" : ".md";
                chooser.setSelectedFile(new File("vista-findings" + extension));
                
                if (chooser.showSaveDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                    try {
                        Files.writeString(chooser.getSelectedFile().toPath(), report);
                        progressArea.append("\n✓ Export complete!\n");
                        progressArea.append("Saved to: " + chooser.getSelectedFile().getAbsolutePath() + "\n");
                        
                        JOptionPane.showMessageDialog(dialog,
                            "Successfully exported " + findings.size() + " findings!",
                            "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                        
                        dialog.dispose();
                    } catch (Exception ex) {
                        progressArea.append("\n✗ Error saving file: " + ex.getMessage() + "\n");
                        JOptionPane.showMessageDialog(dialog,
                            "Failed to save file: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            });
            
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                progressArea.append("\n✗ Export failed: " + e.getMessage() + "\n");
                e.printStackTrace();
                JOptionPane.showMessageDialog(dialog,
                    "Export failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            });
        }
    }
}
