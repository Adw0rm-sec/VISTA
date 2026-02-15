package com.vista.security.ui;

import com.vista.security.model.TrafficFinding;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Panel for displaying detailed information about a selected finding.
 * Shows all fields including parameter, description, impact, and remediation.
 * Uses professional side-by-side HTTP message viewer.
 */
public class FindingDetailsPanel extends JPanel {
    
    private final JTextArea detailsArea;
    private final HttpMessageViewer httpViewer;
    private TrafficFinding currentFinding;
    
    public FindingDetailsPanel() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Title
        JLabel titleLabel = new JLabel("Finding Details");
        titleLabel.setFont(new Font("Dialog", Font.BOLD, 14));
        titleLabel.setBorder(new EmptyBorder(0, 0, 10, 0));
        
        // Details text area (top section)
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setText("Select a finding to view details");
        detailsArea.setRows(12);
        
        JScrollPane detailsScroll = new JScrollPane(detailsArea);
        detailsScroll.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        
        // HTTP message viewer (bottom section - side-by-side)
        httpViewer = new HttpMessageViewer();
        
        // Split pane: details on top, HTTP viewer on bottom
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, detailsScroll, httpViewer);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.4);
        
        // Main layout
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(titleLabel, BorderLayout.NORTH);
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        add(mainPanel, BorderLayout.CENTER);
        
        // Action buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton copyButton = new JButton("Copy Details");
        copyButton.addActionListener(e -> copyToClipboard());
        buttonPanel.add(copyButton);
        
        JButton exportButton = new JButton("Export Finding");
        exportButton.addActionListener(e -> exportFinding());
        buttonPanel.add(exportButton);
        
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    /**
     * Display details for a finding.
     */
    public void showFinding(TrafficFinding finding) {
        this.currentFinding = finding;
        
        if (finding == null) {
            System.out.println("[Finding Details] ℹ️ Cleared (no finding selected)");
            detailsArea.setText("Select a finding to view details");
            httpViewer.clear();
            return;
        }
        
        System.out.println("[Finding Details] ═══════════════════════════════════════");
        System.out.println("[Finding Details] 📋 Displaying Finding Details");
        System.out.println("[Finding Details]    Type: " + finding.getType());
        System.out.println("[Finding Details]    Severity: " + finding.getSeverity());
        System.out.println("[Finding Details]    URL: " + finding.getSourceTransaction().getUrl());
        System.out.println("[Finding Details]    Has parameter: " + (finding.getAffectedParameter() != null && !finding.getAffectedParameter().isEmpty()));
        System.out.println("[Finding Details]    Has impact: " + (finding.getImpact() != null && !finding.getImpact().isEmpty()));
        System.out.println("[Finding Details]    Has remediation: " + (finding.getRemediation() != null && !finding.getRemediation().isEmpty()));
        System.out.println("[Finding Details]    Has decoded data: " + finding.hasDecodedData());
        System.out.println("[Finding Details] ═══════════════════════════════════════");
        
        StringBuilder details = new StringBuilder();
        
        // Header
        details.append("═══════════════════════════════════════════════════════════\n");
        details.append("FINDING DETAILS\n");
        details.append("═══════════════════════════════════════════════════════════\n\n");
        
        // Basic info
        details.append("Type: ").append(finding.getType()).append("\n");
        details.append("Severity: ").append(getSeverityWithEmoji(finding.getSeverity())).append("\n");
        details.append("Detection: ").append(finding.getDetectionEngine()).append("\n");
        details.append("Timestamp: ").append(finding.getFormattedTimestamp()).append("\n\n");
        
        // URL info
        details.append("URL: ").append(finding.getSourceTransaction().getUrl()).append("\n");
        details.append("Method: ").append(finding.getSourceTransaction().getMethod()).append("\n");
        details.append("Status: ").append(finding.getSourceTransaction().getStatusCode()).append("\n\n");
        
        // Parameter (if available)
        if (finding.getAffectedParameter() != null && !finding.getAffectedParameter().isEmpty()) {
            details.append("───────────────────────────────────────────────────────────\n");
            details.append("AFFECTED PARAMETER\n");
            details.append("───────────────────────────────────────────────────────────\n");
            details.append(finding.getAffectedParameter()).append("\n\n");
        }
        
        // Evidence
        details.append("───────────────────────────────────────────────────────────\n");
        details.append("EVIDENCE\n");
        details.append("───────────────────────────────────────────────────────────\n");
        details.append(finding.getEvidence()).append("\n\n");
        
        // Description
        details.append("───────────────────────────────────────────────────────────\n");
        details.append("DESCRIPTION\n");
        details.append("───────────────────────────────────────────────────────────\n");
        if (finding.getDetailedDescription() != null && !finding.getDetailedDescription().isEmpty()) {
            details.append(finding.getDetailedDescription()).append("\n\n");
        } else {
            details.append(finding.getDescription()).append("\n\n");
        }
        
        // Impact (if available)
        if (finding.getImpact() != null && !finding.getImpact().isEmpty()) {
            details.append("───────────────────────────────────────────────────────────\n");
            details.append("IMPACT\n");
            details.append("───────────────────────────────────────────────────────────\n");
            details.append(finding.getImpact()).append("\n\n");
        }
        
        // Remediation (if available)
        if (finding.getRemediation() != null && !finding.getRemediation().isEmpty()) {
            details.append("───────────────────────────────────────────────────────────\n");
            details.append("REMEDIATION\n");
            details.append("───────────────────────────────────────────────────────────\n");
            details.append(finding.getRemediation()).append("\n\n");
        }
        
        // Additional info
        if (finding.hasDecodedData()) {
            details.append("───────────────────────────────────────────────────────────\n");
            details.append("DECODED DATA (").append(finding.getEncodingType()).append(")\n");
            details.append("───────────────────────────────────────────────────────────\n");
            details.append(finding.getDecodedData()).append("\n\n");
        }
        
        detailsArea.setText(details.toString());
        detailsArea.setCaretPosition(0);
        
        // Display HTTP request/response in side-by-side viewer
        byte[] request = finding.getSourceTransaction().getRequest();
        byte[] response = finding.getSourceTransaction().getResponse();
        httpViewer.setHttpMessage(request, response);
    }
    
    /**
     * Clear the details panel.
     */
    public void clear() {
        currentFinding = null;
        detailsArea.setText("Select a finding to view details");
        httpViewer.clear();
    }
    
    /**
     * Get severity with emoji indicator.
     */
    private String getSeverityWithEmoji(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> "🔴 CRITICAL";
            case "HIGH" -> "🟠 HIGH";
            case "MEDIUM" -> "🟡 MEDIUM";
            case "LOW" -> "🔵 LOW";
            case "INFO" -> "⚪ INFO";
            default -> severity;
        };
    }
    
    /**
     * Copy details to clipboard.
     */
    private void copyToClipboard() {
        if (currentFinding == null) {
            return;
        }
        
        String text = detailsArea.getText();
        java.awt.datatransfer.StringSelection selection = 
            new java.awt.datatransfer.StringSelection(text);
        java.awt.Toolkit.getDefaultToolkit()
            .getSystemClipboard()
            .setContents(selection, selection);
        
        JOptionPane.showMessageDialog(this, 
            "Details copied to clipboard", 
            "Success", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Export finding to file.
     */
    private void exportFinding() {
        if (currentFinding == null) {
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Finding");
        fileChooser.setSelectedFile(new java.io.File(
            "finding_" + currentFinding.getType() + "_" + 
            System.currentTimeMillis() + ".txt"));
        
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                java.nio.file.Files.writeString(
                    file.toPath(), 
                    detailsArea.getText());
                
                JOptionPane.showMessageDialog(this, 
                    "Finding exported to: " + file.getAbsolutePath(), 
                    "Success", 
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, 
                    "Export failed: " + ex.getMessage(), 
                    "Error", 
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
