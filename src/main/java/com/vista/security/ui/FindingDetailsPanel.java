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
        System.out.println("[Finding Details]    Has description: " + (finding.getDescription() != null && !finding.getDescription().isEmpty()));
        System.out.println("[Finding Details]    Has detailedDescription: " + (finding.getDetailedDescription() != null && !finding.getDetailedDescription().isEmpty()));
        System.out.println("[Finding Details]    Description value: " + (finding.getDescription() != null ? finding.getDescription().substring(0, Math.min(50, finding.getDescription().length())) + "..." : "null"));
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
        
        // Get description from AI response (try detailedDescription first, then description)
        String descriptionText = null;
        if (finding.getDetailedDescription() != null && !finding.getDetailedDescription().isEmpty()) {
            descriptionText = finding.getDetailedDescription();
        } else if (finding.getDescription() != null && !finding.getDescription().isEmpty()) {
            descriptionText = finding.getDescription();
        }
        
        if (descriptionText != null && !descriptionText.isEmpty()) {
            // Format the description for better readability
            details.append(formatDescription(descriptionText)).append("\n\n");
        } else {
            details.append("No description provided by AI.\n\n");
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
     * Format description text for better readability.
     * - Removes markdown formatting (**, `, etc.)
     * - Adds line breaks at sentence ends
     * - Formats sections like "Summary:" on new lines
     * - Breaks at separators like "---"
     */
    private String formatDescription(String description) {
        if (description == null || description.isEmpty()) {
            return description;
        }
        
        String formatted = description;
        
        // Remove markdown bold markers **text** -> text
        formatted = formatted.replaceAll("\\*\\*([^*]+)\\*\\*", "$1");
        
        // Remove markdown backticks `text` -> text
        formatted = formatted.replaceAll("`([^`]+)`", "$1");
        
        // Replace "---" separator with proper line break
        formatted = formatted.replaceAll("\\s*---\\s*", "\n\n");
        
        // Add line break before common section headers
        formatted = formatted.replaceAll("(?i)(Summary:|Note:|Warning:|Important:|Recommendation:|Impact:|Risk:)", "\n\n• $1");
        
        // Add line breaks after sentences (. followed by space and uppercase letter)
        formatted = formatted.replaceAll("\\.\\s+([A-Z])", ".\n$1");
        
        // Clean up multiple consecutive newlines (max 2)
        formatted = formatted.replaceAll("\n{3,}", "\n\n");
        
        // Trim leading/trailing whitespace
        formatted = formatted.trim();
        
        return formatted;
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
