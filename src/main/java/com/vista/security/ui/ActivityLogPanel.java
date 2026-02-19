package com.vista.security.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Real-time Activity Log panel for Traffic Monitor.
 * Shows a live scrolling table of every request analyzed, with timestamps,
 * status indicators, analysis results, and timing information.
 * 
 * Gives the user full visibility into what VISTA is doing in real-time.
 */
public class ActivityLogPanel extends JPanel {
    
    private static final int MAX_LOG_ENTRIES = 5000;
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    
    private final DefaultTableModel logTableModel;
    private final JTable logTable;
    private final JLabel summaryLabel;
    private boolean autoScroll = true;
    
    // Counters for summary
    private int totalRequests = 0;
    private int analyzedCount = 0;
    private int findingsCount = 0;
    private int errorsCount = 0;
    private int skippedCount = 0;
    
    /**
     * Log entry types for color coding rows.
     */
    public enum LogLevel {
        CAPTURED,      // Request captured (gray)
        QUEUED,        // Queued for analysis (blue)
        ANALYZING,     // Currently being analyzed (yellow/amber)
        COMPLETED,     // Analysis complete, no findings (green)
        FINDING,       // Analysis found vulnerabilities (orange/red)
        SKIPPED,       // Skipped (duplicate, out of scope, etc.) (muted)
        ERROR          // Error during analysis (red)
    }
    
    public ActivityLogPanel() {
        setLayout(new BorderLayout());
        setBackground(VistaTheme.BG_PANEL);
        
        // ── Toolbar ──
        JPanel toolbar = createToolbar();
        add(toolbar, BorderLayout.NORTH);
        
        // ── Log Table ──
        String[] columns = {"Time", "Level", "#", "Method", "URL", "Status", "Result", "Details", "Duration"};
        logTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        logTable = new JTable(logTableModel);
        VistaTheme.styleTable(logTable);
        logTable.setFont(VistaTheme.FONT_MONO_SMALL);
        logTable.setRowHeight(22);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logTable.setShowGrid(false);
        logTable.setIntercellSpacing(new Dimension(0, 0));
        
        // Column widths
        logTable.getColumnModel().getColumn(0).setPreferredWidth(90);   // Time
        logTable.getColumnModel().getColumn(0).setMaxWidth(100);
        logTable.getColumnModel().getColumn(1).setPreferredWidth(80);   // Level
        logTable.getColumnModel().getColumn(1).setMaxWidth(90);
        logTable.getColumnModel().getColumn(2).setPreferredWidth(40);   // #
        logTable.getColumnModel().getColumn(2).setMaxWidth(50);
        logTable.getColumnModel().getColumn(3).setPreferredWidth(55);   // Method
        logTable.getColumnModel().getColumn(3).setMaxWidth(70);
        logTable.getColumnModel().getColumn(4).setPreferredWidth(350);  // URL
        logTable.getColumnModel().getColumn(5).setPreferredWidth(50);   // Status
        logTable.getColumnModel().getColumn(5).setMaxWidth(60);
        logTable.getColumnModel().getColumn(6).setPreferredWidth(100);  // Result
        logTable.getColumnModel().getColumn(6).setMaxWidth(130);
        logTable.getColumnModel().getColumn(7).setPreferredWidth(250);  // Details
        logTable.getColumnModel().getColumn(8).setPreferredWidth(70);   // Duration
        logTable.getColumnModel().getColumn(8).setMaxWidth(80);
        
        // Custom renderer for color-coded rows
        ActivityLogRenderer renderer = new ActivityLogRenderer();
        for (int i = 0; i < logTable.getColumnCount(); i++) {
            logTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }
        
        JScrollPane scrollPane = new JScrollPane(logTable);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        add(scrollPane, BorderLayout.CENTER);
        
        // ── Summary bar ──
        JPanel summaryBar = new JPanel(new BorderLayout());
        summaryBar.setBackground(VistaTheme.BG_CARD);
        summaryBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, VistaTheme.BORDER),
            BorderFactory.createEmptyBorder(4, 12, 4, 12)
        ));
        
        summaryLabel = new JLabel("Ready — No activity yet");
        summaryLabel.setFont(VistaTheme.FONT_SMALL);
        summaryLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        summaryBar.add(summaryLabel, BorderLayout.WEST);
        
        add(summaryBar, BorderLayout.SOUTH);
    }
    
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.setBackground(VistaTheme.BG_CARD);
        toolbar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, VistaTheme.BORDER),
            BorderFactory.createEmptyBorder(2, 8, 2, 8)
        ));
        
        JLabel titleLabel = new JLabel("📋 Activity Log");
        titleLabel.setFont(VistaTheme.FONT_BODY_BOLD);
        titleLabel.setForeground(VistaTheme.TEXT_PRIMARY);
        toolbar.add(titleLabel);
        
        toolbar.add(Box.createHorizontalStrut(15));
        
        // Auto-scroll toggle
        JCheckBox autoScrollCb = new JCheckBox("Auto-scroll", true);
        autoScrollCb.setFont(VistaTheme.FONT_SMALL);
        autoScrollCb.setForeground(VistaTheme.TEXT_SECONDARY);
        autoScrollCb.setOpaque(false);
        autoScrollCb.addActionListener(e -> autoScroll = autoScrollCb.isSelected());
        toolbar.add(autoScrollCb);
        
        toolbar.add(Box.createHorizontalStrut(10));
        
        // Clear button
        JButton clearBtn = VistaTheme.compactButton("Clear Log");
        clearBtn.addActionListener(e -> clearLog());
        toolbar.add(clearBtn);
        
        toolbar.add(Box.createHorizontalStrut(10));
        
        // Filter dropdown
        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setFont(VistaTheme.FONT_SMALL);
        filterLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        toolbar.add(filterLabel);
        
        JComboBox<String> filterCombo = new JComboBox<>(new String[]{
            "All Events", "Findings Only", "Errors Only", "Analysis Only"
        });
        filterCombo.setFont(VistaTheme.FONT_SMALL);
        filterCombo.addActionListener(e -> applyFilter((String) filterCombo.getSelectedItem()));
        toolbar.add(filterCombo);
        
        return toolbar;
    }
    
    /**
     * Add a log entry. Thread-safe — can be called from any thread.
     */
    public void addLogEntry(LogLevel level, int requestNum, String method, String url,
                           int statusCode, String result, String details, long durationMs) {
        SwingUtilities.invokeLater(() -> {
            // Trim old entries if over max
            while (logTableModel.getRowCount() >= MAX_LOG_ENTRIES) {
                logTableModel.removeRow(0);
            }
            
            String time = LocalDateTime.now().format(TIME_FMT);
            String levelStr = formatLevel(level);
            String statusStr = statusCode > 0 ? String.valueOf(statusCode) : "—";
            String durationStr = durationMs > 0 ? durationMs + "ms" : "—";
            String truncUrl = truncate(url, 120);
            String truncDetails = truncate(details, 200);
            
            logTableModel.addRow(new Object[]{
                time, levelStr, requestNum > 0 ? requestNum : "—",
                method != null ? method : "—", truncUrl,
                statusStr, result != null ? result : "—",
                truncDetails, durationStr
            });
            
            // Update counters
            totalRequests++;
            switch (level) {
                case COMPLETED, ANALYZING -> analyzedCount++;
                case FINDING -> { analyzedCount++; findingsCount++; }
                case ERROR -> errorsCount++;
                case SKIPPED -> skippedCount++;
            }
            
            updateSummary();
            
            // Auto-scroll to bottom
            if (autoScroll) {
                int lastRow = logTable.getRowCount() - 1;
                if (lastRow >= 0) {
                    logTable.scrollRectToVisible(logTable.getCellRect(lastRow, 0, true));
                }
            }
        });
    }
    
    /**
     * Convenience: Log a request capture event.
     */
    public void logCapture(int requestNum, String method, String url, int statusCode) {
        addLogEntry(LogLevel.CAPTURED, requestNum, method, url, statusCode,
                "Captured", "Traffic captured from proxy", 0);
    }
    
    /**
     * Convenience: Log a queued-for-analysis event.
     */
    public void logQueued(int requestNum, String method, String url) {
        addLogEntry(LogLevel.QUEUED, requestNum, method, url, 0,
                "Queued", "Submitted for AI analysis", 0);
    }
    
    /**
     * Convenience: Log an analysis-in-progress event.
     */
    public void logAnalyzing(String url) {
        addLogEntry(LogLevel.ANALYZING, 0, null, url, 0,
                "Analyzing...", "AI analysis in progress", 0);
    }
    
    /**
     * Convenience: Log analysis complete with findings.
     */
    public void logFinding(String url, int findingCount, String findingSummary, long durationMs) {
        String result = findingCount + " finding" + (findingCount != 1 ? "s" : "");
        addLogEntry(LogLevel.FINDING, 0, null, url, 0,
                "⚠ " + result, findingSummary, durationMs);
    }
    
    /**
     * Convenience: Log analysis complete with no findings.
     */
    public void logClean(String url, long durationMs) {
        addLogEntry(LogLevel.COMPLETED, 0, null, url, 0,
                "✓ Clean", "No vulnerabilities detected", durationMs);
    }
    
    /**
     * Convenience: Log a skipped request.
     */
    public void logSkipped(String url, String reason) {
        addLogEntry(LogLevel.SKIPPED, 0, null, url, 0,
                "Skipped", reason, 0);
    }
    
    /**
     * Convenience: Log an error.
     */
    public void logError(String url, String errorMessage) {
        addLogEntry(LogLevel.ERROR, 0, null, url, 0,
                "✗ Error", errorMessage, 0);
    }
    
    public void clearLog() {
        SwingUtilities.invokeLater(() -> {
            logTableModel.setRowCount(0);
            totalRequests = 0;
            analyzedCount = 0;
            findingsCount = 0;
            errorsCount = 0;
            skippedCount = 0;
            updateSummary();
        });
    }
    
    private void updateSummary() {
        String summary = String.format(
            "Total: %d | Analyzed: %d | Findings: %d | Errors: %d | Skipped: %d",
            totalRequests, analyzedCount, findingsCount, errorsCount, skippedCount
        );
        summaryLabel.setText(summary);
    }
    
    private void applyFilter(String filterName) {
        // For now, filtering is visual only via row sorter
        // A full implementation would use TableRowSorter with RowFilter
        // Keeping simple for now — all events are shown
    }
    
    private String formatLevel(LogLevel level) {
        return switch (level) {
            case CAPTURED  -> "📥 CAPTURE";
            case QUEUED    -> "📤 QUEUED";
            case ANALYZING -> "🔄 ANALYZE";
            case COMPLETED -> "✅ CLEAN";
            case FINDING   -> "🔴 FINDING";
            case SKIPPED   -> "⏭ SKIP";
            case ERROR     -> "❌ ERROR";
        };
    }
    
    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
    
    /**
     * Custom cell renderer that color-codes rows based on log level.
     */
    private static class ActivityLogRenderer extends DefaultTableCellRenderer {
        
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            
            if (!isSelected) {
                // Get the level from column 1
                try {
                    String level = (String) table.getModel().getValueAt(row, 1);
                    if (level != null) {
                        if (level.contains("FINDING")) {
                            c.setBackground(new Color(254, 242, 242)); // Red-50
                            c.setForeground(new Color(185, 28, 28));   // Red-800
                        } else if (level.contains("ERROR")) {
                            c.setBackground(new Color(254, 226, 226)); // Red-100
                            c.setForeground(new Color(153, 27, 27));   // Red-900
                        } else if (level.contains("CLEAN")) {
                            c.setBackground(new Color(240, 253, 244)); // Green-50
                            c.setForeground(new Color(22, 101, 52));   // Green-800
                        } else if (level.contains("QUEUED") || level.contains("ANALYZE")) {
                            c.setBackground(new Color(239, 246, 255)); // Blue-50
                            c.setForeground(new Color(30, 64, 175));   // Blue-800
                        } else if (level.contains("SKIP")) {
                            c.setBackground(new Color(248, 250, 252)); // Slate-50
                            c.setForeground(VistaTheme.TEXT_MUTED);
                        } else {
                            c.setBackground(Color.WHITE);
                            c.setForeground(VistaTheme.TEXT_PRIMARY);
                        }
                    }
                } catch (Exception e) {
                    c.setBackground(Color.WHITE);
                    c.setForeground(VistaTheme.TEXT_PRIMARY);
                }
            }
            
            // Monospace font for all columns
            c.setFont(VistaTheme.FONT_MONO_SMALL);
            
            return c;
        }
    }
}
