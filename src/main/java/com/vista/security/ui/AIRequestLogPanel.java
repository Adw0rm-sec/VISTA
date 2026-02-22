package com.vista.security.ui;

import com.vista.security.core.AIRequestLogStore;
import com.vista.security.core.AIRequestLogStore.AIRequestRecord;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

import static com.vista.security.ui.VistaTheme.*;

/**
 * AI Request Log Panel — full transparency into every AI call.
 * 
 * Shows a table of all AI requests with:
 * - Timestamp, source, provider, model, template, status, tokens, duration
 * 
 * When a row is selected, a detail view shows:
 * - Full SYSTEM PROMPT (scrollable)
 * - Full USER PROMPT (scrollable)
 * - Full AI RESPONSE (scrollable)
 * 
 * This panel can be embedded in both the AI Advisor and Traffic Monitor tabs
 * with an optional source filter to show only relevant calls.
 */
public class AIRequestLogPanel extends JPanel implements AIRequestLogStore.Listener {
    
    private final DefaultTableModel tableModel;
    private final JTable logTable;
    private final JTextArea systemPromptArea;
    private final JTextArea userPromptArea;
    private final JTextArea responseArea;
    private final JLabel detailHeaderLabel;
    private final JLabel statsLabel;
    private final String sourceFilter; // null = show all, "AI Advisor" = filter
    
    /**
     * Creates an AI Request Log Panel.
     * @param sourceFilter If non-null, only shows records matching this source prefix.
     *                     null = show all records from all sources.
     */
    public AIRequestLogPanel(String sourceFilter) {
        this.sourceFilter = sourceFilter;
        setLayout(new BorderLayout());
        setBackground(BG_PANEL);
        
        // ═══ Top toolbar ═══
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.setBackground(BG_CARD);
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER));
        
        JLabel titleLabel = new JLabel("🔍 AI Request Log" + 
            (sourceFilter != null ? " (" + sourceFilter + ")" : " (All Sources)"));
        titleLabel.setFont(FONT_SMALL_BOLD);
        titleLabel.setForeground(TEXT_PRIMARY);
        toolbar.add(titleLabel);
        
        toolbar.add(Box.createHorizontalStrut(20));
        
        statsLabel = new JLabel("No requests yet");
        statsLabel.setFont(FONT_SMALL);
        statsLabel.setForeground(TEXT_MUTED);
        toolbar.add(statsLabel);
        
        toolbar.add(Box.createHorizontalGlue());
        
        JButton clearButton = compactButton("Clear");
        clearButton.addActionListener(e -> {
            AIRequestLogStore.getInstance().clear();
            refreshTable();
        });
        toolbar.add(clearButton);
        
        JButton refreshButton = compactButton("Refresh");
        refreshButton.addActionListener(e -> refreshTable());
        toolbar.add(refreshButton);
        
        add(toolbar, BorderLayout.NORTH);
        
        // ═══ Main split: table (top) + detail (bottom) ═══
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setDividerLocation(250);
        mainSplit.setResizeWeight(0.35);
        mainSplit.setDividerSize(5);
        
        // ── Table ──
        String[] columns = {"#", "Time", "Source", "Provider", "Model", "Template", "Status", 
                            "Sys Tokens", "User Tokens", "Resp Tokens", "Total", "Duration"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        
        logTable = new JTable(tableModel);
        styleTable(logTable);
        logTable.setFont(FONT_MONO_SMALL);
        logTable.setRowHeight(24);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // Column widths
        int[] widths = {35, 65, 110, 75, 120, 130, 75, 70, 70, 70, 60, 65};
        for (int i = 0; i < widths.length && i < logTable.getColumnCount(); i++) {
            logTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        
        // Color-coded status renderer
        logTable.getColumnModel().getColumn(6).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected && value != null) {
                    String status = value.toString();
                    if (status.contains("Success")) {
                        c.setForeground(new Color(22, 163, 74));
                    } else if (status.contains("Error")) {
                        c.setForeground(new Color(220, 38, 38));
                    } else if (status.contains("Pending")) {
                        c.setForeground(new Color(202, 138, 4));
                    } else {
                        c.setForeground(TEXT_PRIMARY);
                    }
                }
                return c;
            }
        });
        
        // Selection listener — show details
        logTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetail();
            }
        });
        
        JScrollPane tableScroll = new JScrollPane(logTable);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        mainSplit.setTopComponent(tableScroll);
        
        // ── Detail panel (3-section split) ──
        JPanel detailPanel = new JPanel(new BorderLayout());
        detailPanel.setBackground(BG_PANEL);
        
        detailHeaderLabel = new JLabel("  Select a request to view details");
        detailHeaderLabel.setFont(FONT_SMALL_BOLD);
        detailHeaderLabel.setForeground(TEXT_SECONDARY);
        detailHeaderLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
            BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));
        detailHeaderLabel.setOpaque(true);
        detailHeaderLabel.setBackground(BG_CARD);
        detailPanel.add(detailHeaderLabel, BorderLayout.NORTH);
        
        // 3 text areas in a horizontal split
        systemPromptArea = createPromptArea();
        userPromptArea = createPromptArea();
        responseArea = createPromptArea();
        
        JPanel sysPanel = wrapWithLabel("SYSTEM PROMPT", systemPromptArea, new Color(147, 51, 234));
        JPanel userPanel = wrapWithLabel("USER PROMPT", userPromptArea, new Color(59, 130, 246));
        JPanel respPanel = wrapWithLabel("AI RESPONSE", responseArea, new Color(22, 163, 74));
        
        // Horizontal split for the 3 panels
        JSplitPane leftSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sysPanel, userPanel);
        leftSplit.setDividerLocation(0.5);
        leftSplit.setResizeWeight(0.5);
        leftSplit.setDividerSize(4);
        
        JSplitPane rightSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, respPanel);
        rightSplit.setDividerLocation(0.67);
        rightSplit.setResizeWeight(0.67);
        rightSplit.setDividerSize(4);
        
        detailPanel.add(rightSplit, BorderLayout.CENTER);
        
        mainSplit.setBottomComponent(detailPanel);
        add(mainSplit, BorderLayout.CENTER);
        
        // Register for updates
        AIRequestLogStore.getInstance().addListener(this);
        
        // Initial load
        refreshTable();
    }
    
    /**
     * Creates a scrollable, monospaced, read-only text area for prompts/responses.
     */
    private JTextArea createPromptArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(FONT_MONO_SMALL);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBackground(new Color(250, 250, 250));
        area.setForeground(TEXT_PRIMARY);
        area.setMargin(new Insets(6, 8, 6, 8));
        area.setText("(Select a request above)");
        return area;
    }
    
    /**
     * Wraps a text area with a colored label header.
     */
    private JPanel wrapWithLabel(String title, JTextArea area, Color labelColor) {
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel label = new JLabel("  " + title);
        label.setFont(FONT_SMALL_BOLD);
        label.setForeground(Color.WHITE);
        label.setOpaque(true);
        label.setBackground(labelColor);
        label.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        
        // Add copy button
        JButton copyBtn = new JButton("📋");
        copyBtn.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 12));
        copyBtn.setToolTipText("Copy to clipboard");
        copyBtn.setMargin(new Insets(0, 4, 0, 4));
        copyBtn.setBorderPainted(false);
        copyBtn.setContentAreaFilled(false);
        copyBtn.setForeground(Color.WHITE);
        copyBtn.addActionListener(e -> {
            String text = area.getText();
            if (text != null && !text.isEmpty()) {
                java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(text);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
            }
        });
        
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.add(label, BorderLayout.CENTER);
        headerPanel.add(copyBtn, BorderLayout.EAST);
        
        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Refreshes the table from the store.
     */
    public void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            int selectedRow = logTable.getSelectedRow();
            int selectedId = -1;
            if (selectedRow >= 0 && selectedRow < tableModel.getRowCount()) {
                selectedId = (int) tableModel.getValueAt(selectedRow, 0);
            }
            
            tableModel.setRowCount(0);
            
            List<AIRequestRecord> records = AIRequestLogStore.getInstance().getRecords();
            int totalTokens = 0;
            int displayCount = 0;
            
            for (AIRequestRecord r : records) {
                // Apply source filter
                if (sourceFilter != null && !r.source.startsWith(sourceFilter)) {
                    continue;
                }
                
                tableModel.addRow(new Object[]{
                    r.id,
                    r.getFormattedTime(),
                    r.source,
                    r.provider,
                    r.model,
                    r.templateName != null ? r.templateName : "Direct",
                    r.status,
                    r.systemPromptTokens,
                    r.userPromptTokens,
                    r.responseTokens,
                    r.getTotalTokens(),
                    r.getFormattedDuration()
                });
                
                totalTokens += r.getTotalTokens();
                displayCount++;
            }
            
            // Restore selection
            if (selectedId >= 0) {
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    if ((int) tableModel.getValueAt(i, 0) == selectedId) {
                        logTable.setRowSelectionInterval(i, i);
                        break;
                    }
                }
            }
            
            // Update stats
            statsLabel.setText(displayCount + " requests | ~" + formatTokens(totalTokens) + " total tokens");
        });
    }
    
    /**
     * Shows details for the selected row.
     */
    private void showSelectedDetail() {
        int row = logTable.getSelectedRow();
        if (row < 0 || row >= tableModel.getRowCount()) {
            return;
        }
        
        int recordId = (int) tableModel.getValueAt(row, 0);
        
        // Find the record
        List<AIRequestRecord> records = AIRequestLogStore.getInstance().getRecords();
        AIRequestRecord selected = null;
        for (AIRequestRecord r : records) {
            if (r.id == recordId) {
                selected = r;
                break;
            }
        }
        
        if (selected == null) return;
        
        detailHeaderLabel.setText("  #" + selected.id + " | " + selected.source + 
            " | " + selected.provider + " / " + selected.model + 
            " | " + selected.getFormattedDuration() + 
            " | " + selected.getTotalTokens() + " tokens");
        
        systemPromptArea.setText(selected.systemPrompt);
        systemPromptArea.setCaretPosition(0);
        
        userPromptArea.setText(selected.userPrompt);
        userPromptArea.setCaretPosition(0);
        
        responseArea.setText(selected.response != null ? selected.response : "(Waiting for response...)");
        responseArea.setCaretPosition(0);
    }
    
    private String formatTokens(int tokens) {
        if (tokens >= 1000000) return String.format("%.1fM", tokens / 1000000.0);
        if (tokens >= 1000) return String.format("%.1fK", tokens / 1000.0);
        return String.valueOf(tokens);
    }
    
    @Override
    public void onRecordUpdated() {
        // Debounce updates (don't refresh on every single record update)
        SwingUtilities.invokeLater(this::refreshTable);
    }
}
