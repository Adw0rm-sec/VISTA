package com.vista.security.ui;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/**
 * Professional dialog for customizing the Traffic Monitor AI analysis template.
 * Provides a polished editor for the unified system prompt with live stats,
 * section navigation, and preview of the auto-generated user prompt.
 */
public class PromptCustomizationDialog extends JDialog {

    // ── Design tokens (matching VISTA's Tailwind-inspired palette) ──
    private static final Color ACCENT_PURPLE  = new Color(139, 92, 246);
    private static final Color ACCENT_BLUE    = new Color(59, 130, 246);
    private static final Color ACCENT_GREEN   = new Color(16, 185, 129);
    private static final Color BG_CARD        = Color.WHITE;
    private static final Color BG_SUBTLE      = new Color(248, 250, 252);
    private static final Color BG_EDITOR      = new Color(253, 253, 255);
    private static final Color BORDER_COLOR   = new Color(220, 225, 232);
    private static final Color TEXT_TITLE      = new Color(30, 30, 35);
    private static final Color TEXT_MUTED      = new Color(100, 100, 110);
    private static final Color TEXT_HINT       = new Color(140, 145, 155);
    private static final Font FONT_TITLE       = new Font("Segoe UI", Font.BOLD, 18);
    private static final Font FONT_SUBTITLE    = new Font("Segoe UI", Font.PLAIN, 12);
    private static final Font FONT_SECTION     = new Font("Segoe UI", Font.BOLD, 13);
    private static final Font FONT_LABEL       = new Font("Segoe UI", Font.PLAIN, 11);
    private static final Font FONT_EDITOR      = new Font("Monospaced", Font.PLAIN, 13);
    private static final Font FONT_PREVIEW     = new Font("Monospaced", Font.PLAIN, 11);
    private static final Font FONT_BTN         = new Font("Segoe UI", Font.PLAIN, 12);
    private static final Font FONT_BTN_PRIMARY = new Font("Segoe UI", Font.BOLD, 12);
    private static final Font FONT_STATS       = new Font("Segoe UI", Font.PLAIN, 11);

    // ── State ──
    private JTextArea systemPromptArea;
    private JTextArea userPromptPreview;
    private JLabel charLabel;
    private JLabel tokenLabel;
    private JLabel lineLabel;
    private String template;
    private boolean saved = false;

    public PromptCustomizationDialog(Frame owner, String currentTemplate) {
        super(owner, "Traffic Analysis Template Editor", true);
        this.template = (currentTemplate != null && !currentTemplate.trim().isEmpty())
                ? currentTemplate
                : com.vista.security.core.IntelligentTrafficAnalyzer.getDefaultTemplate();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        initializeUI();
        setSize(1000, 780);
        setMinimumSize(new Dimension(700, 500));
        setLocationRelativeTo(owner);

        // Esc to close
        getRootPane().registerKeyboardAction(
            e -> dispose(),
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
            JComponent.WHEN_IN_FOCUSED_WINDOW
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  UI Construction
    // ═══════════════════════════════════════════════════════════════

    private void initializeUI() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG_SUBTLE);

        root.add(buildHeader(),       BorderLayout.NORTH);
        root.add(buildMainContent(),  BorderLayout.CENTER);
        root.add(buildFooter(),       BorderLayout.SOUTH);

        setContentPane(root);
    }

    // ── Header ──────────────────────────────────────────────────────
    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setBackground(BG_CARD);
        header.setBorder(new CompoundBorder(
            new MatteBorder(0, 0, 1, 0, BORDER_COLOR),
            new EmptyBorder(16, 20, 14, 20)
        ));

        // Left: icon + title
        JPanel titleBlock = new JPanel(new BorderLayout(8, 0));
        titleBlock.setOpaque(false);

        JLabel icon = new JLabel("\uD83D\uDD27");
        icon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 26));
        titleBlock.add(icon, BorderLayout.WEST);

        JPanel titleTexts = new JPanel();
        titleTexts.setOpaque(false);
        titleTexts.setLayout(new BoxLayout(titleTexts, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("HTTP Traffic Analysis Template");
        title.setFont(FONT_TITLE);
        title.setForeground(TEXT_TITLE);
        titleTexts.add(title);

        JLabel subtitle = new JLabel("Defines AI behavior for all traffic monitoring — sent as the system prompt");
        subtitle.setFont(FONT_SUBTITLE);
        subtitle.setForeground(TEXT_MUTED);
        titleTexts.add(subtitle);

        titleBlock.add(titleTexts, BorderLayout.CENTER);
        header.add(titleBlock, BorderLayout.WEST);

        // Right: live stats
        JPanel statsPanel = buildStatsPanel();
        header.add(statsPanel, BorderLayout.EAST);

        return header;
    }

    private JPanel buildStatsPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 3, 12, 0));
        panel.setOpaque(false);

        charLabel  = createStatBadge("0", "chars");
        tokenLabel = createStatBadge("0", "tokens");
        lineLabel  = createStatBadge("0", "lines");

        panel.add(charLabel);
        panel.add(tokenLabel);
        panel.add(lineLabel);

        updateStats(template);
        return panel;
    }

    private JLabel createStatBadge(String value, String unit) {
        JLabel label = new JLabel(value + " " + unit, SwingConstants.CENTER);
        label.setFont(FONT_STATS);
        label.setForeground(TEXT_MUTED);
        label.setOpaque(true);
        label.setBackground(BG_SUBTLE);
        label.setBorder(new CompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(4, 10, 4, 10)
        ));
        return label;
    }

    // ── Main Content (split: editor top, preview bottom) ───────────
    private JComponent buildMainContent() {
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.75);
        split.setDividerSize(6);
        split.setBorder(new EmptyBorder(10, 14, 0, 14));
        split.setBackground(BG_SUBTLE);

        split.setTopComponent(buildSystemPromptSection());
        split.setBottomComponent(buildUserPromptPreviewSection());

        return split;
    }

    // ── System Prompt Editor ────────────────────────────────────────
    private JPanel buildSystemPromptSection() {
        JPanel section = new JPanel(new BorderLayout(0, 6));
        section.setBackground(BG_CARD);
        section.setBorder(new CompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));

        // Section header bar
        JPanel sectionHeader = new JPanel(new BorderLayout(8, 0));
        sectionHeader.setBackground(BG_CARD);
        sectionHeader.setBorder(new CompoundBorder(
            new MatteBorder(0, 0, 1, 0, BORDER_COLOR),
            new EmptyBorder(8, 12, 8, 12)
        ));

        JLabel sectionTitle = new JLabel("\uD83E\uDD16  System Prompt");
        sectionTitle.setFont(FONT_SECTION);
        sectionTitle.setForeground(ACCENT_PURPLE);
        sectionHeader.add(sectionTitle, BorderLayout.WEST);

        JLabel sectionHint = new JLabel("Role, expertise, rules, response format — applies to all analyses");
        sectionHint.setFont(FONT_LABEL);
        sectionHint.setForeground(TEXT_HINT);
        sectionHeader.add(sectionHint, BorderLayout.EAST);

        section.add(sectionHeader, BorderLayout.NORTH);

        // Editor area
        systemPromptArea = new JTextArea(template);
        systemPromptArea.setFont(FONT_EDITOR);
        systemPromptArea.setForeground(new Color(40, 42, 54));
        systemPromptArea.setBackground(BG_EDITOR);
        systemPromptArea.setCaretColor(ACCENT_PURPLE);
        systemPromptArea.setSelectionColor(new Color(139, 92, 246, 50));
        systemPromptArea.setSelectedTextColor(new Color(40, 42, 54));
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        systemPromptArea.setTabSize(4);
        systemPromptArea.setMargin(new Insets(10, 14, 10, 14));

        // Live stats update
        systemPromptArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { onTextChanged(); }
            public void removeUpdate(DocumentEvent e)  { onTextChanged(); }
            public void changedUpdate(DocumentEvent e)  { onTextChanged(); }
        });

        JScrollPane scroll = new JScrollPane(systemPromptArea);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        section.add(scroll, BorderLayout.CENTER);

        return section;
    }

    // ── User Prompt Preview (read-only) ─────────────────────────────
    private JPanel buildUserPromptPreviewSection() {
        JPanel section = new JPanel(new BorderLayout(0, 0));
        section.setBackground(BG_CARD);
        section.setBorder(new CompoundBorder(
            new LineBorder(BORDER_COLOR, 1, true),
            new EmptyBorder(0, 0, 0, 0)
        ));

        // Section header
        JPanel sectionHeader = new JPanel(new BorderLayout(8, 0));
        sectionHeader.setBackground(BG_CARD);
        sectionHeader.setBorder(new CompoundBorder(
            new MatteBorder(0, 0, 1, 0, BORDER_COLOR),
            new EmptyBorder(8, 12, 8, 12)
        ));

        JLabel sectionTitle = new JLabel("\uD83D\uDCE8  User Prompt (auto-generated, read-only)");
        sectionTitle.setFont(FONT_SECTION);
        sectionTitle.setForeground(ACCENT_BLUE);
        sectionHeader.add(sectionTitle, BorderLayout.WEST);

        JLabel sectionHint = new JLabel("Sent with each request — contains actual HTTP data");
        sectionHint.setFont(FONT_LABEL);
        sectionHint.setForeground(TEXT_HINT);
        sectionHeader.add(sectionHint, BorderLayout.EAST);

        section.add(sectionHeader, BorderLayout.NORTH);

        // Preview content
        userPromptPreview = new JTextArea(
            "Analyze this <JavaScript|HTML> for security vulnerabilities.\n\n" +
            "URL: <request URL>\n" +
            "Content-Type: <content type>\n" +
            "Size: <N> bytes\n\n" +
            "Content:\n<actual HTTP response body or JS/HTML content>"
        );
        userPromptPreview.setFont(FONT_PREVIEW);
        userPromptPreview.setForeground(TEXT_MUTED);
        userPromptPreview.setBackground(BG_SUBTLE);
        userPromptPreview.setEditable(false);
        userPromptPreview.setLineWrap(true);
        userPromptPreview.setWrapStyleWord(true);
        userPromptPreview.setMargin(new Insets(10, 14, 10, 14));
        userPromptPreview.setCursor(Cursor.getDefaultCursor());

        JScrollPane scroll = new JScrollPane(userPromptPreview);
        scroll.setBorder(null);
        section.add(scroll, BorderLayout.CENTER);

        return section;
    }

    // ── Footer (buttons) ────────────────────────────────────────────
    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBackground(BG_CARD);
        footer.setBorder(new CompoundBorder(
            new MatteBorder(1, 0, 0, 0, BORDER_COLOR),
            new EmptyBorder(10, 20, 10, 20)
        ));

        // Left side: info hint
        JLabel hint = new JLabel("💡 The system prompt defines how the AI analyzes every HTTP request in scope");
        hint.setFont(FONT_LABEL);
        hint.setForeground(TEXT_HINT);
        footer.add(hint, BorderLayout.WEST);

        // Right side: action buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.setOpaque(false);

        JButton resetBtn = createButton("↺ Reset to Default", FONT_BTN, null, false);
        resetBtn.addActionListener(this::resetToDefault);

        JButton cancelBtn = createButton("Cancel", FONT_BTN, null, false);
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = createButton("✔ Save Template", FONT_BTN_PRIMARY, ACCENT_PURPLE, true);
        saveBtn.addActionListener(this::saveTemplate);

        buttons.add(resetBtn);
        buttons.add(cancelBtn);
        buttons.add(Box.createHorizontalStrut(4));
        buttons.add(saveBtn);

        footer.add(buttons, BorderLayout.EAST);
        return footer;
    }

    // ═══════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════

    private JButton createButton(String text, Font font, Color accentColor, boolean primary) {
        JButton btn = new JButton(text);
        btn.setFont(font);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        if (primary && accentColor != null) {
            btn.setBackground(accentColor);
            btn.setForeground(Color.WHITE);
            btn.setOpaque(true);
            btn.setBorderPainted(false);
            btn.setBorder(new EmptyBorder(7, 18, 7, 18));
        } else {
            btn.setBackground(BG_CARD);
            btn.setBorder(new CompoundBorder(
                new LineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(6, 14, 6, 14)
            ));
        }
        return btn;
    }

    private void onTextChanged() {
        updateStats(systemPromptArea.getText());
    }

    private void updateStats(String text) {
        if (text == null) text = "";
        int chars = text.length();
        int tokens = chars / 4;
        int lines = text.isEmpty() ? 0 : text.split("\n", -1).length;
        charLabel.setText(String.format("%,d chars", chars));
        tokenLabel.setText(String.format("~%,d tokens", tokens));
        lineLabel.setText(String.format("%,d lines", lines));
    }

    // ── Actions ─────────────────────────────────────────────────────
    private void resetToDefault(ActionEvent e) {
        int result = JOptionPane.showConfirmDialog(
            this,
            "Reset to the default template?\nThis will discard all your changes.",
            "Confirm Reset",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (result == JOptionPane.YES_OPTION) {
            systemPromptArea.setText(
                com.vista.security.core.IntelligentTrafficAnalyzer.getDefaultTemplate()
            );
            systemPromptArea.setCaretPosition(0);
        }
    }

    private void saveTemplate(ActionEvent e) {
        String text = systemPromptArea.getText();
        if (text == null || text.trim().isEmpty()) {
            JOptionPane.showMessageDialog(
                this,
                "Template cannot be empty.\nUse 'Reset to Default' to restore the default.",
                "Validation Error",
                JOptionPane.WARNING_MESSAGE
            );
            return;
        }
        template = text;
        saved = true;
        JOptionPane.showMessageDialog(
            this,
            "Template saved ✔\n\nAll future Traffic Monitor analyses will use this template.",
            "Saved",
            JOptionPane.INFORMATION_MESSAGE
        );
        dispose();
    }

    // ── Public API ──────────────────────────────────────────────────
    public boolean isSaved()       { return saved; }
    public String  getTemplate()   { return template; }
}
