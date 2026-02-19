package com.vista.security.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;
import java.awt.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Professional Chat Conversation Pane for the AI Security Advisor.
 *
 * Design:
 *   USER  → Clean left-aligned block with indigo accent bar, dark text,
 *           NO background color (avoids the per-character bleed issue).
 *   VISTA → Clean block with emerald accent, rich markdown rendering.
 *   SYSTEM→ Subtle muted inline notification.
 *
 * Key rule: NEVER use StyleConstants.setBackground() for multi-line blocks
 * in JTextPane — it paints only behind glyphs and bleeds unevenly.
 * Instead we use colored accent characters + foreground color hierarchy.
 */
public class ChatConversationPane extends JPanel {

    private final JTextPane textPane;
    private final StyledDocument doc;
    private final JScrollPane scrollPane;

    // ── Style names ──
    private static final String S_USER_BAR     = "u-bar";
    private static final String S_USER_NAME    = "u-name";
    private static final String S_USER_TIME    = "u-time";
    private static final String S_USER_TEXT    = "u-text";

    private static final String S_AI_BAR       = "a-bar";
    private static final String S_AI_NAME      = "a-name";
    private static final String S_AI_TIME      = "a-time";
    private static final String S_AI_TEXT      = "a-text";
    private static final String S_AI_BOLD      = "a-bold";
    private static final String S_AI_ITALIC    = "a-italic";
    private static final String S_AI_CODE      = "a-code";
    private static final String S_AI_CBLK      = "a-cblk";
    private static final String S_AI_CBLK_HDR  = "a-cblk-h";
    private static final String S_AI_HEADING   = "a-heading";
    private static final String S_AI_BULLET    = "a-bullet";
    private static final String S_AI_NUM       = "a-num";

    private static final String S_SYS          = "s-text";
    private static final String S_SPACER       = "spacer";
    private static final String S_DIV          = "div";

    // ═════════════════════════════════════════════════════════════
    //  Colors  (no setBackground on text — only foreground + accent chars)
    // ═════════════════════════════════════════════════════════════

    // User (indigo family — accent bar only, text is dark)
    private static final Color USER_BAR_CLR    = new Color(99, 102, 241);    // Indigo-500
    private static final Color USER_NAME_CLR   = new Color(67, 56, 202);     // Indigo-700
    private static final Color USER_TEXT_CLR   = new Color(30, 27, 75);      // Indigo-950
    private static final Color USER_TIME_CLR   = new Color(165, 180, 252);   // Indigo-300

    // AI (emerald + gray family)
    private static final Color AI_BAR_CLR      = new Color(16, 185, 129);    // Emerald-500
    private static final Color AI_NAME_CLR     = new Color(5, 150, 105);     // Emerald-600
    private static final Color AI_TEXT_CLR     = new Color(31, 41, 55);      // Gray-800
    private static final Color AI_BOLD_CLR     = new Color(17, 24, 39);      // Gray-900
    private static final Color AI_HEADING_CLR  = new Color(17, 24, 39);      // Gray-900
    private static final Color AI_CODE_FG      = new Color(147, 51, 234);    // Purple-600
    private static final Color AI_CODE_BG      = new Color(243, 232, 255);   // Purple-100 (only on short inline)
    private static final Color AI_CBLK_FG      = new Color(30, 41, 59);      // Slate-800 (dark on light bg)
    private static final Color AI_CBLK_HDR_FG  = new Color(100, 116, 139);   // Slate-500
    private static final Color AI_BULLET_CLR   = new Color(16, 185, 129);    // Emerald-500
    private static final Color AI_NUM_CLR      = new Color(59, 130, 246);    // Blue-500
    private static final Color AI_TIME_CLR     = new Color(156, 163, 175);   // Gray-400

    // System / layout
    private static final Color SYS_CLR         = new Color(107, 114, 128);   // Gray-500
    private static final Color PANE_BG         = new Color(251, 252, 253);   // Near-white
    private static final Color DIV_CLR         = new Color(229, 231, 235);   // Gray-200

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm");
    private static final String FONT_UI   = pickFont("Inter", "Segoe UI", "SF Pro Display", ".SF NS Text", "Helvetica Neue", "Arial");
    private static final String FONT_MONO = pickFont("JetBrains Mono", "Fira Code", "Consolas", "SF Mono", "Monaco", "Courier New");

    public ChatConversationPane() {
        setLayout(new BorderLayout());
        setBackground(PANE_BG);

        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setBackground(PANE_BG);
        textPane.setMargin(new Insets(10, 16, 10, 16));

        DefaultCaret caret = (DefaultCaret) textPane.getCaret();
        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

        doc = textPane.getStyledDocument();
        buildStyles();

        scrollPane = new JScrollPane(textPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    // ═════════════════════════════════════════════════════════════
    //  Styles — NO setBackground on any multi-line style
    // ═════════════════════════════════════════════════════════════

    private void buildStyles() {
        Style root = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);
        Style s;

        // ── User ──
        s = doc.addStyle(S_USER_BAR, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setForeground(s, USER_BAR_CLR);
        StyleConstants.setBold(s, true);

        s = doc.addStyle(S_USER_NAME, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 12);
        StyleConstants.setBold(s, true);
        StyleConstants.setForeground(s, USER_NAME_CLR);

        s = doc.addStyle(S_USER_TIME, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 10);
        StyleConstants.setForeground(s, USER_TIME_CLR);

        s = doc.addStyle(S_USER_TEXT, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setForeground(s, USER_TEXT_CLR);
        StyleConstants.setLineSpacing(s, 0.2f);

        // ── AI ──
        s = doc.addStyle(S_AI_BAR, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setForeground(s, AI_BAR_CLR);
        StyleConstants.setBold(s, true);

        s = doc.addStyle(S_AI_NAME, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 12);
        StyleConstants.setBold(s, true);
        StyleConstants.setForeground(s, AI_NAME_CLR);

        s = doc.addStyle(S_AI_TIME, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 10);
        StyleConstants.setForeground(s, AI_TIME_CLR);

        s = doc.addStyle(S_AI_TEXT, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setForeground(s, AI_TEXT_CLR);
        StyleConstants.setLineSpacing(s, 0.3f);

        s = doc.addStyle(S_AI_BOLD, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setBold(s, true);
        StyleConstants.setForeground(s, AI_BOLD_CLR);

        s = doc.addStyle(S_AI_ITALIC, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setItalic(s, true);
        StyleConstants.setForeground(s, AI_TEXT_CLR);

        s = doc.addStyle(S_AI_HEADING, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 14);
        StyleConstants.setBold(s, true);
        StyleConstants.setForeground(s, AI_HEADING_CLR);
        StyleConstants.setSpaceAbove(s, 10);
        StyleConstants.setSpaceBelow(s, 4);

        // Inline code — small snippet, background OK here (short text)
        s = doc.addStyle(S_AI_CODE, root);
        StyleConstants.setFontFamily(s, FONT_MONO);
        StyleConstants.setFontSize(s, 12);
        StyleConstants.setForeground(s, AI_CODE_FG);
        StyleConstants.setBackground(s, AI_CODE_BG);

        // Code block lines — NO setBackground (avoids glyph-only paint bleed)
        s = doc.addStyle(S_AI_CBLK, root);
        StyleConstants.setFontFamily(s, FONT_MONO);
        StyleConstants.setFontSize(s, 12);
        StyleConstants.setForeground(s, AI_CBLK_FG);
        StyleConstants.setLineSpacing(s, 0.15f);

        s = doc.addStyle(S_AI_CBLK_HDR, root);
        StyleConstants.setFontFamily(s, FONT_MONO);
        StyleConstants.setFontSize(s, 10);
        StyleConstants.setBold(s, true);
        StyleConstants.setForeground(s, AI_CBLK_HDR_FG);

        s = doc.addStyle(S_AI_BULLET, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setForeground(s, AI_BULLET_CLR);
        StyleConstants.setBold(s, true);

        s = doc.addStyle(S_AI_NUM, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 13);
        StyleConstants.setForeground(s, AI_NUM_CLR);
        StyleConstants.setBold(s, true);

        // ── System ──
        s = doc.addStyle(S_SYS, root);
        StyleConstants.setFontFamily(s, FONT_UI);
        StyleConstants.setFontSize(s, 11);
        StyleConstants.setForeground(s, SYS_CLR);
        StyleConstants.setItalic(s, true);

        // ── Layout ──
        s = doc.addStyle(S_SPACER, root);
        StyleConstants.setFontSize(s, 8);
        StyleConstants.setForeground(s, PANE_BG);

        s = doc.addStyle(S_DIV, root);
        StyleConstants.setFontSize(s, 2);
        StyleConstants.setForeground(s, DIV_CLR);
    }

    // ═════════════════════════════════════════════════════════════
    //  Public API
    // ═════════════════════════════════════════════════════════════

    /**
     * User message — indigo accent bar on left, dark text, NO background fill.
     *
     *   ▎ You · 22:33
     *   ▎ How to test for XSS Testing?
     */
    public void appendUserMessage(String message) {
        try {
            w("\n", S_SPACER);

            // Header: accent bar + name + time
            w("  ▎ ", S_USER_BAR);
            w("You", S_USER_NAME);
            w("  ·  ", S_USER_BAR);
            w(time(), S_USER_TIME);
            w("\n", S_USER_TEXT);

            // Body lines — each prefixed with accent bar
            for (String line : message.split("\n")) {
                w("  ▎ ", S_USER_BAR);
                w(line + "\n", S_USER_TEXT);
            }

            // Spacer after message
            w("\n", S_SPACER);

            scrollToEnd();
        } catch (BadLocationException ignored) {}
    }

    /**
     * AI (VISTA) message — emerald accent bar, rich markdown body.
     *
     *   ▎ 🛡 VISTA · 22:33
     *   ─ ─ ─ ─ ─ ─ ─ ─ ─
     *     Rich formatted content...
     *   ━━━━━━━━━━━━━━━━━━━━
     */
    public void appendAIMessage(String message) {
        try {
            w("\n", S_SPACER);

            // Header
            w("  ▎ ", S_AI_BAR);
            w("🛡 VISTA", S_AI_NAME);
            w("  ·  ", S_AI_BAR);
            w(time(), S_AI_TIME);
            w("\n", S_AI_TEXT);

            // Separator
            w("    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─\n", S_DIV);
            w("\n", S_SPACER);

            // Body
            renderRichContent(message);

            // End divider
            w("\n", S_SPACER);
            w("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", S_DIV);
            w("\n", S_SPACER);

            scrollToEnd();
        } catch (BadLocationException ignored) {}
    }

    /** System notification — muted italic. */
    public void appendSystemMessage(String message) {
        try {
            w("  ⚙ " + message + "\n", S_SYS);
            scrollToEnd();
        } catch (BadLocationException ignored) {}
    }

    /** Clears all content. */
    public void clear() {
        try { doc.remove(0, doc.getLength()); } catch (BadLocationException ignored) {}
    }

    /** Backward-compat raw text. */
    public void appendRawText(String text) {
        try { w(text, S_SYS); scrollToEnd(); } catch (BadLocationException ignored) {}
    }

    // ═════════════════════════════════════════════════════════════
    //  Rich Content Renderer
    // ═════════════════════════════════════════════════════════════

    private void renderRichContent(String message) throws BadLocationException {
        String[] lines = message.split("\n");
        boolean inCodeBlock = false;
        StringBuilder codeBuf = new StringBuilder();
        String codeLang = "";

        for (String line : lines) {
            String trimmed = line.trim();

            // ── Code block toggle ──
            if (trimmed.startsWith("```")) {
                if (inCodeBlock) {
                    String label = codeLang.isEmpty() ? "CODE" : codeLang.toUpperCase();
                    // Header: border chars in gray, label in muted
                    String hdr = " " + label + " ";
                    String pad = "─".repeat(Math.max(1, 54 - hdr.length()));
                    w("    ┌" + hdr + pad + "\n", S_AI_CBLK_HDR);
                    for (String cl : codeBuf.toString().split("\n")) {
                        w("    │  ", S_AI_CBLK_HDR);
                        w(cl + "\n", S_AI_CBLK);
                    }
                    w("    └" + "─".repeat(55) + "\n", S_AI_CBLK_HDR);
                    codeBuf.setLength(0);
                    codeLang = "";
                    inCodeBlock = false;
                } else {
                    inCodeBlock = true;
                    codeLang = trimmed.length() > 3 ? trimmed.substring(3).trim() : "";
                }
                continue;
            }
            if (inCodeBlock) {
                codeBuf.append(line).append("\n");
                continue;
            }

            // ── Headings ──
            if (trimmed.startsWith("### ")) {
                w("    ◆ ", S_AI_BULLET);
                w(trimmed.substring(4) + "\n", S_AI_HEADING);
                continue;
            }
            if (trimmed.startsWith("## ")) {
                w("    ■ ", S_AI_NUM);
                w(trimmed.substring(3) + "\n", S_AI_HEADING);
                continue;
            }
            if (trimmed.startsWith("# ")) {
                w("    ● ", S_AI_NUM);
                w(trimmed.substring(2) + "\n", S_AI_HEADING);
                continue;
            }

            // ── Numbered list ──
            if (trimmed.matches("^\\d+\\.\\s.*")) {
                int dot = trimmed.indexOf('.');
                String num = trimmed.substring(0, dot + 1);
                String rest = trimmed.substring(dot + 1).trim();
                w("    ", S_AI_TEXT);
                w(num + " ", S_AI_NUM);
                renderInline(rest);
                w("\n", S_AI_TEXT);
                continue;
            }

            // ── Bullet points ──
            if (trimmed.startsWith("- ") || trimmed.startsWith("• ") ||
                (trimmed.startsWith("* ") && !trimmed.startsWith("**"))) {
                String text = trimmed.substring(2);
                int indent = line.indexOf(trimmed.charAt(0));
                String pad = "    " + "  ".repeat(Math.min(indent / 2, 4));
                w(pad, S_AI_TEXT);
                w("→ ", S_AI_BULLET);
                renderInline(text);
                w("\n", S_AI_TEXT);
                continue;
            }

            // ── Horizontal rule ──
            if (trimmed.matches("^[-=─]{3,}$")) {
                w("    ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──\n", S_DIV);
                continue;
            }

            // ── Empty line ──
            if (trimmed.isEmpty()) {
                w("\n", S_SPACER);
                continue;
            }

            // ── Regular text ──
            w("    ", S_AI_TEXT);
            renderInline(trimmed);
            w("\n", S_AI_TEXT);
        }

        // Unclosed code block
        if (inCodeBlock && codeBuf.length() > 0) {
            w("    ┌ CODE " + "─".repeat(44) + "\n", S_AI_CBLK_HDR);
            for (String cl : codeBuf.toString().split("\n")) {
                w("    │  ", S_AI_CBLK_HDR);
                w(cl + "\n", S_AI_CBLK);
            }
            w("    └" + "─".repeat(55) + "\n", S_AI_CBLK_HDR);
        }
    }

    /** Inline formatting: **bold**, `code`, *italic* */
    private void renderInline(String text) throws BadLocationException {
        int i = 0, len = text.length();
        StringBuilder buf = new StringBuilder();

        while (i < len) {
            char c = text.charAt(i);

            // Bold **text**
            if (c == '*' && i + 1 < len && text.charAt(i + 1) == '*') {
                flush(buf);
                int end = text.indexOf("**", i + 2);
                if (end > 0) {
                    w(text.substring(i + 2, end), S_AI_BOLD);
                    i = end + 2;
                    continue;
                }
            }
            // Inline code `text`
            if (c == '`') {
                flush(buf);
                int end = text.indexOf('`', i + 1);
                if (end > 0) {
                    w(" " + text.substring(i + 1, end) + " ", S_AI_CODE);
                    i = end + 1;
                    continue;
                }
            }
            // Italic *text* (single)
            if (c == '*' && (i + 1 >= len || text.charAt(i + 1) != '*')) {
                flush(buf);
                int end = text.indexOf('*', i + 1);
                if (end > 0 && end > i + 1) {
                    w(text.substring(i + 1, end), S_AI_ITALIC);
                    i = end + 1;
                    continue;
                }
            }

            buf.append(c);
            i++;
        }
        flush(buf);
    }

    private void flush(StringBuilder buf) throws BadLocationException {
        if (buf.length() > 0) {
            w(buf.toString(), S_AI_TEXT);
            buf.setLength(0);
        }
    }

    // ═════════════════════════════════════════════════════════════
    //  Helpers
    // ═════════════════════════════════════════════════════════════

    private void w(String text, String style) throws BadLocationException {
        doc.insertString(doc.getLength(), text, doc.getStyle(style));
    }

    private String time() { return LocalTime.now().format(TIME_FMT); }

    private void scrollToEnd() {
        SwingUtilities.invokeLater(() -> {
            try {
                textPane.setCaretPosition(doc.getLength());
                JScrollBar vbar = scrollPane.getVerticalScrollBar();
                vbar.setValue(vbar.getMaximum());
            } catch (Exception ignored) {}
        });
    }

    public JScrollPane getScrollPane() { return scrollPane; }

    private static String pickFont(String... names) {
        String[] sys = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();
        java.util.Set<String> set = new java.util.HashSet<>(java.util.Arrays.asList(sys));
        for (String n : names) { if (set.contains(n)) return n; }
        return names[names.length - 1];
    }
}
