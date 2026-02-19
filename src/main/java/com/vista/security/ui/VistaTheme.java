package com.vista.security.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicTabbedPaneUI;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;

/**
 * VISTA Professional Theme System
 * 
 * Centralized color palette, fonts, borders, and component factory methods
 * for a cohesive, professional security-tool look and feel.
 * 
 * Inspired by modern security dashboards (dark accents, clean typography).
 */
public final class VistaTheme {

    private VistaTheme() {} // Utility class

    // ═══════════════════════════════════════════════════════════════
    // COLOR PALETTE
    // ═══════════════════════════════════════════════════════════════

    // Primary brand colors
    public static final Color PRIMARY        = new Color(59, 130, 246);   // Blue-500
    public static final Color PRIMARY_DARK   = new Color(37, 99, 235);    // Blue-600
    public static final Color PRIMARY_LIGHT  = new Color(96, 165, 250);   // Blue-400
    public static final Color PRIMARY_BG     = new Color(239, 246, 255);  // Blue-50

    // Accent / actions
    public static final Color ACCENT         = new Color(14, 165, 233);   // Sky-500
    public static final Color ACCENT_DARK    = new Color(2, 132, 199);    // Sky-600

    // Backgrounds
    public static final Color BG_DARK        = new Color(15, 23, 42);     // Slate-900
    public static final Color BG_PANEL       = new Color(248, 250, 252);  // Slate-50
    public static final Color BG_CARD        = Color.WHITE;
    public static final Color BG_SIDEBAR     = new Color(241, 245, 249);  // Slate-100
    public static final Color BG_INPUT       = Color.WHITE;
    public static final Color BG_HOVER       = new Color(241, 245, 249);  // Slate-100
    public static final Color BG_CODE        = new Color(248, 250, 252);  // Slate-50

    // Borders
    public static final Color BORDER         = new Color(226, 232, 240);  // Slate-200
    public static final Color BORDER_LIGHT   = new Color(241, 245, 249);  // Slate-100
    public static final Color BORDER_FOCUS   = PRIMARY;
    public static final Color BORDER_DARK    = new Color(51, 65, 85);     // Slate-700

    // Text
    public static final Color TEXT_PRIMARY   = new Color(15, 23, 42);     // Slate-900
    public static final Color TEXT_SECONDARY = new Color(100, 116, 139);  // Slate-500
    public static final Color TEXT_MUTED     = new Color(148, 163, 184);  // Slate-400
    public static final Color TEXT_ON_DARK   = new Color(226, 232, 240);  // Slate-200
    public static final Color TEXT_ON_PRIMARY = Color.WHITE;

    // Severity colors  
    public static final Color SEVERITY_CRITICAL = new Color(220, 38, 38);   // Red-600
    public static final Color SEVERITY_HIGH     = new Color(234, 88, 12);   // Orange-600
    public static final Color SEVERITY_MEDIUM   = new Color(202, 138, 4);   // Yellow-600
    public static final Color SEVERITY_LOW      = new Color(37, 99, 235);   // Blue-600
    public static final Color SEVERITY_INFO     = new Color(100, 116, 139); // Slate-500

    // Severity background (lighter tints)
    public static final Color SEVERITY_CRITICAL_BG = new Color(254, 242, 242);  // Red-50
    public static final Color SEVERITY_HIGH_BG     = new Color(255, 247, 237);  // Orange-50
    public static final Color SEVERITY_MEDIUM_BG   = new Color(254, 252, 232);  // Yellow-50
    public static final Color SEVERITY_LOW_BG      = new Color(239, 246, 255);  // Blue-50
    public static final Color SEVERITY_INFO_BG     = new Color(248, 250, 252);  // Slate-50

    // Status
    public static final Color STATUS_SUCCESS = new Color(22, 163, 74);    // Green-600
    public static final Color STATUS_WARNING = new Color(202, 138, 4);    // Yellow-600
    public static final Color STATUS_ERROR   = new Color(220, 38, 38);    // Red-600
    public static final Color STATUS_READY   = new Color(34, 197, 94);    // Green-500

    // Chat message colors
    public static final Color CHAT_USER_BG   = new Color(219, 234, 254);  // Blue-100
    public static final Color CHAT_AI_BG     = new Color(243, 244, 246);  // Gray-100
    public static final Color CHAT_SYSTEM_BG = new Color(254, 252, 232);  // Yellow-50

    // Button colors
    public static final Color BTN_PRIMARY_BG   = PRIMARY;
    public static final Color BTN_PRIMARY_FG   = Color.WHITE;
    public static final Color BTN_SECONDARY_BG = new Color(241, 245, 249); // Slate-100
    public static final Color BTN_SECONDARY_FG = new Color(51, 65, 85);    // Slate-700
    public static final Color BTN_DANGER_BG    = new Color(254, 242, 242); // Red-50
    public static final Color BTN_DANGER_FG    = SEVERITY_CRITICAL;
    public static final Color BTN_SUCCESS_BG   = new Color(240, 253, 244); // Green-50
    public static final Color BTN_SUCCESS_FG   = STATUS_SUCCESS;

    // ═══════════════════════════════════════════════════════════════
    // FONTS
    // ═══════════════════════════════════════════════════════════════

    private static final String FONT_FAMILY = getAvailableFont("Segoe UI", "SF Pro Display", ".SF NS Text", "Helvetica Neue", "Arial");
    private static final String MONO_FAMILY = getAvailableFont("JetBrains Mono", "Consolas", "SF Mono", "Monaco", "Courier New");

    public static final Font FONT_TITLE      = new Font(FONT_FAMILY, Font.BOLD, 18);
    public static final Font FONT_SUBTITLE   = new Font(FONT_FAMILY, Font.PLAIN, 13);
    public static final Font FONT_HEADING     = new Font(FONT_FAMILY, Font.BOLD, 14);
    public static final Font FONT_BODY        = new Font(FONT_FAMILY, Font.PLAIN, 12);
    public static final Font FONT_BODY_BOLD   = new Font(FONT_FAMILY, Font.BOLD, 12);
    public static final Font FONT_SMALL       = new Font(FONT_FAMILY, Font.PLAIN, 11);
    public static final Font FONT_SMALL_BOLD  = new Font(FONT_FAMILY, Font.BOLD, 11);
    public static final Font FONT_TINY        = new Font(FONT_FAMILY, Font.PLAIN, 10);
    public static final Font FONT_MONO        = new Font(MONO_FAMILY, Font.PLAIN, 12);
    public static final Font FONT_MONO_SMALL  = new Font(MONO_FAMILY, Font.PLAIN, 11);
    public static final Font FONT_LABEL       = new Font(FONT_FAMILY, Font.BOLD, 11);
    public static final Font FONT_TAB         = new Font(FONT_FAMILY, Font.BOLD, 12);
    public static final Font FONT_BTN         = new Font(FONT_FAMILY, Font.BOLD, 12);
    public static final Font FONT_SECTION     = new Font(FONT_FAMILY, Font.BOLD, 13);
    public static final Font FONT_BADGE       = new Font(FONT_FAMILY, Font.BOLD, 10);

    /**
     * Find the first available font from the list.
     */
    private static String getAvailableFont(String... names) {
        String[] systemFonts = GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getAvailableFontFamilyNames();
        java.util.Set<String> fontSet = new java.util.HashSet<>(java.util.Arrays.asList(systemFonts));
        for (String name : names) {
            if (fontSet.contains(name)) return name;
        }
        return names[names.length - 1]; // fallback to last
    }

    // ═══════════════════════════════════════════════════════════════
    // BORDERS & INSETS
    // ═══════════════════════════════════════════════════════════════

    public static Border panelBorder() {
        return new EmptyBorder(16, 16, 16, 16);
    }

    public static Border panelBorderCompact() {
        return new EmptyBorder(10, 12, 10, 12);
    }

    public static Border cardBorder() {
        return BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER, 1),
            new EmptyBorder(14, 16, 14, 16)
        );
    }

    public static Border sectionBorder(String title) {
        return BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER, 1),
                "  " + title + "  ",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                FONT_SECTION,
                TEXT_PRIMARY
            ),
            new EmptyBorder(8, 12, 10, 12)
        );
    }

    public static Border inputBorder() {
        return BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER, 1),
            new EmptyBorder(6, 10, 6, 10)
        );
    }

    public static Border focusInputBorder() {
        return BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_FOCUS, 2),
            new EmptyBorder(5, 9, 5, 9)
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // COMPONENT FACTORIES
    // ═══════════════════════════════════════════════════════════════

    /**
     * Create a styled primary button (blue background, white text).
     */
    public static JButton primaryButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_BTN);
        btn.setForeground(BTN_PRIMARY_FG);
        btn.setBackground(BTN_PRIMARY_BG);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setOpaque(true);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(8, 18, 8, 18));
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setBackground(PRIMARY_DARK);
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setBackground(BTN_PRIMARY_BG);
            }
        });
        return btn;
    }

    /**
     * Create a styled secondary button (subtle background).
     */
    public static JButton secondaryButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_BODY);
        btn.setForeground(BTN_SECONDARY_FG);
        btn.setBackground(BTN_SECONDARY_BG);
        btn.setFocusPainted(false);
        btn.setBorderPainted(true);
        btn.setOpaque(true);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER, 1),
            new EmptyBorder(6, 14, 6, 14)
        ));
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setBackground(BG_HOVER);
                btn.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(PRIMARY_LIGHT, 1),
                    new EmptyBorder(6, 14, 6, 14)
                ));
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setBackground(BTN_SECONDARY_BG);
                btn.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(BORDER, 1),
                    new EmptyBorder(6, 14, 6, 14)
                ));
            }
        });
        return btn;
    }

    /**
     * Create a styled compact/small button for toolbar actions.
     */
    public static JButton compactButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_SMALL);
        btn.setForeground(BTN_SECONDARY_FG);
        btn.setBackground(BTN_SECONDARY_BG);
        btn.setFocusPainted(false);
        btn.setOpaque(true);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER, 1),
            new EmptyBorder(4, 10, 4, 10)
        ));
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setBackground(BG_HOVER);
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setBackground(BTN_SECONDARY_BG);
            }
        });
        return btn;
    }

    /**
     * Create a quick-action pill button (for tags / quick filters).
     */
    public static JButton pillButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_TINY);
        btn.setForeground(PRIMARY);
        btn.setBackground(PRIMARY_BG);
        btn.setFocusPainted(false);
        btn.setOpaque(true);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(191, 219, 254), 1),  // Blue-200
            new EmptyBorder(3, 10, 3, 10)
        ));
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setBackground(PRIMARY);
                btn.setForeground(Color.WHITE);
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setBackground(PRIMARY_BG);
                btn.setForeground(PRIMARY);
            }
        });
        return btn;
    }

    /**
     * Style a JTextField with professional look.
     */
    public static void styleTextField(JTextField field) {
        field.setFont(FONT_BODY);
        field.setBackground(BG_INPUT);
        field.setForeground(TEXT_PRIMARY);
        field.setCaretColor(TEXT_PRIMARY);
        field.setBorder(inputBorder());
        field.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusGained(java.awt.event.FocusEvent e) {
                field.setBorder(focusInputBorder());
            }
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                field.setBorder(inputBorder());
            }
        });
    }

    /**
     * Style a JComboBox with professional look.
     */
    public static void styleComboBox(JComboBox<?> combo) {
        combo.setFont(FONT_BODY);
        combo.setBackground(BG_INPUT);
        combo.setForeground(TEXT_PRIMARY);
        combo.setBorder(BorderFactory.createLineBorder(BORDER, 1));
    }

    /**
     * Style a JTextArea for code/monospace content.
     */
    public static void styleCodeArea(JTextArea area) {
        area.setFont(FONT_MONO);
        area.setBackground(BG_CODE);
        area.setForeground(TEXT_PRIMARY);
        area.setCaretColor(TEXT_PRIMARY);
        area.setMargin(new Insets(8, 10, 8, 10));
        area.setLineWrap(false);
    }

    /**
     * Style a JTextArea for conversation/readable content.
     */
    public static void styleTextArea(JTextArea area) {
        area.setFont(FONT_BODY);
        area.setBackground(BG_CARD);
        area.setForeground(TEXT_PRIMARY);
        area.setCaretColor(TEXT_PRIMARY);
        area.setMargin(new Insets(10, 12, 10, 12));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
    }

    /**
     * Style a JTable with professional look.
     */
    public static void styleTable(JTable table) {
        table.setFont(FONT_BODY);
        table.setForeground(TEXT_PRIMARY);
        table.setBackground(BG_CARD);
        table.setSelectionBackground(PRIMARY_BG);
        table.setSelectionForeground(PRIMARY_DARK);
        table.setRowHeight(28);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(false);
        table.setGridColor(BORDER_LIGHT);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setBorder(null);

        JTableHeader header = table.getTableHeader();
        header.setFont(FONT_SMALL_BOLD);
        header.setBackground(BG_SIDEBAR);
        header.setForeground(TEXT_SECONDARY);
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, BORDER));
        header.setPreferredSize(new Dimension(header.getWidth(), 32));
        
        // Reusable renderer for left-aligned cells
        DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer();
        cellRenderer.setBorder(new EmptyBorder(0, 8, 0, 8));
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(cellRenderer);
        }
    }

    /**
     * Style a JTabbedPane with clean professional tabs.
     */
    public static void styleTabbedPane(JTabbedPane tabbedPane) {
        tabbedPane.setFont(FONT_TAB);
        tabbedPane.setBackground(BG_PANEL);
        tabbedPane.setForeground(TEXT_SECONDARY);
        tabbedPane.setBorder(null);
        tabbedPane.setTabPlacement(JTabbedPane.TOP);
        // Use custom UI for professional look
        tabbedPane.setUI(new VistaTabbedPaneUI());
    }

    /**
     * Create a section header label.
     */
    public static JLabel sectionHeader(String text) {
        JLabel label = new JLabel(text);
        label.setFont(FONT_HEADING);
        label.setForeground(TEXT_PRIMARY);
        label.setBorder(new EmptyBorder(0, 0, 4, 0));
        return label;
    }

    /**
     * Create a muted subtitle / description label.
     */
    public static JLabel subtitle(String text) {
        JLabel label = new JLabel(text);
        label.setFont(FONT_SMALL);
        label.setForeground(TEXT_SECONDARY);
        return label;
    }

    /**
     * Create a severity badge label.
     */
    public static JLabel severityBadge(String severity) {
        JLabel badge = new JLabel(" " + severity.toUpperCase() + " ");
        badge.setFont(FONT_BADGE);
        badge.setOpaque(true);
        badge.setBorder(new EmptyBorder(2, 8, 2, 8));

        switch (severity.toUpperCase()) {
            case "CRITICAL" -> { badge.setForeground(SEVERITY_CRITICAL); badge.setBackground(SEVERITY_CRITICAL_BG); }
            case "HIGH"     -> { badge.setForeground(SEVERITY_HIGH);     badge.setBackground(SEVERITY_HIGH_BG); }
            case "MEDIUM"   -> { badge.setForeground(SEVERITY_MEDIUM);   badge.setBackground(SEVERITY_MEDIUM_BG); }
            case "LOW"      -> { badge.setForeground(SEVERITY_LOW);      badge.setBackground(SEVERITY_LOW_BG); }
            default         -> { badge.setForeground(SEVERITY_INFO);     badge.setBackground(SEVERITY_INFO_BG); }
        }
        return badge;
    }

    /**
     * Create a status indicator dot.
     */
    public static JLabel statusDot(Color color) {
        JLabel dot = new JLabel("●") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);
                g2.fillOval(2, (getHeight() - 8) / 2, 8, 8);
                g2.dispose();
            }
        };
        dot.setPreferredSize(new Dimension(12, 12));
        return dot;
    }

    /**
     * Get the severity color for a severity string.
     */
    public static Color getSeverityColor(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> SEVERITY_CRITICAL;
            case "HIGH"     -> SEVERITY_HIGH;
            case "MEDIUM"   -> SEVERITY_MEDIUM;
            case "LOW"      -> SEVERITY_LOW;
            default         -> SEVERITY_INFO;
        };
    }

    /**
     * Create a styled scroll pane (no border, smooth scrolling).
     */
    public static JScrollPane styledScrollPane(Component view) {
        JScrollPane scrollPane = new JScrollPane(view);
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER, 1));
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.setBackground(BG_CARD);
        return scrollPane;
    }

    /**
     * Create a card panel with white background and subtle border.
     */
    public static JPanel card() {
        JPanel panel = new JPanel();
        panel.setBackground(BG_CARD);
        panel.setBorder(cardBorder());
        return panel;
    }

    /**
     * Style an existing panel as a card.
     */
    public static void applyCardStyle(JPanel panel) {
        panel.setBackground(BG_CARD);
        panel.setBorder(cardBorder());
    }

    // ═══════════════════════════════════════════════════════════════
    // CUSTOM TABBED PANE UI
    // ═══════════════════════════════════════════════════════════════

    /**
     * Professional tabbed pane UI with clean, modern appearance.
     */
    public static class VistaTabbedPaneUI extends BasicTabbedPaneUI {

        @Override
        protected void installDefaults() {
            super.installDefaults();
            tabInsets = new Insets(10, 18, 10, 18);
            selectedTabPadInsets = new Insets(0, 0, 0, 0);
            tabAreaInsets = new Insets(0, 8, 0, 8);
            contentBorderInsets = new Insets(0, 0, 0, 0);
        }

        @Override
        protected void paintTabBorder(Graphics g, int tabPlacement, int tabIndex,
                                       int x, int y, int w, int h, boolean isSelected) {
            // No border on individual tabs
        }

        @Override
        protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex,
                                           int x, int y, int w, int h, boolean isSelected) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            if (isSelected) {
                g2.setColor(BG_CARD);
                g2.fillRoundRect(x + 2, y + 2, w - 4, h - 2, 8, 8);
                // Bottom accent line
                g2.setColor(PRIMARY);
                g2.fillRect(x + 8, y + h - 3, w - 16, 3);
            } else {
                g2.setColor(BG_PANEL);
                g2.fillRoundRect(x + 2, y + 2, w - 4, h - 2, 8, 8);
            }
            g2.dispose();
        }

        @Override
        protected void paintContentBorder(Graphics g, int tabPlacement, int selectedIndex) {
            // Top line only
            g.setColor(BORDER);
            g.fillRect(0, calculateTabAreaHeight(tabPlacement, runCount, maxTabHeight), tabPane.getWidth(), 1);
        }

        @Override
        protected void paintFocusIndicator(Graphics g, int tabPlacement, Rectangle[] rects,
                                            int tabIndex, Rectangle iconRect, Rectangle textRect,
                                            boolean isSelected) {
            // No focus ring
        }

        @Override
        protected void paintText(Graphics g, int tabPlacement, Font font, FontMetrics metrics,
                                  int tabIndex, String title, Rectangle textRect, boolean isSelected) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
            g2.setFont(FONT_TAB);
            g2.setColor(isSelected ? PRIMARY_DARK : TEXT_SECONDARY);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(title, textRect.x, textRect.y + fm.getAscent());
            g2.dispose();
        }
    }
}
