package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import com.vista.security.core.*;
import com.vista.security.model.RequestCollection;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Modern Dashboard Panel - Overview and quick actions.
 * Redesigned with comprehensive statistics and modern UI.
 */
public class DashboardPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private TestingSuggestionsPanel testingSuggestionsPanel;
    
    // Stats labels - Row 1
    private final JLabel templatesCountLabel = new JLabel("0");
    private final JLabel payloadsCountLabel = new JLabel("0");
    private final JLabel collectionsCountLabel = new JLabel("0");
    
    // Stats labels - Row 2
    private final JLabel conversationCountLabel = new JLabel("0");
    private final JLabel testingStepsLabel = new JLabel("0");
    private final JLabel aiStatusLabel = new JLabel("Not Configured");
    
    // System status
    private final JLabel lastSessionLabel = new JLabel("Never");
    private final JLabel browserStatusLabel = new JLabel("Checking...");

    public DashboardPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        setLayout(new BorderLayout());
        buildUI();
        
        // Update stats periodically
        Timer updateTimer = new Timer(2000, e -> updateStats());
        updateTimer.start();
    }

    public void setTestingSuggestionsPanel(TestingSuggestionsPanel panel) {
        this.testingSuggestionsPanel = panel;
    }

    private void buildUI() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        // Use default background
        mainPanel.setBorder(new EmptyBorder(30, 40, 30, 40));

        // Header
        mainPanel.add(createHeader());
        mainPanel.add(Box.createVerticalStrut(30));

        // Stats cards
        mainPanel.add(createStatsPanel());
        mainPanel.add(Box.createVerticalStrut(30));

        // Quick actions
        mainPanel.add(createQuickActionsPanel());
        mainPanel.add(Box.createVerticalStrut(30));

        // System status
        mainPanel.add(createSystemStatusPanel());
        
        mainPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createHeader() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 120));

        JLabel titleLabel = new JLabel("VISTA Dashboard");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 32));
        titleLabel.setForeground(new Color(30, 30, 35));

        JLabel subtitleLabel = new JLabel("AI-Powered Security Testing Assistant");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        subtitleLabel.setForeground(new Color(100, 100, 110));

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);
        textPanel.add(titleLabel);
        textPanel.add(Box.createVerticalStrut(5));
        textPanel.add(subtitleLabel);

        panel.add(textPanel, BorderLayout.WEST);
        return panel;
    }

    private JPanel createStatsPanel() {
        JPanel container = new JPanel();
        container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
        container.setOpaque(false);
        container.setMaximumSize(new Dimension(Integer.MAX_VALUE, 300));
        
        // Row 1: Feature Statistics
        JPanel row1 = new JPanel(new GridLayout(1, 3, 20, 0));
        row1.setOpaque(false);
        row1.setMaximumSize(new Dimension(Integer.MAX_VALUE, 130));
        
        row1.add(createStatCard("📝", "Prompt Templates", templatesCountLabel, new Color(139, 92, 246)));
        row1.add(createStatCard("🎯", "Payloads", payloadsCountLabel, new Color(59, 130, 246)));
        row1.add(createStatCard("📁", "Collections", collectionsCountLabel, new Color(16, 185, 129)));
        
        container.add(row1);
        container.add(Box.createVerticalStrut(20));
        
        // Row 2: Session Statistics
        JPanel row2 = new JPanel(new GridLayout(1, 3, 20, 0));
        row2.setOpaque(false);
        row2.setMaximumSize(new Dimension(Integer.MAX_VALUE, 130));
        
        row2.add(createStatCard("💬", "Conversations", conversationCountLabel, new Color(245, 158, 11)));
        row2.add(createStatCard("🧪", "Testing Steps", testingStepsLabel, new Color(236, 72, 153)));
        row2.add(createStatCard("🤖", "AI Status", aiStatusLabel, new Color(16, 185, 129)));
        
        container.add(row2);
        
        return container;
    }

    private JPanel createStatCard(String icon, String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel();
        card.setLayout(new BorderLayout(15, 10));
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(230, 230, 235), 1),
            new EmptyBorder(20, 20, 20, 20)
        ));

        JLabel iconLabel = new JLabel(icon);
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 36));
        iconLabel.setHorizontalAlignment(SwingConstants.CENTER);
        iconLabel.setPreferredSize(new Dimension(60, 60));

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        titleLbl.setForeground(new Color(100, 100, 110));

        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 28));
        valueLabel.setForeground(accentColor);

        textPanel.add(titleLbl);
        textPanel.add(Box.createVerticalStrut(5));
        textPanel.add(valueLabel);

        card.add(iconLabel, BorderLayout.WEST);
        card.add(textPanel, BorderLayout.CENTER);

        return card;
    }

    private JPanel createQuickActionsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setOpaque(false);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 300));

        JLabel titleLabel = new JLabel("Quick Actions");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(new Color(30, 30, 35));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(15));

        JPanel actionsGrid = new JPanel(new GridLayout(2, 3, 15, 15));
        actionsGrid.setOpaque(false);
        actionsGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));

        actionsGrid.add(createActionButton("💡 AI Advisor", 
            "Get AI-powered testing suggestions", 
            new Color(59, 130, 246),
            e -> openTab(1)));

        actionsGrid.add(createActionButton("📝 Templates", 
            "Manage prompt templates", 
            new Color(139, 92, 246),
            e -> openTab(2)));

        actionsGrid.add(createActionButton("🎯 Payloads", 
            "Browse payload library", 
            new Color(16, 185, 129),
            e -> openTab(3)));

        actionsGrid.add(createActionButton("📁 Collections", 
            "Organize requests", 
            new Color(245, 158, 11),
            e -> openTab(4)));

        actionsGrid.add(createActionButton("⚙️ Settings", 
            "Configure AI provider", 
            new Color(236, 72, 153),
            e -> openTab(5)));

        actionsGrid.add(createActionButton("🗑️ Clear Session", 
            "Clear conversation history", 
            new Color(239, 68, 68),
            e -> clearSession()));

        panel.add(actionsGrid);
        return panel;
    }

    private JButton createActionButton(String title, String description, Color color, java.awt.event.ActionListener action) {
        JButton button = new JButton();
        button.setLayout(new BorderLayout(10, 5));
        button.setBackground(Color.WHITE);
        button.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(230, 230, 235), 1),
            new EmptyBorder(15, 15, 15, 15)
        ));
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLbl.setForeground(color);

        JLabel descLbl = new JLabel(description);
        descLbl.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        descLbl.setForeground(new Color(100, 100, 110));

        textPanel.add(titleLbl);
        textPanel.add(Box.createVerticalStrut(3));
        textPanel.add(descLbl);

        button.add(textPanel, BorderLayout.CENTER);
        button.addActionListener(action);

        // Hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(new Color(248, 250, 252));
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(Color.WHITE);
            }
        });

        return button;
    }

    private JPanel createSystemStatusPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setOpaque(false);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 250));

        JLabel titleLabel = new JLabel("System Status");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(new Color(30, 30, 35));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(15));

        JPanel statusCard = new JPanel();
        statusCard.setLayout(new BoxLayout(statusCard, BoxLayout.Y_AXIS));
        statusCard.setBackground(Color.WHITE);
        statusCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(230, 230, 235), 1),
            new EmptyBorder(20, 20, 20, 20)
        ));
        statusCard.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));

        statusCard.add(createStatusRow("AI Provider:", aiStatusLabel));
        statusCard.add(Box.createVerticalStrut(10));
        statusCard.add(createStatusRow("Browser Verification:", browserStatusLabel));
        statusCard.add(Box.createVerticalStrut(10));
        statusCard.add(createStatusRow("Last Session:", lastSessionLabel));
        statusCard.add(Box.createVerticalStrut(15));
        
        // Data persistence info
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        infoPanel.setOpaque(false);
        JLabel infoLabel = new JLabel("💾 All data is automatically saved to ~/.vista/");
        infoLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        infoLabel.setForeground(new Color(100, 100, 110));
        infoPanel.add(infoLabel);
        statusCard.add(infoPanel);

        panel.add(statusCard);
        return panel;
    }

    private JPanel createStatusRow(String label, JLabel valueLabel) {
        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JLabel lblLabel = new JLabel(label);
        lblLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        lblLabel.setForeground(new Color(100, 100, 110));

        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));

        row.add(lblLabel, BorderLayout.WEST);
        row.add(valueLabel, BorderLayout.EAST);

        return row;
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            // Update template count
            PromptTemplateManager templateMgr = PromptTemplateManager.getInstance();
            templatesCountLabel.setText(String.valueOf(templateMgr.getAllTemplates().size()));
            
            // Update payload count
            PayloadLibraryManager payloadMgr = PayloadLibraryManager.getInstance();
            if (payloadMgr.isInitialized()) {
                payloadsCountLabel.setText(String.valueOf(payloadMgr.getTotalPayloadCount()));
            }
            
            // Update collection count
            RequestCollectionManager collectionMgr = RequestCollectionManager.getInstance();
            if (collectionMgr.isInitialized()) {
                int collectionCount = collectionMgr.getTotalCollectionCount();
                int requestCount = collectionMgr.getTotalRequestCount();
                collectionsCountLabel.setText(collectionCount + " (" + requestCount + " reqs)");
            }
            
            // Update session stats
            SessionManager sessionMgr = SessionManager.getInstance();
            if (sessionMgr.isInitialized()) {
                var stats = sessionMgr.getSessionStats();
                conversationCountLabel.setText(String.valueOf(stats.getOrDefault("conversationMessages", 0)));
                testingStepsLabel.setText(String.valueOf(stats.getOrDefault("testingSteps", 0)));
                
                // Update last session time
                var metadata = sessionMgr.loadSessionMetadata();
                String lastActive = metadata.get("lastActive");
                if (lastActive != null && !lastActive.isEmpty()) {
                    try {
                        long timestamp = Long.parseLong(lastActive);
                        SimpleDateFormat sdf = new SimpleDateFormat("MMM dd, HH:mm");
                        lastSessionLabel.setText(sdf.format(new Date(timestamp)));
                        lastSessionLabel.setForeground(new Color(100, 100, 110));
                    } catch (Exception e) {
                        lastSessionLabel.setText("Unknown");
                    }
                } else {
                    lastSessionLabel.setText("Never");
                    lastSessionLabel.setForeground(new Color(100, 100, 110));
                }
            }

            // Update AI status
            AIConfigManager config = AIConfigManager.getInstance();
            if (config.isConfigured()) {
                aiStatusLabel.setText("✓ " + config.getProvider());
                aiStatusLabel.setForeground(new Color(16, 185, 129));
            } else {
                aiStatusLabel.setText("Not Configured");
                aiStatusLabel.setForeground(new Color(239, 68, 68));
            }

            // Update browser status
            try {
                HeadlessBrowserVerifier verifier = new HeadlessBrowserVerifier();
                if (verifier.isAvailable()) {
                    browserStatusLabel.setText("✓ Available");
                    browserStatusLabel.setForeground(new Color(16, 185, 129));
                } else {
                    browserStatusLabel.setText("✗ Not Available");
                    browserStatusLabel.setForeground(new Color(239, 68, 68));
                }
            } catch (Exception e) {
                browserStatusLabel.setText("✗ Error");
                browserStatusLabel.setForeground(new Color(239, 68, 68));
            }
        });
    }

    private void openTab(int tabIndex) {
        Container parent = getParent();
        while (parent != null && !(parent instanceof JTabbedPane)) {
            parent = parent.getParent();
        }
        if (parent instanceof JTabbedPane) {
            ((JTabbedPane) parent).setSelectedIndex(tabIndex);
        }
    }
    
    private void clearSession() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Clear all session data?\n\n" +
            "This will delete:\n" +
            "• Conversation history\n" +
            "• Testing steps\n" +
            "• Session metadata\n\n" +
            "Collections, templates, and payloads will NOT be affected.",
            "Clear Session",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().clearAllSessionData();
            callbacks.printOutput("[VISTA] Session data cleared");
            
            // Update stats
            updateStats();
            
            JOptionPane.showMessageDialog(this,
                "Session data cleared successfully!",
                "Success",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void openAIAdvisor() {
        openTab(1);
    }

    private void openFindings() {
        openTab(2);
    }

    private void openSettings() {
        openTab(5);
    }
}
