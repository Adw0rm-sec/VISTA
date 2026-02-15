package burp;

import com.vista.security.ui.TestingSuggestionsPanel;
import com.vista.security.ui.SettingsPanel;
import com.vista.security.ui.PromptTemplatePanel;
import com.vista.security.ui.PayloadLibraryPanel;
import com.vista.security.core.AIConfigManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * VISTA - AI-Powered Security Testing Assistant
 * Professional-grade Burp Suite extension for intelligent vulnerability exploitation.
 * 
 * @version 2.10.23
 * @author VISTA Security Team
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    
    private static final String EXTENSION_NAME = "VISTA";
    private static final String VERSION = "2.10.23";
    
    private IBurpExtenderCallbacks callbacks;
    private TestingSuggestionsPanel testingSuggestionsPanel;
    private PromptTemplatePanel promptTemplatePanel;
    private PayloadLibraryPanel payloadLibraryPanel;
    private JPanel trafficMonitorPanel;
    private SettingsPanel settingsPanel;
    private JTabbedPane tabbedPane;
    private JPanel rootPanel;       // wrapper: statusBar + tabbedPane
    private JLabel aiStatusDot;
    private JLabel aiStatusText;
    private JLabel aiModelText;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(EXTENSION_NAME);
        
        // Initialize AI Request Logger with callbacks for proper output
        com.vista.security.core.AIRequestLogger.setCallbacks(callbacks);
        
        // Professional startup banner
        callbacks.printOutput("╔════════════════════════════════════════════════════════════╗");
        callbacks.printOutput("║                                                            ║");
        callbacks.printOutput("║   ██╗   ██╗██╗███████╗████████╗ █████╗                    ║");
        callbacks.printOutput("║   ██║   ██║██║██╔════╝╚══██╔══╝██╔══██╗                   ║");
        callbacks.printOutput("║   ██║   ██║██║███████╗   ██║   ███████║                   ║");
        callbacks.printOutput("║   ╚██╗ ██╔╝██║╚════██║   ██║   ██╔══██║                   ║");
        callbacks.printOutput("║    ╚████╔╝ ██║███████║   ██║   ██║  ██║                   ║");
        callbacks.printOutput("║     ╚═══╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝                   ║");
        callbacks.printOutput("║                                                            ║");
        callbacks.printOutput("║   AI-Powered Security Testing Assistant v" + VERSION + "       ║");
        callbacks.printOutput("║   Professional Vulnerability Exploitation Tool            ║");
        callbacks.printOutput("║                                                            ║");
        callbacks.printOutput("╚════════════════════════════════════════════════════════════╝");
        callbacks.printOutput("");
        callbacks.printOutput("✓ Initializing VISTA extension...");
        callbacks.printOutput("✓ Extension name set to: " + EXTENSION_NAME);
        
        try {
            SwingUtilities.invokeLater(() -> {
                try {
                    callbacks.printOutput("[VISTA] Starting panel initialization in EDT");
                    
                    // Initialize panels with modern design
                    callbacks.printOutput("[VISTA] Initializing SettingsPanel...");
                    this.settingsPanel = new SettingsPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ SettingsPanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing TestingSuggestionsPanel...");
                    this.testingSuggestionsPanel = new TestingSuggestionsPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ TestingSuggestionsPanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing PromptTemplatePanel...");
                    this.promptTemplatePanel = new PromptTemplatePanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ PromptTemplatePanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing PayloadLibraryPanel...");
                    this.payloadLibraryPanel = new PayloadLibraryPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ PayloadLibraryPanel initialized");
                    
                    // Initialize Traffic Monitor with NEW hierarchical UI
                    callbacks.printOutput("[VISTA] Initializing TrafficMonitorPanel (Hierarchical UI)...");
                    this.trafficMonitorPanel = new com.vista.security.ui.TrafficMonitorPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ TrafficMonitorPanel (Hierarchical UI) initialized");
                    
                    // Create modern tabbed interface
                    callbacks.printOutput("[VISTA] Creating tabbed pane...");
                    this.tabbedPane = new JTabbedPane();
                    tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 13));
                    
                    // Add tabs with icons
                    callbacks.printOutput("[VISTA] Adding tabs...");
                    tabbedPane.addTab("  💡 AI Advisor  ", testingSuggestionsPanel);
                    tabbedPane.addTab("  🌐 Traffic Monitor  ", trafficMonitorPanel);
                    tabbedPane.addTab("  📝 Prompt Templates  ", promptTemplatePanel);
                    tabbedPane.addTab("  🎯 Payload Library  ", payloadLibraryPanel);
                    tabbedPane.addTab("  ⚙️ Settings  ", settingsPanel);
                    callbacks.printOutput("[VISTA] ✓ All tabs added to tabbed pane");
                    
                    // Build root panel: status bar + tabs
                    this.rootPanel = new JPanel(new BorderLayout());
                    rootPanel.add(createStatusBar(), BorderLayout.NORTH);
                    rootPanel.add(tabbedPane, BorderLayout.CENTER);
                    
                    // Start AI status polling
                    Timer statusTimer = new Timer(2000, ev -> refreshAIStatus());
                    statusTimer.start();
                    refreshAIStatus(); // initial
                    
                    // Add the tab to Burp Suite
                    callbacks.printOutput("[VISTA] Registering VISTA tab with Burp Suite...");
                    callbacks.addSuiteTab(BurpExtender.this);
                    callbacks.printOutput("[VISTA] ✓ VISTA tab registered successfully!");
                    callbacks.printOutput("[VISTA] ✓ Look for 'VISTA' tab in the top bar next to other extensions");
                    
                    // NOW register context menu factory AFTER panels are initialized
                    callbacks.printOutput("[VISTA] Registering context menu factory...");
                    callbacks.registerContextMenuFactory(BurpExtender.this);
                    callbacks.printOutput("[VISTA] ✓ Context menu factory registered");
                    
                    callbacks.printOutput("");
                    callbacks.printOutput("═══════════════════════════════════════════════════════════");
                    callbacks.printOutput("  VISTA SUCCESSFULLY LOADED!");
                    callbacks.printOutput("═══════════════════════════════════════════════════════════");
                    callbacks.printOutput("");
                    callbacks.printOutput("→ Look for 'VISTA' tab in the top bar");
                    callbacks.printOutput("→ Right-click any request → 'Send to VISTA AI Advisor'");
                    callbacks.printOutput("→ Configure your AI provider in Settings tab");
                    callbacks.printOutput("→ Get testing suggestions and methodologies");
                    callbacks.printOutput("→ Use Prompt Templates for specialized testing");
                    callbacks.printOutput("→ Use Payload Library for quick payload access");
                    callbacks.printOutput("");
                    
                } catch (Exception e) {
                    callbacks.printError("[VISTA] ERROR during panel initialization:");
                    callbacks.printError("[VISTA] " + e.getClass().getName() + ": " + e.getMessage());
                    e.printStackTrace(new java.io.PrintWriter(new java.io.StringWriter()) {
                        @Override
                        public void println(String x) {
                            callbacks.printError("[VISTA] " + x);
                        }
                    });
                }
            });
        } catch (Exception e) {
            callbacks.printError("[VISTA] FATAL ERROR during extension initialization:");
            callbacks.printError("[VISTA] " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace(new java.io.PrintWriter(new java.io.StringWriter()) {
                @Override
                public void println(String x) {
                    callbacks.printError("[VISTA] " + x);
                }
            });
        }
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return menuItems;
        }
        
        // Main action - Send to AI Advisor
        JMenuItem sendToAI = new JMenuItem("💡 Send to VISTA AI Advisor");
        sendToAI.setFont(new Font("Segoe UI", Font.BOLD, 12));
        sendToAI.addActionListener(e -> {
            if (testingSuggestionsPanel != null) {
                testingSuggestionsPanel.setRequest(messages[0]);
                if (tabbedPane != null) {
                    tabbedPane.setSelectedIndex(0); // AI Advisor tab
                }
            }
        });
        menuItems.add(sendToAI);
        
        // Special option for Interactive Assistant - ONLY attach, don't replace display
        JMenuItem sendToInteractive = new JMenuItem("📎 Attach to Interactive Assistant");
        sendToInteractive.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        sendToInteractive.setForeground(new Color(0, 120, 215)); // Blue color
        sendToInteractive.addActionListener(e -> {
            callbacks.printOutput("[VISTA] Context menu: Attach to Interactive Assistant clicked");
            
            if (testingSuggestionsPanel != null) {
                // Track this request
                String url = getUrlFromRequest(messages[0]);
                callbacks.printOutput("[VISTA] Tracking request: " + url);
                com.vista.security.core.RepeaterRequestTracker.getInstance()
                    .addRequest(messages[0], url);
                
                // ONLY attach - do NOT call setRequest() to preserve original display
                callbacks.printOutput("[VISTA] Calling attachRepeaterRequest (without setRequest)");
                testingSuggestionsPanel.attachRepeaterRequest(messages[0]);
                
                if (tabbedPane != null) {
                    callbacks.printOutput("[VISTA] Switching to AI Advisor tab");
                    tabbedPane.setSelectedIndex(0); // AI Advisor tab
                }
                
                callbacks.printOutput("[VISTA] Context menu action completed");
            } else {
                callbacks.printError("[VISTA] testingSuggestionsPanel is null!");
            }
        });
        menuItems.add(sendToInteractive);
        
        // Note: Traffic Monitor (Simple) automatically captures all traffic
        // No need for manual "Send to Traffic Monitor" option
        
        return menuItems;
    }
    
    /**
     * Extracts URL from request for display purposes
     */
    private String getUrlFromRequest(IHttpRequestResponse requestResponse) {
        try {
            byte[] request = requestResponse.getRequest();
            if (request == null) return "Unknown";
            
            String requestStr = new String(request, 0, Math.min(500, request.length));
            String[] lines = requestStr.split("\r?\n");
            if (lines.length > 0) {
                String[] parts = lines[0].split(" ");
                if (parts.length >= 2) {
                    String path = parts[1];
                    
                    // Try to get protocol from IHttpService
                    IHttpService httpService = requestResponse.getHttpService();
                    if (httpService != null) {
                        String protocol = httpService.getProtocol();
                        String host = httpService.getHost();
                        if (host != null && !host.isEmpty()) {
                            return protocol + "://" + host + path;
                        }
                    }
                    
                    // Fallback: try getHost() method
                    String host = requestResponse.getHost();
                    if (host != null && !host.isEmpty()) {
                        // Guess protocol from port or default to http
                        int port = requestResponse.getPort();
                        String protocol = (port == 443) ? "https" : "http";
                        return protocol + "://" + host + path;
                    }
                    
                    return path;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return "Unknown";
    }

    /**
     * Creates a sleek status bar showing VISTA branding + live AI configuration status.
     * Sits above the tabbed pane for always-visible status.
     */
    private JPanel createStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(new Color(15, 23, 42));  // slate-900
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(51, 65, 85)),  // slate-700 bottom border
            new EmptyBorder(8, 16, 8, 16)
        ));
        bar.setPreferredSize(new Dimension(0, 42));

        // Left: VISTA branding
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftPanel.setOpaque(false);

        JLabel logo = new JLabel("VISTA");
        logo.setFont(new Font("Segoe UI", Font.BOLD, 15));
        logo.setForeground(new Color(96, 165, 250));  // blue-400
        leftPanel.add(logo);

        JLabel version = new JLabel("  v" + VERSION);
        version.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        version.setForeground(new Color(148, 163, 184)); // slate-400
        leftPanel.add(version);

        JLabel separator = new JLabel("   │   ");
        separator.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        separator.setForeground(new Color(51, 65, 85));   // slate-700
        leftPanel.add(separator);

        JLabel tagline = new JLabel("AI-Powered Security Testing");
        tagline.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        tagline.setForeground(new Color(148, 163, 184)); // slate-400
        leftPanel.add(tagline);

        bar.add(leftPanel, BorderLayout.WEST);

        // Right: AI status indicator
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightPanel.setOpaque(false);

        aiStatusDot = new JLabel("●");
        aiStatusDot.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        aiStatusDot.setForeground(new Color(239, 68, 68)); // red initially

        aiStatusText = new JLabel("AI: Not Configured");
        aiStatusText.setFont(new Font("Segoe UI", Font.BOLD, 11));
        aiStatusText.setForeground(new Color(148, 163, 184));

        aiModelText = new JLabel("");
        aiModelText.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        aiModelText.setForeground(new Color(148, 163, 184));

        // Clickable → jump to Settings
        JLabel settingsLink = new JLabel("  ⚙");
        settingsLink.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        settingsLink.setForeground(new Color(148, 163, 184));
        settingsLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
        settingsLink.setToolTipText("Open Settings");
        settingsLink.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (tabbedPane != null) {
                    tabbedPane.setSelectedIndex(4); // Settings tab
                }
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                settingsLink.setForeground(new Color(96, 165, 250)); // blue-400
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                settingsLink.setForeground(new Color(148, 163, 184));
            }
        });

        rightPanel.add(aiStatusDot);
        rightPanel.add(aiStatusText);
        rightPanel.add(aiModelText);
        rightPanel.add(settingsLink);

        bar.add(rightPanel, BorderLayout.EAST);

        return bar;
    }

    /**
     * Refreshes the AI status indicator in the status bar.
     */
    private void refreshAIStatus() {
        SwingUtilities.invokeLater(() -> {
            try {
                AIConfigManager config = AIConfigManager.getInstance();
                if (config.isConfigured()) {
                    aiStatusDot.setForeground(new Color(34, 197, 94));     // green-500
                    aiStatusText.setText("AI: Ready");
                    aiStatusText.setForeground(new Color(34, 197, 94));
                    String model = config.getModel();
                    String provider = config.getProvider();
                    aiModelText.setText("(" + provider + (model != null && !model.isEmpty() ? " / " + model : "") + ")");
                } else {
                    aiStatusDot.setForeground(new Color(239, 68, 68));     // red-500
                    aiStatusText.setText("AI: Not Configured");
                    aiStatusText.setForeground(new Color(250, 204, 21));   // yellow-400
                    aiModelText.setText("— click ⚙ to set up");
                }
            } catch (Exception ignored) {
                // Safely ignore during init
            }
        });
    }
}
