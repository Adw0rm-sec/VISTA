package burp;

import com.vista.security.ui.TestingSuggestionsPanel;
import com.vista.security.ui.SettingsPanel;
import com.vista.security.ui.PromptTemplatePanel;
import com.vista.security.ui.PayloadLibraryPanel;
import com.vista.security.ui.VistaTheme;
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
 * @version 2.10.25
 * @author VISTA Security Team
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    
    private static final String EXTENSION_NAME = "VISTA";
    private static final String VERSION = "2.10.25";
    
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
    private Timer statusTimer; // Store reference for proper cleanup

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
                    VistaTheme.styleTabbedPane(tabbedPane);
                    
                    // Add tabs with clean labels (no emoji in tabs - professional look)
                    callbacks.printOutput("[VISTA] Adding tabs...");
                    tabbedPane.addTab("  AI Advisor  ", testingSuggestionsPanel);
                    tabbedPane.addTab("  Traffic Monitor  ", trafficMonitorPanel);
                    tabbedPane.addTab("  Prompt Templates  ", promptTemplatePanel);
                    tabbedPane.addTab("  Payload Library  ", payloadLibraryPanel);
                    tabbedPane.addTab("  Settings  ", settingsPanel);
                    callbacks.printOutput("[VISTA] ✓ All tabs added to tabbed pane");
                    
                    // Build root panel: status bar + tabs
                    this.rootPanel = new JPanel(new BorderLayout());
                    rootPanel.add(createStatusBar(), BorderLayout.NORTH);
                    rootPanel.add(tabbedPane, BorderLayout.CENTER);
                    
                    // Start AI status polling (every 5s is sufficient - reduces EDT load)
                    statusTimer = new Timer(5000, ev -> refreshAIStatus());
                    statusTimer.setRepeats(true);
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
                    
                    // Initialize data persistence - load all saved data
                    callbacks.printOutput("[VISTA] Initializing data persistence...");
                    com.vista.security.core.VistaPersistenceManager.getInstance().initialize();
                    callbacks.printOutput("[VISTA] ✓ Data persistence initialized - previous data restored");
                    
                    // Restore persisted data into the traffic monitor panel
                    if (trafficMonitorPanel instanceof com.vista.security.ui.TrafficMonitorPanel) {
                        ((com.vista.security.ui.TrafficMonitorPanel) trafficMonitorPanel).restorePersistedData();
                    }
                    
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
        bar.setBackground(VistaTheme.BG_DARK);
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, VistaTheme.BORDER_DARK),
            new EmptyBorder(10, 20, 10, 20)
        ));
        bar.setPreferredSize(new Dimension(0, 48));

        // Left: VISTA branding
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftPanel.setOpaque(false);

        JLabel logo = new JLabel("VISTA");
        logo.setFont(new Font("Segoe UI", Font.BOLD, 17));
        logo.setForeground(VistaTheme.PRIMARY_LIGHT);
        leftPanel.add(logo);

        JLabel version = new JLabel("  v" + VERSION);
        version.setFont(VistaTheme.FONT_SMALL);
        version.setForeground(VistaTheme.TEXT_MUTED);
        leftPanel.add(version);

        JLabel separator = new JLabel("   │   ");
        separator.setFont(VistaTheme.FONT_SMALL);
        separator.setForeground(VistaTheme.BORDER_DARK);
        leftPanel.add(separator);

        JLabel tagline = new JLabel("AI-Powered Security Testing");
        tagline.setFont(VistaTheme.FONT_SMALL);
        tagline.setForeground(VistaTheme.TEXT_MUTED);
        leftPanel.add(tagline);

        bar.add(leftPanel, BorderLayout.WEST);

        // Right: AI status indicator
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        rightPanel.setOpaque(false);

        aiStatusDot = new JLabel("●");
        aiStatusDot.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        aiStatusDot.setForeground(VistaTheme.STATUS_ERROR);

        aiStatusText = new JLabel("AI: Not Configured");
        aiStatusText.setFont(VistaTheme.FONT_SMALL_BOLD);
        aiStatusText.setForeground(VistaTheme.TEXT_MUTED);

        aiModelText = new JLabel("");
        aiModelText.setFont(VistaTheme.FONT_SMALL);
        aiModelText.setForeground(VistaTheme.TEXT_MUTED);

        // Clickable → jump to Settings
        JLabel settingsLink = new JLabel("  ⚙");
        settingsLink.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        settingsLink.setForeground(VistaTheme.TEXT_MUTED);
        settingsLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
        settingsLink.setToolTipText("Open Settings");
        settingsLink.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (tabbedPane != null) {
                    tabbedPane.setSelectedIndex(4);
                }
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                settingsLink.setForeground(VistaTheme.PRIMARY_LIGHT);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                settingsLink.setForeground(VistaTheme.TEXT_MUTED);
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
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshAIStatus);
            return;
        }
        try {
            if (aiStatusDot == null || aiStatusText == null || aiModelText == null) return;
            AIConfigManager config = AIConfigManager.getInstance();
            if (config.isConfigured()) {
                aiStatusDot.setForeground(VistaTheme.STATUS_READY);
                aiStatusText.setText("AI: Ready");
                aiStatusText.setForeground(VistaTheme.STATUS_READY);
                String model = config.getModel();
                String provider = config.getProvider();
                aiModelText.setText("(" + provider + (model != null && !model.isEmpty() ? " / " + model : "") + ")");
            } else {
                aiStatusDot.setForeground(VistaTheme.STATUS_ERROR);
                aiStatusText.setText("AI: Not Configured");
                aiStatusText.setForeground(VistaTheme.STATUS_WARNING);
                aiModelText.setText("— click ⚙ to set up");
            }
        } catch (Exception ignored) {
            // Safely ignore during init
        }
    }

    /**
     * Called by Burp when the extension is unloaded.
     * Cleans up all timers, thread pools, and resources to prevent hangs.
     */
    public void extensionUnloaded() {
        try {
            // Save all data before unloading
            callbacks.printOutput("[VISTA] Saving all data before unload...");
            try {
                com.vista.security.core.VistaPersistenceManager.getInstance().shutdown();
                callbacks.printOutput("[VISTA] ✓ All data saved successfully");
            } catch (Exception e) {
                callbacks.printError("[VISTA] Error saving data: " + e.getMessage());
            }
            
            // Stop the AI status polling timer
            if (statusTimer != null) {
                statusTimer.stop();
                statusTimer = null;
            }
            
            // Cleanup Traffic Monitor resources
            if (trafficMonitorPanel instanceof com.vista.security.ui.TrafficMonitorPanel) {
                ((com.vista.security.ui.TrafficMonitorPanel) trafficMonitorPanel).cleanup();
            }
            
            // Shutdown the analysis queue manager
            try {
                com.vista.security.core.AnalysisQueueManager.getInstance().shutdown();
            } catch (Exception ignored) {}
            
            callbacks.printOutput("[VISTA] Extension unloaded - all resources cleaned up");
        } catch (Exception e) {
            callbacks.printError("[VISTA] Error during cleanup: " + e.getMessage());
        }
    }
}
