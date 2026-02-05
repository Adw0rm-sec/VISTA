package burp;

import com.vista.security.ui.DashboardPanel;
import com.vista.security.ui.TestingSuggestionsPanel;
import com.vista.security.ui.SettingsPanel;
import com.vista.security.ui.PromptTemplatePanel;
import com.vista.security.ui.PayloadLibraryPanel;
import com.vista.security.ui.RequestCollectionPanel;
// Using TrafficMonitorPanelSimple instead of TrafficMonitorPanel

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * VISTA - AI-Powered Security Testing Assistant
 * Professional-grade Burp Suite extension for intelligent vulnerability exploitation.
 * 
 * @version 2.8.4
 * @author VISTA Security Team
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    
    private static final String EXTENSION_NAME = "VISTA";
    private static final String VERSION = "2.9.0";
    
    private IBurpExtenderCallbacks callbacks;
    private DashboardPanel dashboardPanel;
    private TestingSuggestionsPanel testingSuggestionsPanel;
    private PromptTemplatePanel promptTemplatePanel;
    private PayloadLibraryPanel payloadLibraryPanel;
    private RequestCollectionPanel requestCollectionPanel;
    private JPanel trafficMonitorPanel; // Can be either TrafficMonitorPanel or TrafficMonitorPanelSimple
    private SettingsPanel settingsPanel;
    private JTabbedPane tabbedPane;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(EXTENSION_NAME);
        
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
        callbacks.printOutput("║   AI-Powered Security Testing Assistant v" + VERSION + "          ║");
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
                    
                    callbacks.printOutput("[VISTA] Initializing DashboardPanel...");
                    this.dashboardPanel = new DashboardPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ DashboardPanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing TestingSuggestionsPanel...");
                    this.testingSuggestionsPanel = new TestingSuggestionsPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ TestingSuggestionsPanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing PromptTemplatePanel...");
                    this.promptTemplatePanel = new PromptTemplatePanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ PromptTemplatePanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing PayloadLibraryPanel...");
                    this.payloadLibraryPanel = new PayloadLibraryPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ PayloadLibraryPanel initialized");
                    
                    callbacks.printOutput("[VISTA] Initializing RequestCollectionPanel...");
                    this.requestCollectionPanel = new RequestCollectionPanel(callbacks);
                    callbacks.printOutput("[VISTA] ✓ RequestCollectionPanel initialized");
                    
                    // Initialize Traffic Monitor (Simplified version - just traffic capture and scope filtering)
                    callbacks.printOutput("[VISTA] Initializing TrafficMonitorPanel (Simple)...");
                    this.trafficMonitorPanel = new com.vista.security.ui.TrafficMonitorPanelSimple(callbacks);
                    callbacks.printOutput("[VISTA] ✓ TrafficMonitorPanel (Simple) initialized");
                    
                    // Create modern tabbed interface
                    callbacks.printOutput("[VISTA] Creating tabbed pane...");
                    this.tabbedPane = new JTabbedPane();
                    tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 13));
                    
                    // Add tabs with icons (using Unicode symbols)
                    callbacks.printOutput("[VISTA] Adding tabs...");
                    tabbedPane.addTab("  🏠 Dashboard  ", dashboardPanel);
                    tabbedPane.addTab("  💡 AI Advisor  ", testingSuggestionsPanel);
                    tabbedPane.addTab("  🌐 Traffic Monitor  ", trafficMonitorPanel);
                    tabbedPane.addTab("  📝 Prompt Templates  ", promptTemplatePanel);
                    tabbedPane.addTab("  🎯 Payload Library  ", payloadLibraryPanel);
                    tabbedPane.addTab("  📁 Collections  ", requestCollectionPanel);
                    tabbedPane.addTab("  ⚙️ Settings  ", settingsPanel);
                    callbacks.printOutput("[VISTA] ✓ All tabs added to tabbed pane");
                    
                    // Connect dashboard to AI Advisor
                    dashboardPanel.setTestingSuggestionsPanel(testingSuggestionsPanel);
                    
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
                    callbacks.printOutput("→ Right-click any request → 'Add to Collection'");
                    callbacks.printOutput("→ Configure your AI provider in Settings tab");
                    callbacks.printOutput("→ Get testing suggestions and methodologies");
                    callbacks.printOutput("→ Use Prompt Templates for specialized testing");
                    callbacks.printOutput("→ Use Payload Library for quick payload access");
                    callbacks.printOutput("→ Use Collections to organize similar requests");
                    callbacks.printOutput("→ View Dashboard for quick stats and actions");
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
        return tabbedPane != null ? tabbedPane : new JPanel();
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
                    tabbedPane.setSelectedIndex(1); // AI Advisor tab
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
                    tabbedPane.setSelectedIndex(1); // AI Advisor tab
                }
                
                callbacks.printOutput("[VISTA] Context menu action completed");
            } else {
                callbacks.printError("[VISTA] testingSuggestionsPanel is null!");
            }
        });
        menuItems.add(sendToInteractive);
        
        // Add separator
        menuItems.add(null);
        
        // Add to Collection
        JMenuItem addToCollection = new JMenuItem("📁 Add to Collection");
        addToCollection.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        addToCollection.addActionListener(e -> {
            if (requestCollectionPanel != null) {
                requestCollectionPanel.addRequestToCollection(messages[0]);
                if (tabbedPane != null) {
                    tabbedPane.setSelectedIndex(5); // Collections tab (index 5 now)
                }
            }
        });
        menuItems.add(addToCollection);
        
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
}
