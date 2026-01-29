package burp;

import com.vista.security.ui.DashboardPanel;
import com.vista.security.ui.TestingSuggestionsPanel;
import com.vista.security.ui.SettingsPanel;
import com.vista.security.ui.PromptTemplatePanel;
import com.vista.security.ui.PayloadLibraryPanel;
import com.vista.security.ui.RequestCollectionPanel;

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
    private static final String VERSION = "2.8.4";
    
    private IBurpExtenderCallbacks callbacks;
    private DashboardPanel dashboardPanel;
    private TestingSuggestionsPanel testingSuggestionsPanel;
    private PromptTemplatePanel promptTemplatePanel;
    private PayloadLibraryPanel payloadLibraryPanel;
    private RequestCollectionPanel requestCollectionPanel;
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
        callbacks.printOutput("✓ Initializing panels...");
        
        SwingUtilities.invokeLater(() -> {
            callbacks.printOutput("[VISTA] Starting panel initialization");
            
            // Initialize panels with modern design
            this.settingsPanel = new SettingsPanel(callbacks);
            callbacks.printOutput("[VISTA] SettingsPanel initialized");
            
            this.dashboardPanel = new DashboardPanel(callbacks);
            callbacks.printOutput("[VISTA] DashboardPanel initialized");
            
            this.testingSuggestionsPanel = new TestingSuggestionsPanel(callbacks);
            callbacks.printOutput("[VISTA] TestingSuggestionsPanel initialized");
            
            this.promptTemplatePanel = new PromptTemplatePanel(callbacks);
            callbacks.printOutput("[VISTA] PromptTemplatePanel initialized");
            
            this.payloadLibraryPanel = new PayloadLibraryPanel(callbacks);
            callbacks.printOutput("[VISTA] PayloadLibraryPanel initialized");
            
            this.requestCollectionPanel = new RequestCollectionPanel(callbacks);
            callbacks.printOutput("[VISTA] RequestCollectionPanel initialized");
            
            // Create modern tabbed interface
            this.tabbedPane = new JTabbedPane();
            tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            // Don't set background - let Burp handle it
            
            // Add tabs with icons (using Unicode symbols)
            tabbedPane.addTab("  🏠 Dashboard  ", dashboardPanel);
            tabbedPane.addTab("  💡 AI Advisor  ", testingSuggestionsPanel);
            tabbedPane.addTab("  📝 Prompt Templates  ", promptTemplatePanel);
            tabbedPane.addTab("  🎯 Payload Library  ", payloadLibraryPanel);
            tabbedPane.addTab("  📁 Collections  ", requestCollectionPanel);
            tabbedPane.addTab("  ⚙️ Settings  ", settingsPanel);
            
            // Connect dashboard to AI Advisor
            dashboardPanel.setTestingSuggestionsPanel(testingSuggestionsPanel);
            
            callbacks.addSuiteTab(this);
            callbacks.printOutput("[VISTA] All panels initialized successfully");
            
            // NOW register context menu factory AFTER panels are initialized
            callbacks.registerContextMenuFactory(BurpExtender.this);
            callbacks.printOutput("[VISTA] Context menu factory registered");
        });
        
        callbacks.printOutput("→ Right-click any request → 'Send to VISTA AI Advisor'");
        callbacks.printOutput("→ Right-click any request → 'Add to Collection'");
        callbacks.printOutput("→ Configure your AI provider in Settings tab");
        callbacks.printOutput("→ Get testing suggestions and methodologies");
        callbacks.printOutput("→ Use Prompt Templates for specialized testing");
        callbacks.printOutput("→ Use Payload Library for quick payload access");
        callbacks.printOutput("→ Use Collections to organize similar requests");
        callbacks.printOutput("→ View Dashboard for quick stats and actions");
        callbacks.printOutput("");
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
        
        // Special option for Interactive Assistant with auto-attach
        JMenuItem sendToInteractive = new JMenuItem("🔄 Send to Interactive Assistant (Auto-Attach)");
        sendToInteractive.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        sendToInteractive.setForeground(new Color(0, 120, 215)); // Blue color
        sendToInteractive.addActionListener(e -> {
            callbacks.printOutput("[VISTA] Context menu: Send to Interactive Assistant clicked");
            
            if (testingSuggestionsPanel != null) {
                // Track this request
                String url = getUrlFromRequest(messages[0]);
                callbacks.printOutput("[VISTA] Tracking request: " + url);
                com.vista.security.core.RepeaterRequestTracker.getInstance()
                    .addRequest(messages[0], url);
                
                // Send to Interactive Assistant and auto-attach
                callbacks.printOutput("[VISTA] Setting request in panel");
                testingSuggestionsPanel.setRequest(messages[0]);
                
                callbacks.printOutput("[VISTA] Calling attachRepeaterRequest");
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
                    tabbedPane.setSelectedIndex(4); // Collections tab
                }
            }
        });
        menuItems.add(addToCollection);
        
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
