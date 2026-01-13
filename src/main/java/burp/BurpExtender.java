package burp;

import com.vista.security.ui.MainPanel;
import com.vista.security.ui.AutoExploitPanel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Main entry point for the VISTA Burp Suite extension.
 * Burp Suite looks for burp.BurpExtender by default.
 * 
 * @author VISTA Team
 * @version 1.0.0
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    
    private static final String EXTENSION_NAME = "VISTA";
    private static final String FULL_NAME = "VISTA (Vulnerability Insight & Strategic Test Assistant)";
    
    private IBurpExtenderCallbacks callbacks;
    private MainPanel mainPanel;
    private AutoExploitPanel autoExploitPanel;
    private JTabbedPane tabbedPane;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(FULL_NAME);
        
        // Initialize UI on Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            this.mainPanel = new MainPanel(callbacks);
            this.autoExploitPanel = new AutoExploitPanel(callbacks);
            
            // Create tabbed pane with both panels
            this.tabbedPane = new JTabbedPane();
            tabbedPane.addTab("📋 Analysis", mainPanel.getComponent());
            tabbedPane.addTab("🚀 VISTA AI", autoExploitPanel);
            
            callbacks.addSuiteTab(this);
        });
        
        callbacks.registerContextMenuFactory(this);
        
        // Log startup
        callbacks.printOutput("═══════════════════════════════════════════════════════");
        callbacks.printOutput("  " + FULL_NAME);
        callbacks.printOutput("  Version 1.0.0 - MVP Release");
        callbacks.printOutput("═══════════════════════════════════════════════════════");
        callbacks.printOutput("  → Right-click any request → Send to VISTA");
        callbacks.printOutput("  → Right-click any request → Send to VISTA AI (Auto-Exploit)");
        callbacks.printOutput("  → Features: AI Analysis, Auto-Exploit, Parameter Extraction,");
        callbacks.printOutput("              Payload Library, Report Export");
        callbacks.printOutput("═══════════════════════════════════════════════════════");
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public java.awt.Component getUiComponent() {
        return tabbedPane != null ? tabbedPane : new JPanel();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        // Send to VISTA (Analysis)
        JMenuItem sendToVista = new JMenuItem("Send to " + EXTENSION_NAME);
        sendToVista.addActionListener(e -> {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages != null && selectedMessages.length > 0 && mainPanel != null) {
                mainPanel.addMessages(selectedMessages);
                // Switch to Analysis tab
                if (tabbedPane != null) tabbedPane.setSelectedIndex(0);
                callbacks.printOutput("[VISTA] Added " + selectedMessages.length + " request(s) to analysis queue.");
            }
        });
        menuItems.add(sendToVista);
        
        // Send to VISTA AI (Auto-Exploit)
        JMenuItem sendToVistaAI = new JMenuItem("🚀 Send to VISTA AI (Auto-Exploit)");
        sendToVistaAI.setFont(sendToVistaAI.getFont().deriveFont(Font.BOLD));
        sendToVistaAI.addActionListener(e -> {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages != null && selectedMessages.length > 0 && autoExploitPanel != null) {
                autoExploitPanel.setRequest(selectedMessages[0]);
                // Switch to VISTA AI tab
                if (tabbedPane != null) tabbedPane.setSelectedIndex(1);
                callbacks.printOutput("[VISTA AI] Request loaded for auto-exploit.");
            }
        });
        menuItems.add(sendToVistaAI);
        
        return menuItems;
    }
}
