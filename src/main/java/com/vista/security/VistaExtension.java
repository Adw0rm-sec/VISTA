package com.vista.security;

import burp.*;
import com.vista.security.ui.MainPanel;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * VISTA - Vulnerability Insight & Strategic Test Assistant
 * Main extension entry point for Burp Suite integration.
 * 
 * @author VISTA Team
 * @version 1.0.0
 */
public class VistaExtension implements IBurpExtender, ITab, IContextMenuFactory {
    
    private static final String EXTENSION_NAME = "VISTA";
    private static final String FULL_NAME = "VISTA (Vulnerability Insight & Strategic Test Assistant)";
    
    private IBurpExtenderCallbacks callbacks;
    private MainPanel mainPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(FULL_NAME);
        
        // Initialize UI on Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            this.mainPanel = new MainPanel(callbacks);
            callbacks.addSuiteTab(this);
        });
        
        callbacks.registerContextMenuFactory(this);
        
        // Log startup
        callbacks.printOutput("═══════════════════════════════════════════════════════");
        callbacks.printOutput("  " + FULL_NAME);
        callbacks.printOutput("  Version 1.0.0 - MVP Release");
        callbacks.printOutput("═══════════════════════════════════════════════════════");
        callbacks.printOutput("  → Right-click any request → Send to VISTA");
        callbacks.printOutput("  → Features: AI Analysis, Parameter Extraction,");
        callbacks.printOutput("              Payload Library, Report Export");
        callbacks.printOutput("═══════════════════════════════════════════════════════");
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public java.awt.Component getUiComponent() {
        return mainPanel != null ? mainPanel.getComponent() : new JPanel();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        JMenuItem sendToVista = new JMenuItem("Send to " + EXTENSION_NAME);
        sendToVista.addActionListener(e -> {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages != null && selectedMessages.length > 0 && mainPanel != null) {
                mainPanel.addMessages(selectedMessages);
                callbacks.printOutput("[VISTA] Added " + selectedMessages.length + " request(s) to analysis queue.");
            }
        });
        menuItems.add(sendToVista);
        
        return menuItems;
    }
}
