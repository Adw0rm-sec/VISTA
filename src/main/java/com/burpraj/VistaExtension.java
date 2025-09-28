package com.burpraj;

import burp.*;
import com.burpraj.ui.VistaPanel;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class VistaExtension implements IBurpExtender, ITab, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private VistaPanel panel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("VISTA (Vulnerability Insight & Strategic Test Assistant)");
        this.panel = new VistaPanel(callbacks);
        callbacks.addSuiteTab(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.printOutput("VISTA loaded. Right-click a message -> Send to VISTA.");
    }

    @Override
    public String getTabCaption() { return "VISTA"; }

    @Override
    public java.awt.Component getUiComponent() { return panel.getRoot(); }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenuItem send = new JMenuItem("Send to VISTA");
        send.addActionListener(e -> {
            IHttpRequestResponse[] msgs = invocation.getSelectedMessages();
            if (msgs != null && msgs.length > 0) {
                panel.addMessages(msgs);
                callbacks.printOutput("Sent " + msgs.length + " message(s) to VISTA.");
            }
        });
        items.add(send);
        return items;
    }
}
