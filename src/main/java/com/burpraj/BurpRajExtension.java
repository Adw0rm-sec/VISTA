package com.burpraj;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import com.burpraj.ui.BurpRajPanel;

import javax.swing.*;
import java.util.List;
import java.util.ArrayList;

public class BurpRajExtension implements IBurpExtender, ITab, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpRajPanel panel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.panel = new BurpRajPanel(callbacks);

        callbacks.setExtensionName("VISTA (Vulnerability Insight & Strategic Test Assistant)");
        callbacks.addSuiteTab(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.printOutput("VISTA loaded. Right-click a message in Proxy/Repeater -> Send to VISTA.");
    }

    @Override
    public String getTabCaption() {
        return "VISTA";
    }

    @Override
    public java.awt.Component getUiComponent() {
        return panel.getRoot();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenuItem send = new JMenuItem("Send to VISTA");
        send.addActionListener(e -> {
            IHttpRequestResponse[] msgs = invocation.getSelectedMessages();
            if (msgs != null && msgs.length > 0) {
                panel.addMessages(msgs);
                callbacks.printOutput("Sent " + msgs.length + " message(s) to VISTA tab.");
            }
        });
        items.add(send);
        return items;
    }
}
