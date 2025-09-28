package com.burpraj.ui;

import burp.*;
import com.burpraj.ai.AzureClient;
import com.burpraj.ai.OpenAIClient;
import com.burpraj.util.HttpFormat;
import com.burpraj.util.VulnTemplates;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class VistaPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JPanel root;

    private final DefaultListModel<String> reqListModel = new DefaultListModel<>();
    private final JList<String> requestList = new JList<>(reqListModel);
    private final java.util.List<IHttpRequestResponse> messages = new ArrayList<>();
    private final Map<IHttpRequestResponse,StringBuilder> chats = new HashMap<>();
    private final StringBuilder globalChat = new StringBuilder();

    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();

    // Styled chat
    private final JTextPane chatPane = new JTextPane();
    private final JTextField questionField = new JTextField();
    private final JButton askButton = new JButton("Ask VISTA");

    private final JComboBox<String> providerCombo = new JComboBox<>(new String[]{"Azure AI", "OpenAI"});
    private final JTextField endpointField = new JTextField();
    private final JTextField deploymentField = new JTextField();
    private final JTextField apiVersionField = new JTextField("2024-12-01-preview");
    private final JPasswordField apiKeyField = new JPasswordField();
    private final JTextField openAiModelField = new JTextField();
    private final JTextField openAiBaseUrlField = new JTextField("https://api.openai.com/v1");
    private final JCheckBox stripHeaders = new JCheckBox("Strip sensitive headers (Authorization, Cookie, Set-Cookie)", true);
    private final JSpinner maxCharsSpinner = new JSpinner(new SpinnerNumberModel(32000, 1000, 200000, 1000));
    private final JButton testButton = new JButton("Test connection");

    private final JTextField templatesDirField = new JTextField();
    private final JButton loadTemplatesButton = new JButton("Load templates");
    private final DefaultListModel<String> templatesModel = new DefaultListModel<>();
    private final JList<String> templatesList = new JList<>(templatesModel);
    private final Map<String,String> templates = new LinkedHashMap<>();
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progress = new JProgressBar();
    private final Timer thinkingDots = new Timer(400, e -> cycleThinking());

    private final JComboBox<String> presetCombo = new JComboBox<>(new String[]{
            "None (auto)", "CSRF", "IDOR", "SQL Injection", "SSRF", "XSS"
    });

    private IHttpRequestResponse current;

    public VistaPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.root = buildUi();
        try { loadState(); } catch (Exception ignored) {}
    }

    public JComponent getRoot() { return root; }

    private JPanel buildUi() {
        JPanel panel = new JPanel(new BorderLayout(8,8));
        panel.setBorder(new EmptyBorder(8,8,8,8));
        requestArea.setEditable(false); responseArea.setEditable(false);
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        requestArea.setFont(mono); responseArea.setFont(mono);
        chatPane.setEditable(false);
        chatPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestList.addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) loadSelectedMessage(); });
        JScrollPane reqScroll = new JScrollPane(requestList);
        reqScroll.setPreferredSize(new Dimension(260,200));

        JButton removeBtn = new JButton("Remove");
        removeBtn.setToolTipText("Remove selected request from VISTA");
        JButton toRepeaterBtn = new JButton("Send to Repeater");
        removeBtn.addActionListener(e -> removeSelected());
        toRepeaterBtn.addActionListener(e -> sendSelectedToRepeater());
        JPanel listButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        listButtons.add(removeBtn); listButtons.add(toRepeaterBtn);
        JPanel left = new JPanel(new BorderLayout(4,4)); left.add(reqScroll, BorderLayout.CENTER); left.add(listButtons, BorderLayout.SOUTH);

        JTabbedPane rrTabs = new JTabbedPane();
        rrTabs.addTab("Request", new JScrollPane(requestArea));
        rrTabs.addTab("Response", new JScrollPane(responseArea));
        JSplitPane leftRight = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, rrTabs); leftRight.setResizeWeight(0.25);

        askButton.addActionListener(this::onAsk);
        JPanel inputPanel = new JPanel(new BorderLayout(6,6));
        installPlaceholder(questionField, "Ask a question or leave blank for suggestions");
        inputPanel.add(questionField, BorderLayout.CENTER); inputPanel.add(askButton, BorderLayout.EAST);
        JPanel chatPanel = new JPanel(new BorderLayout(6,6));
        chatPanel.add(new JScrollPane(chatPane), BorderLayout.CENTER);
        chatPanel.add(inputPanel, BorderLayout.SOUTH);

        JPanel settings = buildSettingsPanel();
        JSplitPane vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT, leftRight, chatPanel); vertical.setResizeWeight(0.5);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JToggleButton settingsToggle = new JToggleButton("Settings");
        settings.setVisible(false);
        settingsToggle.addActionListener(ev -> { settings.setVisible(settingsToggle.isSelected()); panel.revalidate(); panel.repaint(); });
        JButton suggestBtn = new JButton("Suggest tests");
        suggestBtn.addActionListener(e -> doSuggest());
        progress.setVisible(false);
        toolbar.add(settingsToggle); toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(new JLabel("Preset:")); toolbar.add(presetCombo); toolbar.add(Box.createHorizontalStrut(8)); toolbar.add(suggestBtn); toolbar.add(progress); toolbar.add(statusLabel);

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(vertical, BorderLayout.CENTER);
        panel.add(settings, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildSettingsPanel() {
        JPanel p = new JPanel(); p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS)); p.setBorder(BorderFactory.createTitledBorder("Settings & Templates"));
        JPanel row1 = new JPanel(new GridLayout(0,3,6,6)); row1.add(new JLabel("Provider")); row1.add(providerCombo); JButton toggleAdv = new JButton("Show/Hide Advanced"); row1.add(toggleAdv);
        JPanel azure = new JPanel(new GridLayout(0,2,6,6)); azure.setBorder(BorderFactory.createTitledBorder("Azure AI Models"));
        azure.add(new JLabel("Endpoint")); azure.add(endpointField);
        azure.add(new JLabel("Deployment")); azure.add(deploymentField);
        azure.add(new JLabel("API Version")); azure.add(apiVersionField);
        JPanel openai = new JPanel(new GridLayout(0,2,6,6)); openai.setBorder(BorderFactory.createTitledBorder("OpenAI"));
        openai.add(new JLabel("Model")); openai.add(openAiModelField);
        openai.add(new JLabel("Base URL (optional)")); openai.add(openAiBaseUrlField);
        JPanel common = new JPanel(new GridLayout(0,2,6,6));
        common.add(new JLabel("API Key")); common.add(apiKeyField);
        common.add(new JLabel("Max chars to send")); common.add(maxCharsSpinner);
        common.add(new JLabel(" ")); common.add(stripHeaders);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(testButton); actions.add(new JLabel("Data may be sent externally; ensure authorization."));

        JPanel templatesPanel = new JPanel(new GridLayout(0,2,6,6)); templatesPanel.setBorder(BorderFactory.createTitledBorder("Vulnerability Templates (.jinja/.txt)"));
        templatesPanel.add(new JLabel("Templates directory")); templatesPanel.add(templatesDirField); templatesPanel.add(new JLabel(" ")); templatesPanel.add(loadTemplatesButton);
        templatesList.setVisibleRowCount(5); templatesList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane tplScroll = new JScrollPane(templatesList);
        JPanel templatesWrapper = new JPanel(new BorderLayout()); templatesWrapper.add(templatesPanel, BorderLayout.NORTH); templatesWrapper.add(tplScroll, BorderLayout.CENTER);
        JPanel advanced = new JPanel(new BorderLayout()); advanced.add(templatesWrapper, BorderLayout.CENTER); advanced.setVisible(false);
        toggleAdv.addActionListener(e -> advanced.setVisible(!advanced.isVisible()));

        installPlaceholder(endpointField, "https://your-resource.openai.azure.com");
        installPlaceholder(deploymentField, "gpt-5-mini");
        installPlaceholder(apiKeyField, "<paste-your-api-key>");
        installPlaceholder(openAiModelField, "gpt-4o-mini");
        installPlaceholder(openAiBaseUrlField, "https://api.openai.com/v1");
        testButton.addActionListener(e -> doTestConnection());
        loadTemplatesButton.addActionListener(e -> doLoadTemplates());
        providerCombo.addActionListener(e -> updateProviderVisibility()); updateProviderVisibility();

        p.add(row1); p.add(azure); p.add(openai); p.add(common); p.add(advanced); p.add(actions); return p;
    }

    public void addMessages(IHttpRequestResponse[] msgs) {
        if (msgs == null || msgs.length == 0) return;
        for (IHttpRequestResponse m : msgs) {
            messages.add(m); reqListModel.addElement(summarizeRequest(m)); chats.putIfAbsent(m, new StringBuilder());
        }
        if (current == null && !messages.isEmpty()) { requestList.setSelectedIndex(messages.size()-1); loadSelectedMessage(); }
    }

    private void doTestConnection() {
        String provider = (String) providerCombo.getSelectedItem();
        setBusy(true, "Testing connection");
        if ("OpenAI".equals(provider)) {
            OpenAIClient.Config cfg = buildOpenAIConfig(); String val = validateOpenAI(cfg); if (val != null) { appendChat("VISTA", val); setBusy(false,"Ready"); return; }
            appendChat("VISTA", "Testing OpenAI connection to model: " + safe(cfg.model) + (cfg.baseUrl!=null?"\nBase URL: "+cfg.baseUrl: ""));
            new Thread(() -> { try { String resp = OpenAIClient.test(cfg); SwingUtilities.invokeLater(() -> appendChat("VISTA","Test connection: "+resp)); } catch(Exception ex){ callbacks.printError("Test connection failed: "+ex); SwingUtilities.invokeLater(() -> appendChat("VISTA","Test failed: "+ex.getMessage())); } finally { SwingUtilities.invokeLater(() -> setBusy(false,"Ready")); } }, "VISTA-Test").start();
            return;
        }
        AzureClient.Config cfg = buildAzureConfig(); String val = validateAzure(cfg); if (val != null) { appendChat("VISTA", val); setBusy(false,"Ready"); return; }
        appendChat("VISTA", "Testing Azure connection to:\n- Endpoint: "+safe(cfg.endpoint)+"\n- Deployment: "+safe(cfg.deployment)+"\n- API Version: "+safe(cfg.apiVersion));
        new Thread(() -> { try { String resp = AzureClient.test(cfg); SwingUtilities.invokeLater(() -> appendChat("VISTA","Test connection: "+resp)); } catch(Exception ex){ callbacks.printError("Test connection failed: "+ex); SwingUtilities.invokeLater(() -> appendChat("VISTA","Test failed: "+ex.getMessage())); } finally { SwingUtilities.invokeLater(() -> setBusy(false,"Ready")); } }, "VISTA-Test").start();
    }

    private void onAsk(ActionEvent evt) {
        String q = questionField.getText().trim();
        if (q.isEmpty()) q = "Provide request-specific testing guidance with concrete payloads and steps to validate in Burp. Prioritize likely, high-signal tests first.";
        if (getSelectedMessage() == null) { appendChat("VISTA", "Send one or more requests to VISTA first (right-click -> Send to VISTA), then select one."); return; }
        questionField.setText(""); appendChat("You", q);
        String provider = (String) providerCombo.getSelectedItem();
        IHttpRequestResponse sel = getSelectedMessage(); final IHttpRequestResponse bound = sel;
        String reqText = HttpFormat.requestToText(helpers, sel.getRequest()); String rspText = HttpFormat.responseToText(helpers, sel.getResponse());
        boolean strip = stripHeaders.isSelected(); int maxChars = (Integer) maxCharsSpinner.getValue();
        String reqForAi = HttpFormat.prepareForAi(reqText, strip, maxChars); String rspForAi = HttpFormat.prepareForAi(rspText, strip, maxChars);
        String systemPrompt = "You are VISTA (Vulnerability Insight & Strategic Test Assistant), an assistant for authorized web application security testing inside Burp Suite. " +
                "Assume the user is authorized. Be concise and practical. Provide request-specific testing guidance with concrete payloads, rationale, verification cues, safe variants, and prioritized high-signal techniques.";
        String userPrompt = "Current Request:\n"+reqForAi+"\n\nCurrent Response:\n"+rspForAi+"\n\nQuestion:\n"+q;
        setBusy(true, "Thinking");
        new Thread(() -> {
            try {
                String sys = augmentSystemWithPreset(augmentSystemWithTemplates(systemPrompt));
                String answer;
                if ("OpenAI".equals(provider)) { OpenAIClient.Config oc = buildOpenAIConfig(); String val = validateOpenAI(oc); if (val != null) { SwingUtilities.invokeLater(() -> appendChat("VISTA", val)); return; } answer = OpenAIClient.ask(oc, sys, userPrompt); }
                else { AzureClient.Config ac = buildAzureConfig(); String val = validateAzure(ac); if (val != null) { SwingUtilities.invokeLater(() -> appendChat("VISTA", val)); return; } answer = AzureClient.ask(ac, sys, userPrompt); }
                SwingUtilities.invokeLater(() -> {
                    IHttpRequestResponse now = getSelectedMessage();
                    if (now != bound) {
                        StringBuilder sb = chats.computeIfAbsent(bound, k -> new StringBuilder());
                        sb.append("[VISTA] ").append(answer).append("\n\n");
                        appendChat("VISTA", "(Answer stored for previously selected request)");
                    } else {
                        appendChat("VISTA", answer);
                    }
                });
            } catch (Exception ex) {
                callbacks.printError("AI error: "+ex);
                SwingUtilities.invokeLater(() -> appendChat("VISTA", "Error calling provider: "+ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> setBusy(false, "Ready"));
            }
        }, "VISTA-AI").start();
    }

    private void doSuggest() { onAsk(null); }

    private AzureClient.Config buildAzureConfig() { AzureClient.Config c = new AzureClient.Config(); c.endpoint=text(endpointField); c.deployment=text(deploymentField); c.apiVersion=text(apiVersionField); c.apiKey=new String(apiKeyField.getPassword()); return c; }
    private OpenAIClient.Config buildOpenAIConfig() { OpenAIClient.Config c = new OpenAIClient.Config(); c.model=text(openAiModelField); c.apiKey=new String(apiKeyField.getPassword()); String base=text(openAiBaseUrlField); if(base!=null && !base.isBlank()) c.baseUrl=base; return c; }

    private String validateAzure(AzureClient.Config cfg){ if(cfg==null) return "Invalid config."; if(blank(cfg.endpoint)) return "Endpoint is empty."; if(blank(cfg.deployment)) return "Deployment name is empty."; if(blank(cfg.apiKey)) return "API key is empty."; String lc=cfg.endpoint.toLowerCase(); if(!(lc.contains(".openai.azure.com")||lc.contains(".cognitiveservices.azure.com"))) return "Endpoint host not recognized as Azure OpenAI/AI Foundry."; if(cfg.deployment.contains("/")||cfg.deployment.contains(" ")) return "Deployment looks invalid (no spaces or slashes)."; return null; }
    private String validateOpenAI(OpenAIClient.Config cfg){ if(cfg==null) return "Invalid config."; if(blank(cfg.model)) return "OpenAI model is empty."; if(blank(cfg.apiKey)) return "API key is empty."; return null; }
    private static boolean blank(String s){ return s==null||s.isBlank(); }
    private static String text(JTextField f){ return f.getText().trim(); }
    private static String safe(String s){ return s==null?"(null)":s; }

    private void setBusy(boolean busy, String status){ askButton.setEnabled(!busy); testButton.setEnabled(!busy); progress.setVisible(busy); progress.setIndeterminate(busy); statusLabel.setText(status + (busy?"...":"")); if(busy && !thinkingDots.isRunning()) thinkingDots.start(); }
    private int dotCount=0; private void cycleThinking(){ dotCount=(dotCount+1)%4; String base=statusLabel.getText(); int removed=0; while(base.endsWith(".")&&removed<3){ base=base.substring(0,base.length()-1); removed++; } statusLabel.setText(base + ".".repeat(dotCount)); }

    private void appendChat(String who, String text){
        if(who==null) who="?";
        if(text==null) text="";
        if(current!=null){ StringBuilder sb=chats.computeIfAbsent(current,k->new StringBuilder()); sb.append("[").append(who).append("] ").append(text).append("\n\n"); }
        else { globalChat.append("[").append(who).append("] ").append(text).append("\n\n"); }
        // Re-render current visible chat
        String visible = current!=null ? chats.get(current).toString() : globalChat.toString();
        renderChat(visible);
    }

    private void renderChat(String full){
        StyledDocument doc = chatPane.getStyledDocument();
        try { doc.remove(0, doc.getLength()); } catch (BadLocationException ignored) {}
        // Body style (theme friendly)
        SimpleAttributeSet bodyAttr = new SimpleAttributeSet();
        StyleConstants.setForeground(bodyAttr, chatPane.getForeground());

        // Helper to build (and maybe cache later) a style for a speaker name
        java.util.function.Function<String, SimpleAttributeSet> styleFor = speaker -> {
            String key = speaker == null ? "" : speaker.trim().toUpperCase();
            Color c;
            switch (key) {
                case "VISTA" -> c = Color.RED;
                case "YOU" -> c = new Color(0,70,170); // deep blue
                case "SYSTEM" -> c = Color.DARK_GRAY;
                case "INFO" -> c = new Color(90,90,90);
                case "ERROR" -> c = new Color(160,0,0);
                default -> c = new Color(120,0,120); // magenta-ish for others
            }
            SimpleAttributeSet a = new SimpleAttributeSet();
            StyleConstants.setBold(a, true);
            StyleConstants.setForeground(a, c);
            return a;
        };

        String[] blocks = full.split("\n\n");
        try {
            for(String block: blocks){
                if(block == null || block.isBlank()) continue;
                int idx = block.indexOf(']');
                if(block.startsWith("[") && idx > 1){
                    String tag = block.substring(0, idx+1); // e.g. [VISTA]
                    String speaker = tag.substring(1, tag.length()-1); // VISTA
                    String rest = block.substring(idx+1).trim();
                    SimpleAttributeSet speakerAttr = styleFor.apply(speaker);
                    doc.insertString(doc.getLength(), tag+" ", speakerAttr);
                    doc.insertString(doc.getLength(), rest+"\n\n", bodyAttr);
                } else {
                    doc.insertString(doc.getLength(), block+"\n\n", bodyAttr);
                }
            }
        } catch (BadLocationException ignored) {}
        chatPane.setCaretPosition(chatPane.getDocument().getLength());
    }

    private void updateProviderVisibility(){ boolean azure = !"OpenAI".equals(providerCombo.getSelectedItem()); endpointField.setEnabled(azure); deploymentField.setEnabled(azure); apiVersionField.setEnabled(azure); openAiModelField.setEnabled(!azure); openAiBaseUrlField.setEnabled(!azure); }

    private String augmentSystemWithPreset(String system){ String sel=(String)presetCombo.getSelectedItem(); if(sel==null||sel.startsWith("None")) return system; String add = switch(sel){ case "CSRF"->VulnTemplates.CSRF; case "IDOR"->VulnTemplates.IDOR; case "SQL Injection"->VulnTemplates.SQLI; case "SSRF"->VulnTemplates.SSRF; case "XSS"->VulnTemplates.XSS; default->null;}; if(add==null) return system; return system+"\n\nFocus area preset:\n"+add+"\n(Adapt payloads to the specific request.)"; }
    private String augmentSystemWithTemplates(String system){ java.util.List<String> sel = templatesList.getSelectedValuesList(); if(sel==null||sel.isEmpty()) return system; StringBuilder sb=new StringBuilder(system); sb.append("\n\nUse these playbooks (adapt specifically):\n"); int budget=6000; for(String name: sel){ String content=templates.get(name); if(content==null) continue; String trimmed=content.length()>1400?content.substring(0,1400)+"\n...[truncated]...":content; if(budget-trimmed.length()<0) break; budget-=trimmed.length(); sb.append("\n--- Template: ").append(name).append(" ---\n").append(trimmed).append("\n"); } return sb.toString(); }

    private void doLoadTemplates(){ String dir=templatesDirField.getText().trim(); if(dir.isEmpty()){ appendChat("VISTA","Enter a templates directory path and click Load templates."); return; } File folder=new File(dir); if(!folder.exists()||!folder.isDirectory()){ appendChat("VISTA","Templates directory not found: "+dir); return; } File[] files=folder.listFiles((d,n)-> n.toLowerCase().endsWith(".jinja")||n.toLowerCase().endsWith(".txt")); if(files==null||files.length==0){ appendChat("VISTA","No .jinja or .txt files found in: "+dir); return; } templates.clear(); templatesModel.clear(); for(File f: files){ try { String content = java.nio.file.Files.readString(f.toPath()); templates.put(f.getName(), content); templatesModel.addElement(f.getName()); } catch(Exception ex){ callbacks.printError("Failed to read template: "+f+" -> "+ex); } } appendChat("VISTA","Loaded "+templates.size()+" template(s) from: "+dir); }

    private IHttpRequestResponse getSelectedMessage(){ int idx=requestList.getSelectedIndex(); if(idx<0||idx>=messages.size()) return null; return messages.get(idx);}    
    private void loadSelectedMessage(){ int idx=requestList.getSelectedIndex(); if(idx<0||idx>=messages.size()) return; current = messages.get(idx); requestArea.setText(HttpFormat.requestToText(helpers,current.getRequest())); responseArea.setText(HttpFormat.responseToText(helpers,current.getResponse())); requestArea.setCaretPosition(0); responseArea.setCaretPosition(0); StringBuilder buffer = chats.get(current); renderChat(buffer==null?"":buffer.toString()); }
    private String summarizeRequest(IHttpRequestResponse msg){ try { String req=HttpFormat.requestToText(helpers,msg.getRequest()); String[] lines=req.split("\r?\n"); String start=lines.length>0?lines[0] : "(request)"; String host=""; for(String l: lines){ if(l.toLowerCase().startsWith("host:")){ host=l.substring(5).trim(); break; } } String shortPath=start.length()>100?start.substring(0,100)+"…":start; return (host.isEmpty()?"":host+" ")+shortPath; } catch(Exception e){ return "Request "+(messages.size()+1); }}
    private void removeSelected(){ int idx=requestList.getSelectedIndex(); if(idx<0||idx>=messages.size()) return; IHttpRequestResponse removed=messages.remove(idx); reqListModel.remove(idx); chats.remove(removed); if(messages.isEmpty()){ current=null; requestArea.setText(""); responseArea.setText(""); renderChat(globalChat.toString()); } else { int newIdx=Math.min(idx,messages.size()-1); requestList.setSelectedIndex(newIdx); loadSelectedMessage(); } saveStateAsync(); }

    private void sendSelectedToRepeater(){ IHttpRequestResponse sel=getSelectedMessage(); if(sel==null){ appendChat("VISTA","No request selected to send to Repeater."); return; } try { String host=null; int port=0; boolean https=false; try{host=sel.getHost();}catch(Throwable ignored){} try{port=sel.getPort();}catch(Throwable ignored){} try{https=sel.isHttps();}catch(Throwable ignored){} if(host==null||host.isBlank()||port==0){ String reqText=HttpFormat.requestToText(helpers, sel.getRequest()); String[] lines=reqText.split("\r?\n"); String first= lines.length>0?lines[0]:""; for(String l: lines){ if(l.toLowerCase().startsWith("host:")){ String hv=l.substring(5).trim(); if(hv.contains(":")){ String[] hp=hv.split(":",2); host=hp[0].trim(); try{ port=Integer.parseInt(hp[1].trim()); }catch(NumberFormatException ignored){} } else host=hv.trim(); break; } } String lower=first.toLowerCase(); if(lower.contains("http://")) https=false; else if(lower.contains("https://")) https=true; if(port==0) port=https?443:80; }
        if(host==null||host.isBlank()){ appendChat("VISTA","Could not determine host for Repeater."); return; }
        callbacks.sendToRepeater(host, port, https, sel.getRequest(), "VISTA"); appendChat("VISTA","Sent to Repeater: "+host+":"+port+(https?" (https)":" (http)")); saveStateAsync(); } catch(Exception ex){ callbacks.printError("Send to Repeater failed: "+ex); appendChat("VISTA","Failed to send to Repeater: "+ex.getMessage()); } }

    // Persistence (migrate from old file name)
    private File stateFile(){ String home=System.getProperty("user.home", "."); return new File(home, ".vista.json"); }
    private File oldStateFile(){ String home=System.getProperty("user.home", "."); return new File(home, ".burpraj.json"); }
    private synchronized void saveStateAsync(){ new Thread(this::saveState, "VISTA-Save").start(); }
    private synchronized void saveState(){ try(FileWriter fw=new FileWriter(stateFile())){ StringBuilder sb=new StringBuilder(); sb.append('{'); sb.append("\"provider\":\"").append(escape((String)providerCombo.getSelectedItem())).append("\","); sb.append("\"endpoint\":\"").append(escape(text(endpointField))).append("\","); sb.append("\"deployment\":\"").append(escape(text(deploymentField))).append("\","); sb.append("\"apiVersion\":\"").append(escape(text(apiVersionField))).append("\","); sb.append("\"openAiModel\":\"").append(escape(text(openAiModelField))).append("\","); sb.append("\"openAiBaseUrl\":\"").append(escape(text(openAiBaseUrlField))).append("\","); sb.append("\"strip\":").append(stripHeaders.isSelected()).append(','); sb.append("\"maxChars\":").append((Integer)maxCharsSpinner.getValue()).append(','); sb.append("\"preset\":\"").append(escape((String)presetCombo.getSelectedItem())).append("\","); sb.append("\"globalChat\":\"").append(escape(globalChat.toString())).append("\"}"); fw.write(sb.toString()); } catch(Exception ex){ callbacks.printError("Failed to save state: "+ex); } }
    private synchronized void loadState(){ try { File f=stateFile(); if(!f.exists()){ File old=oldStateFile(); if(old.exists()) old.renameTo(f); } if(!f.exists()) return; String json= java.nio.file.Files.readString(f.toPath()); providerCombo.setSelectedItem(extract(json,"provider")); endpointField.setText(extract(json,"endpoint")); deploymentField.setText(extract(json,"deployment")); apiVersionField.setText(extract(json,"apiVersion")); openAiModelField.setText(extract(json,"openAiModel")); openAiBaseUrlField.setText(extract(json,"openAiBaseUrl")); String strip=extract(json,"strip"); if("true".equals(strip)||"false".equals(strip)) stripHeaders.setSelected(Boolean.parseBoolean(strip)); String max=extract(json,"maxChars"); try{ if(max!=null) maxCharsSpinner.setValue(Integer.parseInt(max)); }catch(NumberFormatException ignored){} String preset=extract(json,"preset"); if(preset!=null) presetCombo.setSelectedItem(preset); String g=extract(json,"globalChat"); if(g!=null){ globalChat.setLength(0); globalChat.append(unescape(g)); renderChat(globalChat.toString()); } } catch(Exception ex){ callbacks.printError("Failed to load state: "+ex); } }
    private static String escape(String s){ if(s==null) return ""; return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n"); }
    private static String unescape(String s){ return s.replace("\\n","\n").replace("\\\"","\"").replace("\\\\","\\"); }
    private static String extract(String json,String key){ String pattern="\""+key+"\":"; int idx=json.indexOf(pattern); if(idx<0) return null; int start=idx+pattern.length(); if(start<json.length() && json.charAt(start)=='"'){ start++; int end=json.indexOf('"', start); if(end<0) return null; return unescape(json.substring(start,end)); } else { int end=start; while(end<json.length() && ",}\n".indexOf(json.charAt(end))==-1) end++; return json.substring(start,end).trim(); } }

    private static void installPlaceholder(JTextField f, String placeholder){ Color hint = new Color(150,150,150); Color normal = f.getForeground(); if(f.getText()==null||f.getText().isBlank()){ f.setForeground(hint); f.setText(placeholder);} f.addFocusListener(new java.awt.event.FocusAdapter(){ public void focusGained(java.awt.event.FocusEvent e){ if(f.getForeground().equals(hint)){ f.setText(""); f.setForeground(normal);} } public void focusLost(java.awt.event.FocusEvent e){ if(f.getText().isBlank()){ f.setForeground(hint); f.setText(placeholder);} } }); }
    private static void installPlaceholder(JPasswordField f, String placeholder){ Color hint=new Color(150,150,150); Color normal=f.getForeground(); char echo=f.getEchoChar(); if(f.getPassword().length==0){ f.setForeground(hint); f.setEchoChar((char)0); f.setText(placeholder);} f.addFocusListener(new java.awt.event.FocusAdapter(){ public void focusGained(java.awt.event.FocusEvent e){ if(f.getForeground().equals(hint)){ f.setText(""); f.setEchoChar(echo); f.setForeground(normal);} } public void focusLost(java.awt.event.FocusEvent e){ if(new String(f.getPassword()).isBlank()){ f.setForeground(hint); f.setEchoChar((char)0); f.setText(placeholder);} } }); }
}
