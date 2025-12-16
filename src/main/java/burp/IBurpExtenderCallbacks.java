package burp;

public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    void addSuiteTab(ITab tab);
    void registerContextMenuFactory(IContextMenuFactory factory);
    void printOutput(String output);
    void printError(String error);
    IExtensionHelpers getHelpers();
    // Classic Burp API method to send requests to Repeater
    void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption);
}