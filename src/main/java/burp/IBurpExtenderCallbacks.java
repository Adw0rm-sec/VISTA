package burp;

public interface IBurpExtenderCallbacks {
    // Tool flags for identifying which Burp tool made the request
    int TOOL_SUITE = 1;
    int TOOL_TARGET = 2;
    int TOOL_PROXY = 4;
    int TOOL_SPIDER = 8;
    int TOOL_SCANNER = 16;
    int TOOL_INTRUDER = 32;
    int TOOL_REPEATER = 64;
    int TOOL_SEQUENCER = 128;
    int TOOL_DECODER = 256;
    int TOOL_COMPARER = 512;
    int TOOL_EXTENDER = 1024;
    
    void setExtensionName(String name);
    void addSuiteTab(ITab tab);
    void registerContextMenuFactory(IContextMenuFactory factory);
    void registerHttpListener(IHttpListener listener);
    void removeHttpListener(IHttpListener listener);
    void printOutput(String output);
    void printError(String error);
    IExtensionHelpers getHelpers();
    // Classic Burp API method to send requests to Repeater
    void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption);
    // Make HTTP request and get response
    IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request);
}