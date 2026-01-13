package burp;

public interface IHttpRequestResponse {
    byte[] getRequest();
    byte[] getResponse();
    default String getHost() { return ""; }
    default int getPort() { return 80; }
    default boolean isHttps() { return false; }
    default IHttpService getHttpService() { 
        String host = getHost();
        int port = getPort();
        boolean https = isHttps();
        return new IHttpService() {
            @Override public String getHost() { return host; }
            @Override public int getPort() { return port; }
            @Override public String getProtocol() { return https ? "https" : "http"; }
        };
    }
}