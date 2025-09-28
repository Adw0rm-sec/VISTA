package burp;

public interface IHttpRequestResponse {
    byte[] getRequest();
    byte[] getResponse();
    default String getHost() { return ""; }
    default int getPort() { return 80; }
    default boolean isHttps() { return false; }
}